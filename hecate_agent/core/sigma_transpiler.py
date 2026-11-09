"""Multi-target EDR and SIEM Sigma query transpilation engine.

Transpiles vendor-agnostic Sigma rules (YAML) into native, copy-paste and
deployment-ready search queries for major enterprise EDRs and SIEMs:
- Microsoft Defender for Endpoint (MDE) / Microsoft Sentinel (KQL)
- CrowdStrike Falcon (LogScale / Raptor / FDR) (CQL)
- Rapid7 InsightIDR (Log Entry Query Language - LEQL)
"""

from __future__ import annotations

import hashlib
import logging
import stat
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, Iterator, List, Optional

import yaml

from hecate_agent.core.atomic_write import DEFAULT_FILE_MODE, atomic_write_text
from hecate_agent.core.query_validator import (
    QueryValidationResult,
    QueryValidator,
)

try:
    from sigma.backends.crowdstrike import LogScaleBackend
    from sigma.backends.elasticsearch import EqlBackend
    from sigma.backends.kusto import KustoBackend
    from sigma.backends.sentinelone import SentinelOneBackend
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.conversion.base import TextQueryBackend
    from sigma.conversion.state import ConversionState
    from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
    from sigma.pipelines.elasticsearch import ecs_windows
    from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
    from sigma.pipelines.sentinelone import sentinelone_pipeline
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation
    from sigma.rule import SigmaRule

    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False
    LogScaleBackend = None  # type: ignore
    KustoBackend = None  # type: ignore
    SplunkBackend = None  # type: ignore
    EqlBackend = None  # type: ignore
    SentinelOneBackend = None  # type: ignore
    SigmaCollection = None  # type: ignore
    TextQueryBackend = object  # type: ignore
    ConversionState = Any  # type: ignore
    SigmaRule = Any  # type: ignore
    ProcessingPipeline = Any  # type: ignore
    ProcessingItem = Any  # type: ignore
    FieldMappingTransformation = Any  # type: ignore
    LogsourceCondition = Any  # type: ignore
    IncludeFieldCondition = Any  # type: ignore

logger = logging.getLogger(__name__)

_BACKEND_CACHE: Dict[str, Any] = {}
_CACHE_LOCK = threading.Lock()
# Only immutable query text is shared. Validation results and public result
# objects are rebuilt per call. The cache lives no longer than loaded backends.
_QUERY_CACHE: OrderedDict[tuple[Any, ...], str] = OrderedDict()
_QUERY_CACHE_LOCK = threading.RLock()
MAX_QUERY_CACHE_ENTRIES = 256
MAX_CACHED_QUERY_BYTES = 262144

_ELASTIC_PROXY_MAPPING: Dict[str, str] = {
    "c-useragent": "user_agent.original",
    "cs-user-agent": "user_agent.original",
    "cs-cookie": "http.request.headers.cookie",
    "cs-referrer": "http.request.referrer",
    "cs-method": "http.request.method",
    "sc-status": "http.response.status_code",
    "cs-host": "url.domain",
    "cs-uri-stem": "url.path",
    "cs-uri-query": "url.query",
    "c-ip": "source.ip",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
}

_ELASTIC_LINUX_MAPPING: Dict[str, str] = {
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "CommandLine": "process.command_line",
    "ParentCommandLine": "process.parent.command_line",
    "CurrentDirectory": "process.working_directory",
    "User": "user.name",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
    "TargetFilename": "file.path",
    "DestinationIp": "destination.ip",
    "DestinationHostname": "destination.domain",
    "DestinationPort": "destination.port",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "Protocol": "network.transport",
    "QueryName": "dns.question.name",
}


_PATH_FIELDS = ("Image", "ParentImage", "TargetFilename", "CommandLine", "ParentCommandLine", "CurrentDirectory")


def _has_unix_path(detection: Any) -> bool:
    """Whether a process or file field in the detection holds a Unix path such as ``/bin/sh``."""
    if not isinstance(detection, dict):
        return False
    for block in detection.values():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if str(key).split("|", 1)[0] not in _PATH_FIELDS:
                continue
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and item.lstrip("*").startswith("/"):
                    return True
    return False


def _get_or_create_backend(key: str, builder: Callable[[], Any]) -> Any:
    """Thread-safe cached pySigma backend lookup to avoid re-compiling processing pipelines."""
    backend = _BACKEND_CACHE.get(key)
    if backend is None:
        with _CACHE_LOCK:
            backend = _BACKEND_CACHE.get(key)
            if backend is None:
                backend = builder()
                _BACKEND_CACHE[key] = backend
    return backend


def clear_backend_cache() -> None:
    """Invalidate converted queries together with backend/pipeline instances."""
    with _QUERY_CACHE_LOCK, _CACHE_LOCK:
        _QUERY_CACHE.clear()
        _BACKEND_CACHE.clear()


def write_query_if_changed(path: Path, query: str) -> bool:
    """Persist canonical native query text without touching an unchanged file."""
    content = query.strip() + "\n"
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except (FileNotFoundError, UnicodeError):
        pass
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = DEFAULT_FILE_MODE
    atomic_write_text(path, content, mode=mode)
    return True


def write_transpiled_queries(rule_path: Path, results: Dict[str, Any]) -> Iterator[Path]:
    """Yield valid artifacts as they are materialized, including unchanged files."""
    for result in results.values():
        if getattr(result, "success", False) and getattr(result, "query", None):
            path = rule_path.with_suffix(result.file_extension)
            write_query_if_changed(path, result.query)
            yield path


def build_insight_idr_pipeline() -> Optional[Any]:
    """Build a comprehensive, modern pySigma processing pipeline for Rapid7 InsightIDR LEQL."""
    if not PYSIGMA_AVAILABLE:
        return None
    return ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "ProcessId": "process.pid",
                        "Image": "process.exe_path",
                        "OriginalFileName": "process.name",
                        "CommandLine": "process.cmd_line",
                        "CurrentDirectory": "process.working_directory",
                        "User": "process.username",
                        "ParentProcessId": "parent_process.pid",
                        "ParentImage": "parent_process.exe_path",
                        "ParentCommandLine": "parent_process.cmd_line",
                        "ParentUser": "parent_process.username",
                        "TargetFilename": "file.path",
                        "DestinationIp": "destination_address",
                        "DestinationPort": "destination_port",
                        "SourceIp": "source_address",
                        "SourcePort": "source_port",
                        "QueryName": "query",
                        "QueryResults": "query_results",
                        "TargetObject": "registry.key",
                        "Details": "registry.value",
                        "TargetUserName": "account",
                        "SubjectUserName": "account",
                        "WorkstationName": "source_asset",
                        "cs-method": "http_method",
                        "cs-uri-stem": "uri_path",
                        "cs-uri-query": "uri_query",
                        "cs-cookie": "cookie",
                        "c-useragent": "user_agent",
                        "sc-status": "http_status",
                    }
                )
            )
        ]
    )


def build_sentinelone_pipeline() -> Optional[Any]:
    """Build a SentinelOne processing pipeline patched for EndpointOS detection item compatibility."""
    if not PYSIGMA_AVAILABLE or sentinelone_pipeline is None:
        return None
    try:
        pipeline = sentinelone_pipeline()
        for item in pipeline.items:
            if getattr(item, "identifier", None) == "s1_fail_field_not_supported":
                for cond in getattr(item, "field_name_conditions", []):
                    fields = getattr(cond, "fields", None)
                    if isinstance(fields, list) and "EndpointOS" not in fields:
                        fields.append("EndpointOS")
        return pipeline
    except Exception as exc:
        logger.debug("Failed to build SentinelOne pipeline: %s", exc)
        return None


class InsightIDRBackend(TextQueryBackend):
    """Native Rapid7 InsightIDR Log Entry Query Language (LEQL) Backend."""

    name: ClassVar[str] = "Rapid7 InsightIDR LEQL"
    formats: ClassVar[Dict[str, str]] = {
        "default": "where(query)",
        "leql_advanced_search": "Advanced Log Entry Query Language (LEQL) queries",
    }
    requires_pipeline: ClassVar[bool] = False

    group_expression: ClassVar[str] = "({expr})"
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    icontains_token: ClassVar[str] = "ICONTAINS"
    istarts_with_token: ClassVar[str] = "ISTARTS-WITH"
    str_double_quote: ClassVar[str] = '"'
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    re_expression: ClassVar[str] = "{field}=/{regex}/i"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[List[str]] = ["/"]

    def __init__(self, processing_pipeline: Optional[Any] = None):
        if processing_pipeline is None and PYSIGMA_AVAILABLE:
            processing_pipeline = build_insight_idr_pipeline()
        super().__init__(processing_pipeline=processing_pipeline)

    def convert_value_str(self, value: Any, state: ConversionState) -> str:
        # LEQL values do not interpret Sigma's wildcard syntax. Use its
        # documented case-insensitive regex predicates to preserve exact,
        # startswith, endswith, and contains semantics, including path escapes.
        # https://docs.rapid7.com/insightidr/components-for-building-a-query/
        pattern = value.to_regex(custom_escaped="/").regexp
        return f"/^{pattern}$/i"

    def finalize_query_default(self, rule: Any, query: str, index: int, state: Any) -> str:
        return f"where({query})"

    def finalize_query_leql_advanced_search(self, rule: Any, query: str, index: int, state: Any) -> str:
        return f"where({query})"


@dataclass
class TranspiledQuery:
    """A transpiled search query for a specific EDR or SIEM platform."""

    target: str
    platform_name: str
    dialect: str
    file_extension: str
    query: Optional[str]
    success: bool
    error_message: Optional[str] = None
    validation: Optional[QueryValidationResult] = None


class SigmaTranspiler:
    """Multi-target query transpiler for Sigma detection rules."""

    TARGET_MDE = "sentinel_kql"
    TARGET_CROWDSTRIKE = "crowdstrike_cql"
    TARGET_RAPID7 = "rapid7_leql"
    TARGET_SENTINELONE = "sentinelone_s1ql"
    TARGET_SPLUNK = "splunk_spl"
    TARGET_ELASTIC = "elastic_eql"

    SUPPORTED_TARGETS = [
        TARGET_MDE,
        TARGET_CROWDSTRIKE,
        TARGET_RAPID7,
        TARGET_SENTINELONE,
        TARGET_SPLUNK,
        TARGET_ELASTIC,
    ]

    TARGET_METADATA = {
        TARGET_MDE: {
            "name": "Microsoft Defender / Microsoft Sentinel",
            "dialect": "kql",
            "extension": ".kql",
        },
        TARGET_CROWDSTRIKE: {
            "name": "CrowdStrike Falcon (LogScale / Raptor)",
            "dialect": "cql",
            "extension": ".cql",
        },
        TARGET_RAPID7: {
            "name": "Rapid7 InsightIDR",
            "dialect": "leql",
            "extension": ".leql",
        },
        TARGET_SENTINELONE: {
            "name": "SentinelOne (S1QL / Deep Visibility)",
            "dialect": "s1ql",
            "extension": ".s1ql",
        },
        TARGET_SPLUNK: {
            "name": "Splunk Enterprise / Cloud (SPL)",
            "dialect": "spl",
            "extension": ".spl",
        },
        TARGET_ELASTIC: {
            "name": "Elastic Security (EQL)",
            "dialect": "eql",
            "extension": ".eql",
        },
    }

    def __init__(self) -> None:
        self.validator = QueryValidator()
        if not PYSIGMA_AVAILABLE:
            logger.warning("pySigma and required backends not installed; transpilation will fail open.")

    @classmethod
    def clear_cache(cls) -> None:
        """Clear converted queries, backend instances and processing pipelines."""
        clear_backend_cache()

    def validate_query(self, target: str, query: str) -> QueryValidationResult:
        """Validate an arbitrary query against the target platform dialect rules."""
        return self.validator.validate(target, query)

    @classmethod
    def normalize_rule_for_backends(cls, rule_yaml: str) -> str:
        """Alias for backward-compatible logsource normalization without target."""
        return cls.normalize_rule_for_backend(rule_yaml, target="")

    @classmethod
    def normalize_rule_for_backend(cls, rule_yaml: str, target: str = "") -> str:
        """Ensure standard logsource and field mappings are aligned with vendor pipelines."""
        try:
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict):
                return rule_yaml

            logsource = parsed.get("logsource", {})
            if not isinstance(logsource, dict):
                return rule_yaml

            category = logsource.get("category", "")
            product = logsource.get("product")
            service = logsource.get("service")

            # General Windows normalization for endpoint events
            if not product and not service:
                endpoint_cats = {
                    "process_creation",
                    "file_event",
                    "image_load",
                    "registry_event",
                    "network_connection",
                    "dns_query",
                }
                detection_str = str(parsed.get("detection", ""))
                windows_values = "\\" in detection_str or ".exe" in detection_str.lower()
                if category in endpoint_cats and not windows_values and _has_unix_path(parsed.get("detection")):
                    logsource["product"] = "linux"
                    parsed["logsource"] = logsource
                elif category in endpoint_cats or windows_values:
                    logsource["product"] = "windows"
                    parsed["logsource"] = logsource

            return yaml.dump(parsed, sort_keys=False)
        except Exception:
            return rule_yaml

    def transpile(
        self,
        rule_yaml: str,
        targets: Optional[List[str]] = None,
    ) -> Dict[str, TranspiledQuery]:
        """Transpile a Sigma rule YAML string to multiple target EDR/SIEM query dialects.

        Args:
            rule_yaml: The canonical Sigma rule in YAML string format.
            targets: List of target identifiers to generate (defaults to all supported).

        Returns:
            Dictionary mapping target ID to TranspiledQuery instance.
        """
        if targets is None:
            targets = list(self.SUPPORTED_TARGETS)

        results: Dict[str, TranspiledQuery] = {}

        if not PYSIGMA_AVAILABLE:
            for target in targets:
                meta = self.TARGET_METADATA.get(target, {"name": target, "dialect": "txt", "extension": ".txt"})
                results[target] = TranspiledQuery(
                    target=target,
                    platform_name=meta["name"],
                    dialect=meta["dialect"],
                    file_extension=meta["extension"],
                    query=None,
                    success=False,
                    error_message="pySigma or backend packages not available in environment",
                )
            return results

        rule_digest = hashlib.sha256(rule_yaml.encode("utf-8")).digest()
        for target in targets:
            meta = self.TARGET_METADATA.get(target, {"name": target, "dialect": "txt", "extension": ".txt"})
            try:
                query, val_res = self._validated_conversion(rule_yaml, rule_digest, target)
                if not val_res.is_valid:
                    results[target] = TranspiledQuery(
                        target=target,
                        platform_name=meta["name"],
                        dialect=meta["dialect"],
                        file_extension=meta["extension"],
                        query=query,
                        success=False,
                        error_message=f"Syntax validation failed: {'; '.join(val_res.error_messages)}",
                        validation=val_res,
                    )
                else:
                    results[target] = TranspiledQuery(
                        target=target,
                        platform_name=meta["name"],
                        dialect=meta["dialect"],
                        file_extension=meta["extension"],
                        query=query,
                        success=True,
                        validation=val_res,
                    )
            except Exception as exc:
                logger.debug("Transpilation failed for target %s: %s", target, exc)
                results[target] = TranspiledQuery(
                    target=target,
                    platform_name=meta["name"],
                    dialect=meta["dialect"],
                    file_extension=meta["extension"],
                    query=None,
                    success=False,
                    error_message=str(exc),
                )

        return results

    def _validated_conversion(self, rule_yaml: str, digest: bytes, target: str) -> tuple[str, QueryValidationResult]:
        converter = self._transpile_single_target
        normalizer = self.normalize_rule_for_backend
        key = (digest, target, getattr(converter, "__func__", converter), getattr(normalizer, "__func__", normalizer))
        # Custom subclasses may have per-instance conversion settings. Do not
        # share their output across instances without a declared settings key.
        cacheable = type(self) is SigmaTranspiler
        with _QUERY_CACHE_LOCK:
            query = _QUERY_CACHE.get(key) if cacheable else None
            if query is None:
                query = converter(normalizer(rule_yaml, target), target)
            validation = self.validator.validate(target, query)
            if cacheable:
                if validation.is_valid and query and len(query.encode("utf-8")) <= MAX_CACHED_QUERY_BYTES:
                    _QUERY_CACHE[key] = query
                    _QUERY_CACHE.move_to_end(key)
                    while len(_QUERY_CACHE) > MAX_QUERY_CACHE_ENTRIES:
                        _QUERY_CACHE.popitem(last=False)
                else:
                    _QUERY_CACHE.pop(key, None)
            return query, validation

    def _transpile_single_target(self, rule_yaml: str, target: str) -> str:
        """Internal helper to convert a Sigma rule for a specific backend."""
        # Always parse a fresh collection to avoid in-place pipeline AST mutation
        col = SigmaCollection.from_yaml(rule_yaml)

        if target == self.TARGET_MDE:
            for rule in col.rules:
                pending = list(rule.detection.detections.values())
                while pending:
                    item = pending.pop()
                    if hasattr(item, "detection_items"):
                        pending.extend(item.detection_items)
                    elif item.field == "Initiated":
                        raise ValueError(
                            "MDE mapping cannot preserve the Initiated direction predicate; "
                            "an explicit direction mapping is required"
                        )
                    elif any(":" in str(getattr(value, "cidr", "")) for value in item.value):
                        raise ValueError(
                            "Kusto backend uses IPv4 CIDR functions and cannot preserve IPv6 CIDRs"
                        )
            if col.rules and col.rules[0].logsource.category in {"proxy", "webserver", "web", "apache", "nginx", "iis"}:
                raise ValueError("HTTP KQL requires an explicit deployed table and field mapping; generic Sigma field names must not become quoted string constants")
            if col.rules and col.rules[0].logsource.category == "dns_query":
                # DNS is a Sentinel ASIM signal, not a generic DeviceEvents
                # field. Preserve the condition AST while mapping only fields
                # whose meaning is established by the ASIM DNS schema.
                # https://learn.microsoft.com/azure/sentinel/normalization-schema-dns
                for rule in col.rules:
                    pending = list(rule.detection.detections.values())
                    while pending:
                        item = pending.pop()
                        if hasattr(item, "detection_items"):
                            pending.extend(item.detection_items)
                        elif item.field != "QueryName":
                            raise ValueError(
                                f"Sentinel ASIM DNS mapping does not support field {item.field!r}"
                            )
                kusto_backend = _get_or_create_backend(
                    "mde_asim_dns",
                    lambda: KustoBackend(
                        processing_pipeline=ProcessingPipeline(items=[ProcessingItem(
                            transformation=FieldMappingTransformation({"QueryName": "DnsQuery"})
                        )])
                    ),
                )
                queries = kusto_backend.convert(col)
                if not queries:
                    raise ValueError("No query returned from Sentinel ASIM DNS backend")
                return "\n\n".join(f"_Im_Dns | where {query}" for query in queries)

            query_table: Optional[str] = None
            try:
                first_rule = col.rules[0] if col.rules else None
                logsource = getattr(first_rule, "logsource", None)
                category = getattr(logsource, "category", None)
                if category:
                    cat = str(category).lower()
                    if cat in {"webserver", "web", "apache", "nginx", "iis"}:
                        query_table = "W3CIISLog"
                    elif cat in {"firewall", "proxy"}:
                        query_table = "CommonSecurityLog"
                    elif cat in {"cloud", "azure", "office365", "o365"}:
                        query_table = "CloudAppEvents"
            except Exception:
                pass

            mde_key = f"mde_table_{query_table}" if query_table else "mde_default"
            kusto_backend = _get_or_create_backend(
                mde_key,
                lambda: KustoBackend(
                    processing_pipeline=(
                        microsoft_365_defender_pipeline(query_table=query_table)
                        if query_table
                        else microsoft_365_defender_pipeline()
                    )
                ),
            )
            try:
                queries = kusto_backend.convert(col)
            except Exception as k_err:
                if "Unable to determine table name" in str(k_err):
                    fallback_backend: Any = _get_or_create_backend(
                        "mde_table_DeviceEvents",
                        lambda: KustoBackend(
                            processing_pipeline=microsoft_365_defender_pipeline(query_table="DeviceEvents")
                        ),
                    )
                    queries = fallback_backend.convert(col)
                else:
                    raise
            if not queries:
                raise ValueError("No query returned from Kusto/MDE backend")
            return "\n\n".join(queries)

        if target == self.TARGET_CROWDSTRIKE:
            cs_backend: Any = _get_or_create_backend(
                "crowdstrike_cql",
                lambda: LogScaleBackend(processing_pipeline=crowdstrike_fdr_pipeline()),
            )
            queries = cs_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from CrowdStrike backend")
            return "\n\n".join(queries)

        if target == self.TARGET_RAPID7:
            idr_backend: Any = _get_or_create_backend(
                "rapid7_leql",
                lambda: InsightIDRBackend(),
            )
            queries = idr_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from Rapid7 InsightIDR backend")
            return "\n\n".join(queries)

        if target == self.TARGET_SENTINELONE:
            s1_backend: Any = _get_or_create_backend(
                "sentinelone_s1ql",
                lambda: SentinelOneBackend(processing_pipeline=build_sentinelone_pipeline()),
            )
            queries = s1_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from SentinelOne backend")
            return "\n\n".join(queries)

        if target == self.TARGET_SPLUNK:
            sp_backend: Any = _get_or_create_backend(
                "splunk_spl",
                lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline()),
            )
            queries = sp_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from Splunk backend")
            return "\n\n".join(queries)

        if target == self.TARGET_ELASTIC:
            if col.rules and col.rules[0].logsource.category in {"proxy", "webserver"}:
                # Proxy/webserver fields do not pass through ecs_windows(). Preserve
                # their meaning with an explicit ECS mapping instead of
                # emitting raw fields such as c-useragent into EQL.
                for rule in col.rules:
                    pending = list(rule.detection.detections.values())
                    while pending:
                        item = pending.pop()
                        if hasattr(item, "detection_items"):
                            pending.extend(item.detection_items)
                        elif item.field not in _ELASTIC_PROXY_MAPPING:
                            raise ValueError(f"{col.rules[0].logsource.category.title()} ECS mapping does not support field {item.field!r}")
                es_backend: Any = _get_or_create_backend(
                    "elastic_proxy_webserver",
                    lambda: EqlBackend(processing_pipeline=ProcessingPipeline(items=[ProcessingItem(
                        transformation=FieldMappingTransformation(_ELASTIC_PROXY_MAPPING)
                    )])),
                )
            elif col.rules and col.rules[0].logsource.product == "linux":
                # ecs_windows() leaves Linux Sigma fields unchanged. Use ECS
                # fields explicitly and reject signals without a mapping.
                # https://www.elastic.co/docs/reference/ecs/ecs-process
                for rule in col.rules:
                    pending = list(rule.detection.detections.values())
                    while pending:
                        item = pending.pop()
                        if hasattr(item, "detection_items"):
                            pending.extend(item.detection_items)
                        elif item.field not in _ELASTIC_LINUX_MAPPING:
                            raise ValueError(f"Linux ECS mapping does not support field {item.field!r}")
                es_backend = _get_or_create_backend(
                    "elastic_linux",
                    lambda: EqlBackend(processing_pipeline=ProcessingPipeline(items=[ProcessingItem(
                        transformation=FieldMappingTransformation(_ELASTIC_LINUX_MAPPING)
                    )])),
                )
            else:
                es_backend = _get_or_create_backend(
                    "elastic_windows",
                    lambda: EqlBackend(processing_pipeline=ecs_windows()),
                )
            queries = es_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from Elastic EQL backend")
            return "\n\n".join(queries)

        raise ValueError(f"Unsupported transpilation target: {target}")

    def format_markdown_queries(
        self,
        results: Dict[str, TranspiledQuery],
        include_heading: bool = True,
    ) -> str:
        """Format transpiled queries into readable GitHub markdown code blocks."""
        lines = []
        if include_heading:
            lines.append("##### Native EDR & SIEM Queries")
            lines.append("")

        for target in self.SUPPORTED_TARGETS:
            res = results.get(target)
            if not res:
                continue

            lines.append(f"**{res.platform_name} ({res.dialect.upper()}):**")
            if res.success and res.query:
                code_lang = "kql" if res.dialect == "kql" else ("text" if res.dialect == "leql" else res.dialect)
                lines.append(f"```{code_lang}")
                lines.append(res.query.strip())
                lines.append("```")
            else:
                lines.append(f"> *Query conversion unavailable: {res.error_message or 'unsupported log source'}*")
            lines.append("")

        return "\n".join(lines).strip()
