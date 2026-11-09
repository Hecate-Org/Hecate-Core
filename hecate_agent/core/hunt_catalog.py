"""Indexed source-link and CVE membership for intake deduplication."""

import re
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from hecate_agent.core.catalog_index import CatalogIndex


def _source_metadata(path: Path, text: str) -> Dict[str, Any]:
    urls: set[str] = set()
    # Index literal Markdown destinations, retaining the old ](URL) membership
    # semantics even when a URL itself contains parentheses.
    for line in text.splitlines():
        for match in re.finditer(r"\]\(", line):
            tail = line[match.end() :]
            urls.update(tail[: end.start()] for end in re.finditer(r"\)", tail))
    cves: set[str] = set()
    for match in re.finditer(r"CVE-\d{4}-\d+", text):
        # Intake historically used substring membership, including a shorter
        # CVE suffix occurring at the start of a longer one. Preserve it.
        value = match.group()
        cves.update(value[:length] for length in range(13, min(len(value), 41) + 1))
    return {"url": sorted(urls), "cve": sorted(cves)}


def _tokens(data: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    return ((kind, token) for kind in ("url", "cve") for token in data[kind])


def source_catalog(hunts_root: Path) -> CatalogIndex:
    index = CatalogIndex(hunts_root, "source-membership-v1")
    index.refresh(hunts_root.rglob("H-*.md"), _source_metadata, tokens=_tokens)
    return index
