import json
import logging
import re
from typing import Any, Dict, List, Tuple

import httpx
from bs4 import BeautifulSoup

from hecate_agent.core.llm_router import create_router
from hecate_agent.core.source_evidence import is_safe_report_url

logger = logging.getLogger(__name__)

#: Upper bound on scraped text per page, to keep the extraction prompt bounded.
_MAX_PAGE_CHARS = 15000

#: Links in CTI blurbs that are not the report itself: MISP event links point at
#: the local MISP instance, which is neither public nor the source.
_SKIP_HOSTS = ("localhost", "127.0.0.1")

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def scrape_url_text(url: str) -> str:
    """Fetch a report page and return its visible text, or "" on any failure."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        resp = httpx.get(url, timeout=15.0, headers=headers, follow_redirects=True)
    except httpx.HTTPError as e:
        logger.error(f"Failed to scrape {url}: {e}")
        return ""
    if resp.status_code != 200:
        logger.warning(f"Failed to scrape {url}: HTTP {resp.status_code}")
        return ""
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return str(soup.get_text(separator="\n", strip=True))[:_MAX_PAGE_CHARS]


def report_urls(threat_intel: str, limit: int = 2) -> List[str]:
    """The first ``limit`` distinct public links in the CTI text."""
    urls: List[str] = []
    for match in _URL_RE.finditer(threat_intel):
        url = match.group(0).rstrip(".,;:)")
        if not is_safe_report_url(url) or url in urls:
            continue
        urls.append(url)
        if len(urls) == limit:
            break
    return urls


def refang(value: str) -> str:
    """Undo report defanging ("hxxp", "[.]", "(.)") so the value matches real telemetry."""
    value = value.replace("[.]", ".").replace("(.)", ".")
    return re.sub(r"hxxp", "http", value, flags=re.IGNORECASE)


def _normalise(text: str) -> str:
    """Lowercase, refang and collapse whitespace and doubled path separators."""
    text = refang(text).lower()
    text = text.replace("\\\\", "\\")
    return re.sub(r"\s+", " ", text).strip()


def verbatim_artifacts(candidates: List[Any], source_text: str) -> Tuple[List[str], List[str]]:
    """Split model-extracted artifacts into those the page contains verbatim and those it does not.

    The extraction model paraphrases and invents: a domain, path or task name
    that is not in the fetched text is the model's, not the report's, and must
    never reach a hunt's observables or a Sigma rule.
    """
    haystack = _normalise(source_text)
    kept: List[str] = []
    dropped: List[str] = []
    for candidate in candidates:
        value = str(candidate).strip()
        if not value:
            continue
        if _normalise(value) in haystack:
            # Kept refanged: a rule or MISP attribute matching "evil[.]com" matches nothing.
            usable = refang(value)
            if usable not in kept:
                kept.append(usable)
        else:
            dropped.append(value)
    return kept, dropped


def _parse_json_object(text: str) -> Dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


SYSTEM_PROMPT = """You are a threat intelligence artifact extractor.
Read the report text provided and extract CONCRETE artifacts, copied EXACTLY as
they appear in the text -- character for character. Do not reformat, complete,
normalise or invent anything. If the text does not contain an artifact, leave it out.

Extract, when present:
- File paths and file names
- Registry keys and values
- Scheduled task, service and LaunchAgent names
- Command lines
- Domains, URLs and IP addresses
- Mutexes, named pipes and other host artifacts

Return a strict JSON object with two keys:
"observables": [ "each artifact, exactly as written in the text" ]
"summary": "Up to 3 sentences on how the artifacts are used, from the text only."
"""


def _fetch_pages(urls: List[str]) -> List[Tuple[str, str]]:
    pages: List[Tuple[str, str]] = []
    for url in urls:
        logger.info(f"Deep Scraping URL: {url}")
        text = scrape_url_text(url)
        if text:
            pages.append((url, text))
    return pages


def _intel_block(pages: List[Tuple[str, str]], observables: List[str], summary: str) -> str:
    lines = [
        "",
        "",
        "### Artifacts from the source report",
        f"Fetched from: {', '.join(url for url, _ in pages)}",
    ]
    if summary:
        lines.append(f"Model summary (unverified): {summary}")
    lines += ["Each artifact below appears verbatim in the fetched text.", ""]
    lines.extend(f"- {o}" for o in observables)
    return "\n".join(lines) + "\n"


def extract_deep_artifacts(threat_intel: str) -> Dict[str, Any]:
    """Fetch the report(s) the CTI links to and extract artifacts they state verbatim."""
    empty: Dict[str, Any] = {"new_intel": "", "new_observables": []}
    pages = _fetch_pages(report_urls(threat_intel))
    if not pages:
        return empty

    from hecate_agent.core.llm_prompt_budget import clip_text_for_simple

    scraped = "\n".join(f"\n--- CONTENT FROM {url} ---\n{text}\n" for url, text in pages)
    # artifact_extract routes to simple by default; keep the blob under the
    # simple-tier budget before escalation can widen to complex.
    scraped = clip_text_for_simple(scraped)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": scraped},
    ]

    def _valid_extract(text: str) -> bool:
        data = _parse_json_object(text)
        return isinstance(data.get("observables"), list)

    try:
        from hecate_agent.core.llm_escalate import complete_with_escalation

        response, _escalated = complete_with_escalation(
            create_router(),
            messages,
            validate=_valid_extract,
            temperature=0.0,
            capability="artifact_extract",
        )
    except Exception as e:  # the provider raises its SDK's own error types
        logger.error(f"Deep Artifact Extraction Failed: {e}")
        return empty

    data = _parse_json_object(response.text)
    candidates = data.get("observables", [])
    observables, dropped = verbatim_artifacts(candidates if isinstance(candidates, list) else [], scraped)
    if dropped:
        logger.warning(
            f"Dropped {len(dropped)} extracted artifact(s) not found verbatim in the fetched report: {dropped[:10]}"
        )
    if not observables:
        return empty
    summary = str(data.get("summary", "")).strip()
    return {"new_intel": _intel_block(pages, observables, summary), "new_observables": observables}
