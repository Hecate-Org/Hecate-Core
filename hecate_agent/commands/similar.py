"""Semantic similarity search for past hunts."""

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.table import Table

from hecate_agent.core.catalog_index import CatalogIndex, file_fingerprint

console = Console()


class _CachedCorpus(NamedTuple):
    signature: Tuple[Any, ...]
    hunt_data: List[Dict[str, Any]]
    session_data: List[Dict[str, Any]]
    vectorizer: Any
    doc_vectors: Any
    text_signature: str


_CACHE_LOCK = threading.Lock()
_CORPUS_CACHE: Dict[str, _CachedCorpus] = {}
_BUILD_LOCKS: Dict[str, Any] = {}


def _clear_tfidf_cache() -> None:
    """Clear in-memory TF-IDF and corpus cache."""
    with _CACHE_LOCK:
        _CORPUS_CACHE.clear()


def _get_corpus_signature(hunt_files: List[Path], sessions_dir: Path) -> Tuple[Any, ...]:
    """Check edits and replacements, including same-size/restored-mtime edits."""
    files = []
    for hf in hunt_files:
        try:
            files.append((str(hf.absolute()), file_fingerprint(hf)))
        except OSError:
            pass
    if sessions_dir.exists() and sessions_dir.is_dir():
        try:
            for item in sessions_dir.iterdir():
                if item.is_dir():
                    for name in ("decisions.yaml", "summary.md", "session.yaml"):
                        p = item / name
                        try:
                            files.append((str(p.absolute()), file_fingerprint(p)))
                        except OSError:
                            pass
        except OSError:
            pass
    files.sort(key=lambda x: x[0])
    return tuple(files)


class SimilarityUnavailable(RuntimeError):
    """Similarity search cannot run because scikit-learn is not installed.

    Distinct from "ran and found nothing" on purpose. `_find_similar_hunts` is
    a library function -- the research agent and the MCP server both call it --
    and collapsing an absent dependency into an empty result list let the
    runner report "no similar hunts found" for a search that never happened.
    """

SIMILAR_EPILOG = """
\b
Examples:
  # Find hunts similar to a text query
  hecate-agent similar "password spraying via RDP"

  # Find hunts similar to specific hunt
  hecate-agent similar --hunt H-0013

  # Include session logs as separate results
  hecate-agent similar "telegram bot" --sessions

  # Limit results to top 5
  hecate-agent similar "kerberos" --limit 5

  # Export as JSON
  hecate-agent similar "credential theft" --format json

\b
Why This Helps AI:
  • Semantic search (not just keyword matching)
  • Find related hunts with different terminology
  • Session decisions and rationales boost hunt scores
  • --sessions shows individual session matches
  • Discover patterns across hunt history
  • Better than grep for conceptual matches
  • Identify similar hunts to avoid duplication
"""


@click.command(epilog=SIMILAR_EPILOG)
@click.argument("query", required=False)
@click.option("--hunt", help="Hunt ID to find similar hunts for (e.g., H-0013)")
@click.option("--limit", default=10, type=int, help="Maximum number of results (default: 10)")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format (default: table)",
)
@click.option("--threshold", default=0.1, type=float, help="Minimum similarity score (0-1, default: 0.1)")
@click.option("--sessions", is_flag=True, default=False, help="Include session logs as separate results")
def similar(
    query: Optional[str],
    hunt: Optional[str],
    limit: int,
    output_format: str,
    threshold: float,
    sessions: bool,
) -> None:
    """Find hunts similar to a query or hunt ID.

    Uses semantic similarity to find related hunts even when
    terminology differs. Session logs (decisions, rationales)
    are folded into hunt scores by default.

    \b
    Use Cases:
    • Check if similar hunt already exists
    • Find related hunts for context
    • Search past session decisions and rationales
    • Discover patterns across hunt history
    • Identify hunt clusters by topic

    \b
    Examples:
      # Text query
      hecate-agent similar "password spraying"

      # Include session results
      hecate-agent similar "orphaned CDN" --sessions

      # Similar to existing hunt
      hecate-agent similar --hunt H-0013

      # Top 5 results
      hecate-agent similar "lateral movement" --limit 5
    """
    # Validate inputs
    if not query and not hunt:
        console.print("[red]Error: Must provide either QUERY or --hunt option[/red]")
        console.print("\n[dim]Examples:[/dim]")
        console.print('  hecate-agent similar "password spraying"')
        console.print("  hecate-agent similar --hunt H-0013")
        raise click.Abort()

    if query and hunt:
        console.print("[red]Error: Cannot specify both QUERY and --hunt[/red]")
        raise click.Abort()

    # Get query text
    query_text: str
    if hunt:
        hunt_text = _get_hunt_text(hunt)
        if not hunt_text:
            console.print(f"[red]Error: Hunt {hunt} not found[/red]")
            raise click.Abort()
        query_text = hunt_text
    else:
        query_text = query or ""  # Should never be None due to validation above

    # Find similar hunts
    try:
        results = _find_similar_hunts(query_text, limit=limit, threshold=threshold, exclude_hunt=hunt, include_sessions=sessions)
    except SimilarityUnavailable as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise click.Abort() from exc

    # Format and display results
    if output_format == "json":
        output = json.dumps(results, indent=2)
        click.echo(output)
    elif output_format == "yaml":
        output = yaml.dump(results, default_flow_style=False, sort_keys=False)
        click.echo(output)
    else:  # table
        _display_results_table(results, query_text=query_text, reference_hunt=hunt, include_sessions=sessions)


def _get_hunt_text(hunt_id: str, workspace: Optional[Path] = None) -> Optional[str]:
    """Get full text content of a hunt.

    Args:
        workspace: See _find_similar_hunts's `workspace` param -- same
            cwd-relative-by-default, explicit-path-when-provided contract.
    """
    from hecate_agent.core.hunt_manager import HuntManager

    hunt_file = HuntManager(hunts_dir=(workspace / "hunts") if workspace else None).find_hunt_file(hunt_id)
    if not hunt_file:
        return None
    return hunt_file.read_text(encoding="utf-8")


def _build_corpus(
    hunt_files: List[Path],
    *,
    sessions_dir: Path,
    exclude_hunt: Optional[str],
    include_sessions: bool,
    catalog_root: Optional[Path] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Turn hunt files into searchable documents, folding sessions in.

    Session text is folded into its parent hunt at 0.75x weight so a hunt with
    a rich session history ranks above an identical one without, without the
    sessions swamping the hunt's own wording. With ``include_sessions`` the
    sessions are additionally returned as documents of their own.
    """
    hunt_data: List[Dict[str, Any]] = []
    session_data: List[Dict[str, Any]] = []
    if not hunt_files:
        return hunt_data, session_data

    index = CatalogIndex(catalog_root or hunt_files[0].parent, "similarity-hunts-v1")
    index.refresh(hunt_files, _hunt_search_document)
    indexed_hunts = {entry.path: entry.data for entry in index.entries()}
    indexed_sessions = _indexed_session_data(sessions_dir, set(path.stem for path in hunt_files))
    for hunt_file in hunt_files:
        hunt_id = hunt_file.stem
        if exclude_hunt and hunt_id == exclude_hunt:
            continue

        document = indexed_hunts.get(hunt_file.absolute())
        if document is None:
            continue
        metadata = document["metadata"]
        searchable_text = document["searchable_text"]

        hunt_sessions = indexed_sessions.get(hunt_id, [])
        if hunt_sessions:
            session_texts = " ".join(s["searchable_text"] for s in hunt_sessions)
            searchable_text = f"{searchable_text} {session_texts[: int(len(session_texts) * 0.75)]}"

        hunt_data.append(
            {
                "hunt_id": hunt_id,
                "searchable_text": searchable_text,
                "metadata": metadata,
                "source": "hunt",
                "session_count": len(hunt_sessions),
            }
        )
        if include_sessions:
            session_data.extend(hunt_sessions)

    return hunt_data, session_data


def _hunt_search_document(path: Path, content: str) -> Dict[str, Any]:
    metadata = _extract_hunt_metadata(content)
    return {"metadata": metadata, "searchable_text": _extract_searchable_text(content, metadata)}


def _session_component(path: Path, content: str) -> Dict[str, Any]:
    if path.name == "summary.md":
        return {"text": " ".join(filter(None, (_extract_section(content, heading) for heading in ("## Key Decisions", "## Lessons"))))}
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        data = {}
    if path.name == "decisions.yaml":
        return {"text": " ".join(_decision_parts(data))}
    return {"metadata": data if isinstance(data, dict) else {}}


def _indexed_session_data(sessions_dir: Path, hunt_ids: set) -> Dict[str, List[Dict[str, Any]]]:
    paths: list[Path] = []
    if sessions_dir.is_dir():
        for directory in sorted(sessions_dir.iterdir()):
            if directory.is_dir():
                paths.extend(directory / name for name in ("decisions.yaml", "summary.md", "session.yaml"))
    index = CatalogIndex(sessions_dir, "similarity-session-components-v1")
    index.refresh(paths, _session_component)
    components: Dict[str, Dict[str, Any]] = {}
    for entry in index.entries():
        components.setdefault(entry.path.parent.name, {})[entry.path.name] = entry.data
    results: Dict[str, List[Dict[str, Any]]] = {}
    for session_id, values in sorted(components.items()):
        text = " ".join(filter(None, (values.get(name, {}).get("text", "") for name in ("decisions.yaml", "summary.md")))).strip()
        if not text:
            continue
        # Match the old '<hunt-id>-*' rule without scanning every session for
        # every hunt. Prefixes also preserve behavior for nonstandard hunt IDs.
        parents = {session_id[:i] for i, char in enumerate(session_id) if char == "-"} & hunt_ids
        for hunt_id in parents:
            results.setdefault(hunt_id, []).append({
                "session_id": session_id, "hunt_id": hunt_id, "searchable_text": text,
                "metadata": values.get("session.yaml", {}).get("metadata", {}),
            })
    return results


def _get_or_build_corpus_cache(
    hunt_files: List[Path],
    sessions_dir: Path,
    workspace_key: str,
    vectorizer_cls: Any,
) -> Optional[_CachedCorpus]:
    """Retrieve cached corpus and TF-IDF matrix or build a new one if stale."""
    with _CACHE_LOCK:
        build_lock = _BUILD_LOCKS.setdefault(workspace_key, threading.Lock())
    with build_lock:
        return _refresh_corpus_cache(hunt_files, sessions_dir, workspace_key, vectorizer_cls)


def _refresh_corpus_cache(hunt_files: List[Path], sessions_dir: Path, workspace_key: str, vectorizer_cls: Any) -> Optional[_CachedCorpus]:
    current_sig = _get_corpus_signature(hunt_files, sessions_dir)
    with _CACHE_LOCK:
        cached = _CORPUS_CACHE.get(workspace_key)
    if cached is not None and cached.signature == current_sig:
        return cached

    # Rebuild corpus
    hunt_data, session_data = _build_corpus(
        hunt_files,
        sessions_dir=sessions_dir,
        exclude_hunt=None,
        include_sessions=True,
        catalog_root=Path(workspace_key) / "hunts",
    )

    if not hunt_data:
        return None

    all_docs = hunt_data + session_data
    doc_texts = [d["searchable_text"] for d in all_docs]

    signature = hashlib.sha256()
    for document in all_docs:
        signature.update(json.dumps([document["hunt_id"], document.get("session_id"), document["searchable_text"]]).encode())
    text_signature = signature.hexdigest()
    if cached is not None and cached.text_signature == text_signature:
        vectorizer, doc_vectors = cached.vectorizer, cached.doc_vectors
    else:
        vectorizer = vectorizer_cls(max_features=1000, stop_words="english", ngram_range=(1, 2))
        try:
            doc_vectors = vectorizer.fit_transform(doc_texts)
        except ValueError:
            doc_vectors = None

    entry = _CachedCorpus(
        signature=current_sig,
        hunt_data=hunt_data,
        session_data=session_data,
        vectorizer=vectorizer,
        doc_vectors=doc_vectors,
        text_signature=text_signature,
    )
    with _CACHE_LOCK:
        _CORPUS_CACHE[workspace_key] = entry
        while len(_CORPUS_CACHE) > 16:
            _CORPUS_CACHE.pop(next(key for key in _CORPUS_CACHE if key != workspace_key))
    return entry


def _find_similar_hunts(
    query_text: str,
    limit: int = 10,
    threshold: float = 0.1,
    exclude_hunt: Optional[str] = None,
    include_sessions: bool = False,
    workspace: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Find similar hunts using TF-IDF similarity.

    Sessions are always folded into their parent hunt's searchable text
    at 0.75x weight. When include_sessions=True, sessions are also added
    as separate documents in the corpus.

    Args:
        workspace: Workspace root to search under. Defaults to None, which
            preserves this function's original behavior of resolving
            hunts/sessions relative to the current working directory (the
            CLI's own convention -- a command always runs with cwd set to
            the workspace). Pass this explicitly from callers that can't
            rely on cwd being the right workspace, e.g. a long-lived MCP
            server thread -- an explicit path is race-free where temporarily
            os.chdir()-ing for the duration of the call would not be,
            since chdir is process-wide and this server may run tool calls
            on separate threads.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError as exc:
        # Raised, not printed. Click output goes to the wrong place when the
        # caller is the research agent or the MCP server, and click.Abort
        # carries no meaning outside a Click app. The CLI command renders it.
        raise SimilarityUnavailable(
            "scikit-learn is required for similarity search. "
            "Install with: pip install -e '.[similarity]'"
        ) from exc

    # Load all hunts (HuntManager handles recursive search + deduplication)
    from hecate_agent.core.hunt_manager import HuntManager

    hunt_files = HuntManager(hunts_dir=(workspace / "hunts") if workspace else None).find_all_hunt_files()

    if not hunt_files:
        return []

    workspace_path = workspace.resolve() if workspace else Path.cwd().resolve()
    sessions_dir = (workspace / "sessions") if workspace else Path("sessions")

    corpus_entry = _get_or_build_corpus_cache(
        hunt_files=hunt_files,
        sessions_dir=sessions_dir,
        workspace_key=str(workspace_path),
        vectorizer_cls=TfidfVectorizer,
    )

    if not corpus_entry or corpus_entry.doc_vectors is None or not corpus_entry.hunt_data:
        return []

    hunt_count = len(corpus_entry.hunt_data)
    if include_sessions:
        all_docs = corpus_entry.hunt_data + corpus_entry.session_data
        doc_vectors = corpus_entry.doc_vectors
    else:
        all_docs = corpus_entry.hunt_data
        doc_vectors = corpus_entry.doc_vectors[:hunt_count]

    try:
        query_vector = corpus_entry.vectorizer.transform([query_text])
    except Exception:
        return []

    similarities = cosine_similarity(query_vector, doc_vectors)[0]

    # Build results
    results = []
    for i, doc_info in enumerate(all_docs):
        if exclude_hunt and doc_info.get("hunt_id") == exclude_hunt:
            continue

        score = float(similarities[i])
        if score < threshold:
            continue

        if "session_id" not in doc_info:
            # Hunt result
            metadata = doc_info["metadata"]
            results.append(
                {
                    "source": "hunt",
                    "hunt_id": doc_info["hunt_id"],
                    "similarity_score": round(score, 4),
                    "title": metadata.get("title", "Unknown"),
                    "status": metadata.get("status", "unknown"),
                    "tactics": metadata.get("tactics", []),
                    "techniques": metadata.get("techniques", []),
                    "platform": metadata.get("platform", []),
                    "session_count": doc_info.get("session_count", 0),
                }
            )
        else:
            # Session result
            sess_meta = doc_info.get("metadata", {})
            # Auto-generate title from first 60 chars of decision text
            title = doc_info["searchable_text"][:60]
            if len(doc_info["searchable_text"]) > 60:
                title = title.rsplit(" ", 1)[0] + "..."

            results.append(
                {
                    "source": "session",
                    "session_id": doc_info["session_id"],
                    "hunt_id": doc_info["hunt_id"],
                    "similarity_score": round(score, 4),
                    "title": title,
                    "decision_count": (
                        len(sess_meta.get("decisions", [])) if isinstance(sess_meta.get("decisions"), list) else 0
                    ),
                    "query_count": sess_meta.get("query_count", 0),
                }
            )

    results.sort(key=lambda x: x["similarity_score"], reverse=True)
    return results[:limit]


def _extract_hunt_metadata(content: str) -> Dict[str, Any]:
    """Extract YAML frontmatter metadata from hunt file."""
    if not content.startswith("---"):
        return {}

    try:
        yaml_end = content.find("---", 3)
        if yaml_end > 0:
            frontmatter = content[3:yaml_end]
            return yaml.safe_load(frontmatter) or {}
    except yaml.YAMLError:
        return {}

    return {}


def _extract_searchable_text(content: str, metadata: Dict[str, Any]) -> str:  # noqa: C901
    """Extract semantically important text for similarity matching.

    Focuses on key sections and applies weighting to improve match accuracy:
    - Title (3x weight)
    - Hypothesis (2x weight)
    - ABLE framework sections (1.5x weight)
    - Tactics/Techniques (1x weight)

    Ignores: SQL queries, results, timestamps, org IDs, lessons learned
    """
    parts = []

    # Title (3x weight - most important)
    title = metadata.get("title", "")
    if title:
        parts.extend([title] * 3)

    # Tactics and techniques (1x weight)
    tactics = metadata.get("tactics", [])
    if isinstance(tactics, list):
        parts.extend(tactics)
    elif tactics:
        parts.append(str(tactics))

    techniques = metadata.get("techniques", [])
    if isinstance(techniques, list):
        parts.extend(techniques)
    elif techniques:
        parts.append(str(techniques))

    platform = metadata.get("platform", [])
    if isinstance(platform, list):
        parts.extend(platform)
    elif platform:
        parts.append(str(platform))

    # Extract hypothesis section (2x weight)
    hypothesis = _extract_section(content, "## Hypothesis")
    if hypothesis:
        parts.extend([hypothesis] * 2)

    # Extract ABLE framework sections (1.5x weight each)
    able_sections = ["Actor", "Behavior", "Location", "Evidence"]
    for section in able_sections:
        text = _extract_section(content, f"### {section}")
        if text:
            # Weight 1.5x = add once + half again
            parts.append(text)
            parts.append(text[: len(text) // 2])  # Add first half again for 1.5x weight

    return " ".join(parts)


def _extract_section(content: str, heading: str) -> str:
    """Extract text from a markdown section until the next heading."""
    lines = content.split("\n")
    section_lines = []
    in_section = False

    for line in lines:
        if line.startswith(heading):
            in_section = True
            continue

        if in_section:
            # Stop at next heading of same or higher level
            if line.startswith("#"):
                break
            section_lines.append(line)

    return " ".join(section_lines).strip()


def _extract_session_text(session_dir: Path) -> str:
    """Extract searchable text from a session's decisions and summary.

    Reads decisions.yaml (decision + rationale fields) and summary.md
    (Key Decisions + Lessons sections). Skips queries.yaml (SQL noise)
    and session.yaml (metadata only).
    """
    if not session_dir.exists():
        return ""

    parts = _decision_text(session_dir / "decisions.yaml")
    parts.extend(_summary_text(session_dir / "summary.md"))
    return " ".join(parts).strip()


def _decision_text(decisions_file: Path) -> List[str]:
    """Decision and rationale strings from a session's decisions.yaml.

    Malformed or unreadable files yield nothing rather than raising: this
    feeds a similarity search, where a missing session is a smaller problem
    than a crash mid-listing.
    """
    if not decisions_file.exists():
        return []
    try:
        data = yaml.safe_load(decisions_file.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return []

    return _decision_parts(data)


def _decision_parts(data: Any) -> List[str]:
    if not isinstance(data, dict) or not isinstance(data.get("decisions"), list):
        return []

    parts: List[str] = []
    for decision in data["decisions"]:
        if not isinstance(decision, dict):
            continue
        parts.extend(str(decision[key]) for key in ("decision", "rationale") if decision.get(key))
    return parts


def _summary_text(summary_file: Path) -> List[str]:
    """The Key Decisions and Lessons sections of a session summary."""
    if not summary_file.exists():
        return []
    try:
        content = summary_file.read_text(encoding="utf-8")
    except OSError:
        return []

    sections = (_extract_section(content, heading) for heading in ("## Key Decisions", "## Lessons"))
    return [section for section in sections if section]


def _load_session_data(sessions_dir: Path, hunt_id: str) -> List[Dict[str, Any]]:
    """Load session data for a given hunt ID.

    Returns list of dicts with session_id, hunt_id, searchable_text,
    and metadata from session.yaml.
    """
    if not sessions_dir.exists():
        return []

    sessions = []
    for session_dir in sorted(sessions_dir.glob(f"{hunt_id}-*")):
        if not session_dir.is_dir():
            continue

        session_id = session_dir.name
        searchable_text = _extract_session_text(session_dir)
        if not searchable_text:
            continue

        # Load session metadata
        metadata: Dict[str, Any] = {}
        session_yaml = session_dir / "session.yaml"
        if session_yaml.exists():
            try:
                metadata = yaml.safe_load(session_yaml.read_text(encoding="utf-8")) or {}
            except (yaml.YAMLError, OSError):
                pass

        sessions.append(
            {
                "session_id": session_id,
                "hunt_id": hunt_id,
                "searchable_text": searchable_text,
                "metadata": metadata,
            }
        )

    return sessions


def _score_cell(score: float) -> str:
    """Colour a similarity score by band (see the legend under the table)."""
    for threshold, style in ((0.5, "bold green"), (0.3, "green"), (0.15, "yellow")):
        if score >= threshold:
            return f"[{style}]{score:.3f}[/{style}]"
    return f"[dim]{score:.3f}[/dim]"


def _result_columns(result: Dict[str, Any], source: str) -> Tuple[str, str, str, str]:
    """The id/title/status/tactics cells for one row.

    Sessions have no status or tactics of their own, so both render as an
    em dash rather than borrowing their parent hunt's -- a session is not
    "planning" just because its hunt is.
    """
    if source == "session":
        return result.get("session_id", ""), result.get("title", ""), "[dim]\u2014[/dim]", "[dim]\u2014[/dim]"

    status = result.get("status", "unknown")
    status_map = {"completed": "\u2705", "in-progress": "\U0001f504", "planning": "\U0001f4cb"}
    tactics = result.get("tactics", [])
    tactics_str = ", ".join(tactics[:2])
    if len(tactics) > 2:
        tactics_str += f" +{len(tactics) - 2}"
    # Bound outside the f-string: a backslash escape inside an f-string
    # expression is a syntax error before Python 3.12, and this package
    # supports 3.8.
    status_emoji = status_map.get(status, "\u2753")
    return (
        result.get("hunt_id", ""),
        result.get("title", "Unknown"),
        f"{status_emoji} {status}",
        tactics_str,
    )


def _display_results_table(
    results: List[Dict[str, Any]],
    query_text: str,
    reference_hunt: Optional[str] = None,
    include_sessions: bool = False,
) -> None:
    """Display results in rich table format."""
    # Header (always show, even if no results)
    if reference_hunt:
        console.print(f"\n[bold]Similar to {reference_hunt}:[/bold]")
    else:
        query_preview = query_text[:60] + "..." if len(query_text) > 60 else query_text
        console.print(f"\n[bold]Similar to:[/bold] [dim]{query_preview}[/dim]")

    if not results:
        console.print("[yellow]No similar hunts found[/yellow]")
        return

    # Count sources
    hunt_count = sum(1 for r in results if r.get("source") == "hunt")
    session_count = sum(1 for r in results if r.get("source") == "session")
    if include_sessions and session_count > 0:
        console.print(f"[dim]Found {hunt_count} hunts and {session_count} sessions[/dim]\n")
    else:
        console.print(f"[dim]Found {len(results)} similar hunts[/dim]\n")

    # Table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Score", style="green", no_wrap=True, width=6)
    if include_sessions:
        table.add_column("Source", style="magenta", no_wrap=True, width=8)
    table.add_column("ID", style="cyan", no_wrap=True, width=22 if include_sessions else 10)
    table.add_column("Title", style="white")
    table.add_column("Status", style="yellow", no_wrap=True, width=12)
    table.add_column("Tactics", style="dim", width=20)

    for result in results:
        source = result.get("source", "hunt")
        result_id, title, status_display, tactics_str = _result_columns(result, source)
        score_str = _score_cell(result["similarity_score"])

        if include_sessions:
            source_str = f"[magenta]{source}[/magenta]" if source == "session" else source
            table.add_row(score_str, source_str, result_id, title, status_display, tactics_str)
        else:
            table.add_row(score_str, result_id, title, status_display, tactics_str)

    console.print(table)

    # Legend
    console.print("\n[dim]Similarity Score Legend:[/dim]")
    console.print(
        "[dim]  \u22650.50 = Very similar  |  0.30-0.49 = Similar  |  0.15-0.29 = Somewhat similar  |  <0.15 = Low similarity[/dim]\n"
    )
