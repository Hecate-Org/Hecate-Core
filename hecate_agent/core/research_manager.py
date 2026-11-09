"""Manage research files and operations."""

import contextlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

if TYPE_CHECKING:
    from hecate_agent.agents.llm.hypothesis_generator import ResearchContext

import yaml

from hecate_agent.core.catalog_index import CatalogIndex
from hecate_agent.utils.validation import validate_research_id

try:
    import fcntl as _fcntl_module
except ImportError:  # pragma: no cover - fcntl is POSIX-only
    _fcntl_module = None  # type: ignore[assignment]

# Bound through an Optional alias so the Windows fallback in
# _id_allocation_lock stays a reachable branch rather than one the type
# checker prunes as dead. Placed below the imports because the alias is a
# statement, and an import after it would trip E402.
_fcntl: Optional[Any] = _fcntl_module

# Persisted high-water mark for allocated research IDs, kept in research/.
# The ID used to be derived purely by scanning research/ for the highest
# R-XXXX still present, which made it a function of what happened to be on
# disk rather than of what had ever been allocated. Clearing the directory --
# the normal cleanup here is to commit the documents and remove them -- reset
# numbering to R-0001, so new documents silently reused IDs that already
# named a different document in git history. Since drafts reference their
# grounding as `spawned_from: R-XXXX`, a reused ID also repoints that link at
# the wrong research. The counter records the highest ID ever handed out, so
# numbering survives the directory being emptied.
#
# Stored as a JSON object keyed by ID prefix, since get_next_research_id()
# takes a configurable prefix and separate prefixes must not share a mark.
_ID_COUNTER_FILENAME = ".research_id_counter"

# flock target guarding the counter's read-modify-write. Mirrors the hunt
# side's .hunt_id.lock; created on demand, never read, and never created at
# all on platforms without fcntl.
_ID_LOCK_FILENAME = ".research_id.lock"

# Bound the one-off git seed scan so a large or damaged repo cannot wedge
# research ID allocation behind it.
_GIT_SEED_TIMEOUT_SEC = 30


def _default_file_mode() -> int:
    """Mode a plain open() would create: 0o666 masked by the process umask.

    Read once at import, before any worker threads exist -- querying the
    umask means temporarily setting it, which is not thread-safe.
    """
    umask = os.umask(0o022)
    os.umask(umask)
    return 0o666 & ~umask


_DEFAULT_FILE_MODE = _default_file_mode()


class ResearchParser:
    """Parser for research files (YAML frontmatter + markdown)."""

    def __init__(self, file_path: Path) -> None:
        """Initialize parser with research file path."""
        self.file_path = Path(file_path)
        self.frontmatter: Dict[str, Any] = {}
        self.content = ""
        self.sections: Dict[str, str] = {}

    def parse(self) -> Dict[str, Any]:
        """Parse research file and return structured data.

        Returns:
            Dict containing frontmatter, content, and sections
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Research file not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return self.parse_text(content)

    def parse_text(self, content: str) -> Dict[str, Any]:
        """Parse an already-read document, for incremental catalog readers."""

        # Parse YAML frontmatter
        self.frontmatter = self._parse_frontmatter(content)

        # Extract main content (after frontmatter)
        self.content = self._extract_content(content)

        # Parse research sections
        self.sections = self._parse_sections(self.content)

        return {
            "file_path": str(self.file_path),
            "research_id": self.frontmatter.get("research_id"),
            "frontmatter": self.frontmatter,
            "content": self.content,
            "sections": self.sections,
        }

    def _parse_frontmatter(self, content: str) -> Dict[str, Any]:
        """Extract and parse YAML frontmatter."""
        frontmatter_pattern = r"^---\s*\n(.*?)\n---\s*\n"
        match = re.match(frontmatter_pattern, content, re.DOTALL)

        if not match:
            return {}

        frontmatter_text = match.group(1)

        try:
            return yaml.safe_load(frontmatter_text) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML frontmatter: {e}")

    def _extract_content(self, content: str) -> str:
        """Extract content after frontmatter."""
        frontmatter_pattern = r"^---\s*\n.*?\n---\s*\n"
        content_without_fm = re.sub(frontmatter_pattern, "", content, count=1, flags=re.DOTALL)
        return content_without_fm.strip()

    def _parse_sections(self, content: str) -> Dict[str, str]:
        """Parse research sections from content.

        Returns:
            Dict with section names and content
        """
        sections = {}

        # Define section patterns for the 5 research skills
        section_patterns = {
            "system_research": r"##\s+1\.\s+System Research.*?(?=##\s+2\.|$)",
            "adversary_tradecraft": r"##\s+2\.\s+Adversary Tradecraft.*?(?=##\s+3\.|$)",
            "telemetry_mapping": r"##\s+3\.\s+Telemetry Mapping.*?(?=##\s+4\.|$)",
            "related_work": r"##\s+4\.\s+Related Work.*?(?=##\s+5\.|$)",
            "synthesis": r"##\s+5\.\s+Research Synthesis.*?(?=\n## (?!#)|$)",
        }

        for section_name, pattern in section_patterns.items():
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                sections[section_name] = match.group(0).strip()

        return sections


def parse_research_file(file_path: Path) -> Dict[str, Any]:
    """Convenience function to parse a research file."""
    parser = ResearchParser(file_path)
    return parser.parse()


def _generated_hypothesis_lines(
    *,
    hypothesis: str,
    justification: Optional[str],
    mitre_techniques: Optional[List[str]],
    data_sources: Optional[List[str]],
    expected_observables: Optional[List[str]],
    known_false_positives: Optional[List[str]],
    time_range_suggestion: Optional[str],
) -> List[str]:
    """Render the "## Generated Hypothesis" body.

    Every field is optional and each was guarded inline, which is what made
    append_hypothesis too complex to read: the guards had nothing to do with
    the file rewrite around them.
    """
    lines: List[str] = ["", "", "## Generated Hypothesis", "", f"> {hypothesis}", ""]
    if justification:
        lines.extend(["**Justification:**", "", justification, ""])
    if mitre_techniques:
        lines.extend(["**MITRE Techniques:** " + ", ".join(mitre_techniques), ""])
    if data_sources:
        lines.extend(["**Data Sources:** " + ", ".join(data_sources), ""])
    for heading, items in (
        ("**Expected Observables:**", expected_observables),
        ("**Known False Positives:**", known_false_positives),
    ):
        if items:
            lines.extend([heading, "", *(f"- {item}" for item in items), ""])
    if time_range_suggestion:
        lines.extend([f"**Time Range:** {time_range_suggestion}", ""])
    return lines


class ResearchManager:
    """Manage research files and operations.

    Similar pattern to HuntManager but for research documents.
    Research files use R-XXXX IDs and are stored in research/ directory.
    """

    def __init__(self, research_dir: Optional[Path] = None) -> None:
        """Initialize research manager.

        Args:
            research_dir: Directory containing research files (default: ./research)
        """
        self.research_dir = Path(research_dir) if research_dir else Path.cwd() / "research"
        self._research_mtimes: Dict[str, int] = {}

        if not self.research_dir.exists():
            self.research_dir.mkdir(parents=True, exist_ok=True)

    def _find_all_research_files(self) -> List[Path]:
        """Find all research files (R-*.md).

        Returns:
            List of paths to research files
        """
        research_files: List[Path] = []

        # Find flat files (R-*.md)
        research_files.extend(self.research_dir.rglob("R-*.md"))

        return sorted(set(research_files))

    def _counter_path(self) -> Path:
        """Path to the persisted research ID high-water mark."""
        return self.research_dir / _ID_COUNTER_FILENAME

    @contextlib.contextmanager
    def _id_allocation_lock(self) -> Iterator[None]:
        """Serialize the counter's read-modify-write across processes.

        Without this, a manual `hecate-agent research new` overlapping the hourly
        orchestrator can have both processes read the same high-water mark
        before either writes it back, and both allocate the same ID.

        This covers allocation only, not the later write of the research
        document -- the caller does that well after the lock is released.

        No-op where fcntl is unavailable (Windows): concurrent callers there
        can read the same mark and be handed the same ID, which is the
        pre-existing behavior. Degrading was chosen over a Windows-specific
        lock that no CI here can exercise, and over blocking the import
        outright. See get_next_research_id for the caller-facing statement of
        that limit, and test_allocation_works_without_fcntl for what still
        holds.
        """
        if _fcntl is None:
            yield
            return

        self.research_dir.mkdir(parents=True, exist_ok=True)
        with open(self.research_dir / _ID_LOCK_FILENAME, "w") as lock_file:
            _fcntl.flock(lock_file, _fcntl.LOCK_EX)
            try:
                yield
            finally:
                _fcntl.flock(lock_file, _fcntl.LOCK_UN)

    def _read_id_counters(self) -> Dict[str, int]:
        """Read the persisted per-prefix high-water marks.

        Returns:
            Mapping of ID prefix to highest allocated number. Empty when the
            file is absent, unreadable, or corrupted by a hand-edit -- the
            caller falls back to the on-disk and git floors rather than
            failing allocation over a bad counter.
        """
        try:
            data = json.loads(self._counter_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

        if not isinstance(data, dict):
            return {}

        return {
            key: value
            for key, value in data.items()
            if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool)
        }

    def _write_id_counter(self, prefix: str, value: int) -> None:
        """Persist `value` as the high-water mark for `prefix`.

        Written to a temp file in the same directory and renamed over the
        destination: os.replace is atomic on POSIX, so a reader only ever
        sees the old complete file or the new complete one, never a partial
        write from an interrupted process.

        Args:
            prefix: Research ID prefix the mark applies to
            value: Highest allocated number for that prefix
        """
        counters = self._read_id_counters()
        counters[prefix] = value

        path = self._counter_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(counters, f, indent=2, sort_keys=True)
            # mkstemp hardcodes 0600 and os.replace carries that onto the
            # destination, which would leave the counter private to its owner
            # while every other file in the workspace is world-readable.
            os.chmod(tmp_name, _DEFAULT_FILE_MODE)
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def _max_id_on_disk(self, prefix: str) -> int:
        """Highest research ID currently written under research_dir.

        Args:
            prefix: Research ID prefix to match

        Returns:
            Highest matching number, or 0 when none are present
        """
        numbers = []
        pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")

        for research_file in self._find_all_research_files():
            try:
                research_data = parse_research_file(research_file)
                research_id = research_data.get("frontmatter", {}).get("research_id")

                if not research_id or not isinstance(research_id, str):
                    continue

                match = pattern.match(research_id)
                if match:
                    numbers.append(int(match.group(1)))
            except Exception:
                # Try to extract from filename if parsing fails
                match = pattern.match(research_file.stem)
                if match:
                    numbers.append(int(match.group(1)))

        return max(numbers) if numbers else 0

    def _max_id_in_git(self, prefix: str) -> int:
        """Highest research ID ever committed under research_dir.

        Seeds the counter on the first allocation after it was introduced, so
        numbering resumes past every document git remembers instead of
        restarting underneath documents that were committed and then cleaned
        off disk. `--name-only` over `--all` lists paths from every commit on
        every branch, which includes files added and later deleted -- exactly
        the ones a disk scan can no longer see.

        Args:
            prefix: Research ID prefix to match

        Returns:
            Highest matching number, or 0 when the workspace is not a git
            repo, git is unavailable, or the scan fails or times out. A
            missing seed only risks reusing an ID already unreachable on
            disk, which is not worth failing allocation over.
        """
        try:
            proc = subprocess.run(
                [
                    "git",
                    "log",
                    "--all",
                    "--pretty=format:",
                    "--name-only",
                    "--",
                    self.research_dir.name,
                ],
                cwd=self.research_dir.parent,
                capture_output=True,
                text=True,
                timeout=_GIT_SEED_TIMEOUT_SEC,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return 0

        if proc.returncode != 0:
            return 0

        numbers = [int(match.group(1)) for match in re.finditer(rf"{re.escape(prefix)}(\d+)\.md", proc.stdout)]
        return max(numbers) if numbers else 0

    def get_next_research_id(self, prefix: str = "R-") -> str:
        """Allocate the next research ID and persist it as the new
        high-water mark.

        The ID is burned at allocation time, before the document is written,
        so a run that dies between the two leaves a gap in the numbering
        rather than handing the same ID to the next caller.

        Concurrency is serialized across processes only where fcntl exists
        (POSIX). On Windows the lock degrades to a no-op, so two
        `hecate-agent research new` runs started at the same instant can be handed
        the same ID -- and since the document is named after it, the second
        written would overwrite the first. Known and accepted: the scheduled
        orchestrator runs on Linux, and interactive Windows use is
        sequential. Anything driving this concurrently on Windows needs its
        own locking.

        Args:
            prefix: Research ID prefix (default: R-)

        Returns:
            Next research ID (e.g., R-0023)
        """
        with self._id_allocation_lock():
            # The on-disk max is always a floor, so a document added by hand
            # (or by a version predating the counter) cannot be clobbered.
            high_water = self._max_id_on_disk(prefix)

            counters = self._read_id_counters()
            if prefix in counters:
                high_water = max(high_water, counters[prefix])
            else:
                high_water = max(high_water, self._max_id_in_git(prefix))

            next_num = high_water + 1
            self._write_id_counter(prefix, next_num)

        return f"{prefix}{next_num:04d}"

    def list_research(
        self,
        status: Optional[str] = None,
        technique: Optional[str] = None,
        topic: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all research documents with optional filters.

        Args:
            status: Filter by status (draft, in_progress, completed)
            technique: Filter by MITRE technique
            topic: Filter by topic (substring match)

        Returns:
            List of research metadata dicts
        """
        research_list = []
        self._research_mtimes = {}

        research_files = self._find_all_research_files()
        index = CatalogIndex(self.research_dir, "research-frontmatter-v1")
        index.refresh(
            research_files,
            lambda path, text: {"frontmatter": ResearchParser(path)._parse_frontmatter(text)},
        )
        CatalogIndex(self.research_dir, "research-document-v1").prune(research_files)
        for entry in index.entries():
            research_file = self.research_dir / entry.path.relative_to(self.research_dir.absolute())
            self._research_mtimes[str(research_file)] = entry.mtime_ns
            try:
                frontmatter = entry.data.get("frontmatter", {})

                # Apply filters
                if status and frontmatter.get("status") != status:
                    continue

                if technique:
                    techniques = frontmatter.get("mitre_techniques", [])
                    if technique not in techniques:
                        continue

                if topic:
                    research_topic = frontmatter.get("topic", "").lower()
                    if topic.lower() not in research_topic:
                        continue

                # Extract summary info
                research_list.append(
                    {
                        "research_id": frontmatter.get("research_id"),
                        "topic": frontmatter.get("topic"),
                        "status": frontmatter.get("status"),
                        "created_date": frontmatter.get("created_date"),
                        "depth": frontmatter.get("depth"),
                        "mitre_techniques": frontmatter.get("mitre_techniques", []),
                        "linked_hunts": frontmatter.get("linked_hunts", []),
                        "duration_minutes": frontmatter.get("duration_minutes"),
                        "total_cost_usd": frontmatter.get("total_cost_usd"),
                        "file_path": str(research_file),
                    }
                )

            except Exception:
                # Skip files that can't be parsed
                continue

        return research_list

    def get_research(self, research_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific research document by ID.

        Args:
            research_id: Research ID (e.g., R-0001)

        Returns:
            Research data dict or None if not found
        """
        # Validate research ID format and prevent path traversal
        if not validate_research_id(research_id):
            return None

        # Try direct file
        research_file = self.research_dir / f"{research_id}.md"

        # Validate path is within research directory
        try:
            research_file.resolve().relative_to(self.research_dir.resolve())
        except (ValueError, OSError):
            return None

        if research_file.exists():
            return self._indexed_research(research_file)

        # Try nested search
        research_files = list(self.research_dir.rglob(f"{research_id}.md"))
        if research_files:
            # Validate nested file is also within research directory (Python 3.8 compatible)
            nested_file = research_files[0]
            try:
                nested_file.resolve().relative_to(self.research_dir.resolve())
            except (ValueError, OSError):
                return None
            return self._indexed_research(nested_file)

        return None

    def _indexed_research(self, path: Path) -> Optional[Dict[str, Any]]:
        index = CatalogIndex(self.research_dir, "research-document-v1")
        index.refresh([path], lambda path, text: ResearchParser(path).parse_text(text), prune=False)
        entries = index.entries()
        if not entries:
            return parse_research_file(path)  # Preserve selected-document parse errors.
        result = entries[0].data
        result["file_path"] = str(path)
        return result

    def extract_research_context(self, research_doc: Dict[str, Any]) -> "ResearchContext":
        """Extract structured ResearchContext from a parsed research document.

        Args:
            research_doc: Parsed research doc from get_research()

        Returns:
            ResearchContext dataclass instance
        """
        from hecate_agent.agents.llm.hypothesis_generator import ResearchContext

        frontmatter = research_doc.get("frontmatter", {})
        sections = research_doc.get("sections", {})

        # Extract from frontmatter
        research_id = frontmatter.get("research_id", "")
        topic = frontmatter.get("topic", "")
        mitre_techniques = frontmatter.get("mitre_techniques", [])
        data_source_availability = frontmatter.get("data_source_availability", {})
        estimated_hunt_complexity = frontmatter.get("estimated_hunt_complexity", "unknown")
        raw_actors = frontmatter.get("threat_actors", [])
        threat_actors = [raw_actors] if isinstance(raw_actors, str) else list(raw_actors)

        # Extract from synthesis section
        synthesis = sections.get("synthesis", "")
        recommended_hypothesis = self._extract_markdown_blockquote(synthesis)
        gaps_identified = self._extract_markdown_list_under_heading(synthesis, "Gaps Identified")

        # Extract from adversary_tradecraft section
        adversary_section = sections.get("adversary_tradecraft", "")
        adversary_tradecraft_findings = self._extract_markdown_list_under_heading(adversary_section, "Key Findings")
        adversary_tradecraft_summary = self._extract_markdown_paragraph_under_heading(adversary_section, "Summary")

        # Extract from telemetry_mapping section (handles both "Key Findings" and "Key Fields")
        telemetry_section = sections.get("telemetry_mapping", "")
        telemetry_mapping_findings = self._extract_markdown_list_under_heading(telemetry_section, "Key Findings")
        if not telemetry_mapping_findings:
            telemetry_mapping_findings = self._extract_markdown_list_under_heading(telemetry_section, "Key Fields")
        telemetry_mapping_summary = self._extract_markdown_paragraph_under_heading(telemetry_section, "Summary")

        # Extract system research summary
        system_section = sections.get("system_research", "")
        system_research_summary = self._extract_markdown_paragraph_under_heading(system_section, "Summary")

        return ResearchContext(
            research_id=research_id,
            topic=topic,
            mitre_techniques=mitre_techniques,
            recommended_hypothesis=recommended_hypothesis,
            gaps_identified=gaps_identified,
            data_source_availability=data_source_availability,
            estimated_hunt_complexity=estimated_hunt_complexity,
            adversary_tradecraft_findings=adversary_tradecraft_findings,
            telemetry_mapping_findings=telemetry_mapping_findings,
            system_research_summary=system_research_summary,
            adversary_tradecraft_summary=adversary_tradecraft_summary,
            telemetry_mapping_summary=telemetry_mapping_summary,
            threat_actors=threat_actors,
        )

    def find_by_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Find the most recent completed research document for a technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1055)

        Returns:
            Parsed research doc or None if not found
        """
        matches = self.list_research(technique=technique_id, status="completed")

        if not matches:
            return None

        # Sort by created_date descending, pick most recent
        matches.sort(key=lambda r: r.get("created_date", ""), reverse=True)

        research_id = matches[0].get("research_id")
        if research_id:
            return self.get_research(research_id)

        return None

    def find_recent_match(
        self,
        topic: str,
        technique_id: Optional[str] = None,
        max_age_days: int = 7,
    ) -> Optional[Dict[str, Any]]:
        """Find recent completed research for a topic or technique within max_age_days.

        Avoids redundant LLM and Tavily calls when high-quality research on the same
        threat actor, malware family, or technique already exists.
        """
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        clean_topic = topic.strip().lower()
        candidates = []

        for r in self.list_research(status="completed"):
            r_topic = str(r.get("topic", "")).strip().lower()
            r_path = r.get("file_path")

            age_ok = False
            if r_path:
                try:
                    timestamp = self._research_mtimes.get(r_path)
                    modified = timestamp / 1_000_000_000 if timestamp is not None else Path(r_path).stat().st_mtime
                    mtime = datetime.datetime.fromtimestamp(modified, tz=datetime.timezone.utc)
                    if (now - mtime).total_seconds() <= max_age_days * 86400:
                        age_ok = True
                except Exception:
                    pass
            if not age_ok and r.get("created_date"):
                try:
                    dt = datetime.datetime.fromisoformat(str(r["created_date"]))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=datetime.timezone.utc)
                    if (now - dt).total_seconds() <= max_age_days * 86400:
                        age_ok = True
                except Exception:
                    pass

            if not age_ok:
                continue

            topic_matched = False
            if clean_topic and r_topic:
                if clean_topic == r_topic:
                    topic_matched = True
                elif len(clean_topic) >= 4 and (clean_topic in r_topic or r_topic in clean_topic):
                    topic_matched = True

            technique_matched = False
            if technique_id and technique_id in r.get("mitre_techniques", []):
                technique_matched = True

            if topic_matched or (technique_id and technique_matched and len(clean_topic) <= 6):
                candidates.append((r, 2 if topic_matched else 1))

        if not candidates:
            return None

        # Dates have day precision, so same-day regenerations need the
        # monotonically allocated ID as a tie-breaker. File mtime is unsuitable:
        # linking an old document to another hunt touches it without refreshing
        # its research.
        def freshness(item: Any) -> tuple[Any, ...]:
            document, priority = item
            suffix = str(document.get("research_id", "")).removeprefix("R-")
            sequence = int(suffix) if suffix.isdigit() else -1
            return priority, str(document.get("created_date", "")), sequence

        candidates.sort(key=freshness, reverse=True)
        best_id = candidates[0][0].get("research_id")
        if best_id:
            return self.get_research(best_id)
        return None

    @staticmethod
    def _extract_markdown_blockquote(text: str) -> Optional[str]:
        """Extract the first blockquote line from markdown text.

        Args:
            text: Markdown text to search

        Returns:
            Blockquote content without '> ' prefix, or None
        """
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("> "):
                return stripped[2:]
        return None

    @staticmethod
    def _extract_markdown_list_under_heading(text: str, heading: str) -> List[str]:
        """Extract bullet list items under a specific ### heading.

        Args:
            text: Markdown text to search
            heading: Heading text (without ### prefix)

        Returns:
            List of bullet item strings (without '- ' prefix)
        """
        items: List[str] = []
        in_section = False

        for line in text.split("\n"):
            stripped = line.strip()

            # Check for target heading
            if stripped.lower() == f"### {heading.lower()}" or stripped.lower() == f"### {heading}".lower():
                in_section = True
                continue

            # Stop at next heading
            if in_section and stripped.startswith("### "):
                break

            # Collect list items
            if in_section and stripped.startswith("- "):
                items.append(stripped[2:])

        return items

    @staticmethod
    def _extract_markdown_paragraph_under_heading(text: str, heading: str) -> str:
        """Extract the first paragraph under a specific ### heading.

        Args:
            text: Markdown text to search
            heading: Heading text (without ### prefix)

        Returns:
            Paragraph text, or empty string
        """
        in_section = False
        paragraph_lines: List[str] = []

        for line in text.split("\n"):
            stripped = line.strip()

            # Check for target heading
            if stripped.lower() == f"### {heading.lower()}" or stripped.lower() == f"### {heading}".lower():
                in_section = True
                continue

            # Stop at next heading
            if in_section and stripped.startswith("### "):
                break

            if in_section:
                if stripped:
                    paragraph_lines.append(stripped)
                elif paragraph_lines:
                    # First empty line after content ends the paragraph
                    break

        return " ".join(paragraph_lines)

    def search_research(self, query: str) -> List[Dict[str, Any]]:
        """Full-text search across research documents.

        Args:
            query: Search query string

        Returns:
            List of matching research documents
        """
        results = []
        query_lower = query.lower()

        for research_file in self._find_all_research_files():
            try:
                with open(research_file, "r", encoding="utf-8") as f:
                    content = f.read()

                if query_lower in content.lower():
                    research_data = parse_research_file(research_file)
                    frontmatter = research_data.get("frontmatter", {})

                    results.append(
                        {
                            "research_id": frontmatter.get("research_id"),
                            "topic": frontmatter.get("topic"),
                            "status": frontmatter.get("status"),
                            "file_path": str(research_file),
                        }
                    )

            except Exception:
                continue

        return results

    def link_hunt_to_research(self, research_id: str, hunt_id: str) -> bool:
        """Link a hunt to its source research.

        Updates the research document's linked_hunts field.

        Args:
            research_id: Research ID (e.g., R-0001)
            hunt_id: Hunt ID to link (e.g., H-0001)

        Returns:
            True if successful, False otherwise
        """
        research_data = self.get_research(research_id)
        if not research_data:
            return False

        file_path = Path(research_data["file_path"])

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Frontmatter is round-tripped through yaml rather than patched by
            # regex. The previous pattern matched up to the next key with
            # DOTALL and re-appended a newline, so every call left a stray
            # blank line behind ("linked_hunts: [...]\n\nweb_searches: 0") --
            # accumulating one per link, since `hecate-agent hunt new --research` runs
            # this on every hunt created from a research doc.
            parts = content.split("---", 2)
            if len(parts) < 3:
                return False

            frontmatter = yaml.safe_load(parts[1]) or {}
            linked_hunts = frontmatter.get("linked_hunts") or []

            if hunt_id in linked_hunts:
                return True

            linked_hunts.append(hunt_id)
            frontmatter["linked_hunts"] = linked_hunts

            # flow_style=None keeps short lists inline; width avoids wrapping a
            # long topic onto a continuation line.
            new_frontmatter = yaml.dump(frontmatter, default_flow_style=None, sort_keys=False, width=4096)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("---\n{}---{}".format(new_frontmatter, parts[2]))

            return True

        except Exception:
            return False

    def append_hypothesis(
        self,
        research_id: str,
        hypothesis: str,
        mitre_techniques: Optional[List[str]] = None,
        data_sources: Optional[List[str]] = None,
        justification: Optional[str] = None,
        expected_observables: Optional[List[str]] = None,
        known_false_positives: Optional[List[str]] = None,
        time_range_suggestion: Optional[str] = None,
    ) -> Optional[Path]:
        """Append a generated hypothesis to a research document.

        Adds (or replaces) a ``## Generated Hypothesis`` section at the end of
        the markdown body, and records ``generated_hypothesis`` metadata in the
        YAML frontmatter for quick lookup. Idempotent: re-running with new
        content overwrites the prior section in place.

        Args:
            research_id: Research ID (e.g., R-0001)
            hypothesis: Hypothesis statement
            mitre_techniques: Linked MITRE ATT&CK techniques
            data_sources: Suggested data sources
            justification: Reasoning the hypothesis is worth hunting
            expected_observables: What we expect to see in telemetry
            known_false_positives: Common benign patterns
            time_range_suggestion: Recommended hunt time window

        Returns:
            Path to the updated file, or None if research_id not found.
        """
        research_data = self.get_research(research_id)
        if not research_data:
            return None

        file_path = Path(research_data["file_path"])

        # Re-check the file is still readable before rebuilding it: research_data
        # came from an earlier parse, so the file may have been removed or had
        # its permissions changed since. The contents are deliberately not read
        # -- the rewrite below is reconstructed entirely from research_data.
        try:
            with open(file_path, "r", encoding="utf-8"):
                pass
        except OSError:
            return None

        # Update frontmatter with structured hypothesis metadata
        new_frontmatter = dict(research_data.get("frontmatter", {}))
        new_frontmatter["generated_hypothesis"] = {
            "hypothesis": hypothesis,
            "mitre_techniques": list(mitre_techniques or []),
            "data_sources": list(data_sources or []),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        body = research_data.get("content", "")
        body = self._strip_generated_hypothesis_section(body)
        body = body.rstrip()

        section_lines = _generated_hypothesis_lines(
            hypothesis=hypothesis,
            justification=justification,
            mitre_techniques=mitre_techniques,
            data_sources=data_sources,
            expected_observables=expected_observables,
            known_false_positives=known_false_positives,
            time_range_suggestion=time_range_suggestion,
        )

        new_body = body + "\n".join(section_lines).rstrip() + "\n"

        yaml_content = yaml.dump(new_frontmatter, default_flow_style=False, sort_keys=False)
        new_content = f"---\n{yaml_content}---\n\n{new_body}"

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return None

        return file_path

    @staticmethod
    def _strip_generated_hypothesis_section(body: str) -> str:
        """Remove an existing ``## Generated Hypothesis`` section if present.

        Args:
            body: Markdown body (after frontmatter)

        Returns:
            Body with the section removed (everything from the heading through
            the next ``## `` heading or end of document).
        """
        pattern = re.compile(
            r"\n##\s+Generated\s+Hypothesis\b.*?(?=\n##\s+(?!#)|\Z)",
            re.DOTALL | re.IGNORECASE,
        )
        return pattern.sub("", body)

    def create_research_file(
        self,
        research_id: str,
        topic: str,
        content: str,
        frontmatter: Dict[str, Any],
    ) -> Path:
        """Create a new research file.

        Args:
            research_id: Research ID (e.g., R-0001)
            topic: Research topic
            content: Markdown content
            frontmatter: YAML frontmatter dict

        Returns:
            Path to created file
        """
        # Ensure research_id and topic are in frontmatter
        frontmatter["research_id"] = research_id
        frontmatter["topic"] = topic
        frontmatter.setdefault("created_date", datetime.now().strftime("%Y-%m-%d"))
        frontmatter.setdefault("status", "completed")

        # Build file content
        yaml_content = yaml.dump(frontmatter, default_flow_style=False, sort_keys=False)
        file_content = f"---\n{yaml_content}---\n\n{content}"

        # Write file
        file_path = self.research_dir / f"{research_id}.md"

        # Validate path is within research directory (Python 3.8 compatible)
        try:
            file_path.resolve().relative_to(self.research_dir.resolve())
        except (ValueError, OSError) as e:
            raise ValueError(f"Invalid research file path: {e}") from e

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(file_content)

        return file_path

    def _hunts_spawned_from(self) -> Dict[str, set]:
        """Map research_id -> set of hunt_ids whose `spawned_from` names it.

        `linked_hunts` on the research doc is meant to be the inverse of a
        hunt's `spawned_from`, but nothing keeps them in sync -- a hunt
        creator (CLI or an external orchestrator) that sets `spawned_from`
        has no obligation, and often no code path, to also write back to
        the research doc's `linked_hunts`. Scanning hunts directly makes
        stats correct regardless of whether that write-back ever happened.
        """
        from hecate_agent.core.hunt_manager import HuntManager  # local import: avoid a module-level cycle

        hunts_dir = self.research_dir.parent / "hunts"
        mapping: Dict[str, set] = {}
        if not hunts_dir.exists():
            return mapping
        for hunt in HuntManager(hunts_dir).list_hunts():
            research_id = hunt.get("spawned_from")
            if not research_id:
                continue
            mapping.setdefault(research_id, set()).add(hunt.get("hunt_id"))
        return mapping

    def calculate_stats(self) -> Dict[str, Any]:
        """Calculate research program statistics.

        Returns:
            Dict with counts, costs, and other metrics
        """
        research_list = self.list_research()

        if not research_list:
            return {
                "total_research": 0,
                "completed_research": 0,
                "total_cost_usd": 0.0,
                "unpriced_research": 0,
                "total_duration_minutes": 0,
                "avg_duration_minutes": 0.0,
                "by_status": {},
                "total_linked_hunts": 0,
            }

        total_research = len(research_list)
        completed_research = len([r for r in research_list if r.get("status") == "completed"])

        # A document whose cost is unknown (null) is counted apart, not as $0.
        priced = [r["total_cost_usd"] for r in research_list if r.get("total_cost_usd") is not None]
        total_cost = sum(priced)
        unpriced = total_research - len(priced)
        total_duration = sum(r.get("duration_minutes", 0) or 0 for r in research_list)
        avg_duration = total_duration / total_research if total_research > 0 else 0.0

        # Count by status
        by_status: Dict[str, int] = {}
        for research in research_list:
            status = research.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

        # Count linked hunts. Unions each research doc's own `linked_hunts`
        # frontmatter with hunts discovered via their `spawned_from` field,
        # so a hunt creator that only ever sets `spawned_from` (never calls
        # back to update the research doc) still counts here.
        spawned_from = self._hunts_spawned_from()
        total_linked_hunts = sum(
            len(set(r.get("linked_hunts", [])) | spawned_from.get(r.get("research_id", ""), set())) for r in research_list
        )

        return {
            "total_research": total_research,
            "completed_research": completed_research,
            "total_cost_usd": round(total_cost, 4),
            "unpriced_research": unpriced,
            "total_duration_minutes": total_duration,
            "avg_duration_minutes": round(avg_duration, 1),
            "by_status": by_status,
            "total_linked_hunts": total_linked_hunts,
        }
