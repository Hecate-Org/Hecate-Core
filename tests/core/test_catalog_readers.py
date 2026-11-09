"""Research and similarity readers reuse unchanged indexed source documents."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from hecate_agent.commands.similar import _clear_tfidf_cache, _find_similar_hunts
from hecate_agent.core.research_manager import ResearchManager


def write_hunt(root, number, *, title="Kerberos ticket theft", status="completed"):
    root.mkdir(exist_ok=True)
    path = root / f"H-{number:04}.md"
    path.write_text(
        f"---\ntitle: {title}\nstatus: {status}\ntactics: [credential-access]\n---\n## Hypothesis\nKerberos ticket cracking\n"
    )
    return path


def watch_reads(monkeypatch):
    original = Path.read_text
    reads = []

    def read(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    return reads


def watch_fits(monkeypatch):
    from sklearn.feature_extraction.text import TfidfVectorizer

    original = TfidfVectorizer.fit_transform
    fits = []

    def fit(self, *args, **kwargs):
        fits.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(TfidfVectorizer, "fit_transform", fit)
    return fits


def test_metadata_only_changes_reuse_matrix_and_read_only_the_changed_hunt(tmp_path, monkeypatch):
    root = tmp_path / "hunts"
    first = write_hunt(root, 1)
    write_hunt(root, 2)
    fits = watch_fits(monkeypatch)
    _find_similar_hunts("kerberos", workspace=tmp_path, threshold=0)
    reads = watch_reads(monkeypatch)
    first.write_text(first.read_text().replace("status: completed", "status: planning"))
    reads.clear()
    results = _find_similar_hunts("kerberos", workspace=tmp_path, threshold=0)
    assert reads == [first]
    assert len(fits) == 1
    assert next(row for row in results if row["hunt_id"] == "H-0001")["status"] == "planning"
    reads.clear()
    _find_similar_hunts("kerberos", workspace=tmp_path)
    assert reads == []


def test_search_text_edits_refit_and_match_a_fresh_search(tmp_path, monkeypatch):
    root = tmp_path / "hunts"
    first = write_hunt(root, 1)
    write_hunt(root, 2, title="Process execution")
    fits = watch_fits(monkeypatch)
    _find_similar_hunts("kerberos", workspace=tmp_path)
    first.write_text(first.read_text().replace("Kerberos ticket theft", "Password spraying"))
    reads = watch_reads(monkeypatch)
    changed = _find_similar_hunts("password spraying", workspace=tmp_path, threshold=0)
    assert reads == [first] and len(fits) == 2
    _clear_tfidf_cache()
    reads.clear()
    fresh = _find_similar_hunts("password spraying", workspace=tmp_path, threshold=0)
    assert fresh == changed
    assert reads == []  # Parsed documents survive a new in-memory search cache.


def test_session_components_refresh_independently(tmp_path, monkeypatch):
    hunt = write_hunt(tmp_path / "hunts", 1)
    session = tmp_path / "sessions/H-0001-2026-01-01"
    session.mkdir(parents=True)
    decision = session / "decisions.yaml"
    decision.write_text("decisions:\n- decision: Kerberos ticket abuse\n")
    metadata = session / "session.yaml"
    metadata.write_text("query_count: 1\n")
    fits = watch_fits(monkeypatch)
    _find_similar_hunts("kerberos", workspace=tmp_path, include_sessions=True)
    reads = watch_reads(monkeypatch)
    metadata.write_text("query_count: 2\n")
    _find_similar_hunts("kerberos", workspace=tmp_path, include_sessions=True)
    assert reads == [metadata] and len(fits) == 1
    reads.clear()
    decision.write_text("decisions:\n- decision: Password spraying was observed\n")
    results = _find_similar_hunts("password spraying", workspace=tmp_path, include_sessions=True, threshold=0)
    assert reads == [decision] and len(fits) == 2
    assert any(row.get("session_id") == session.name for row in results)
    assert hunt not in reads
    decision.unlink()
    results = _find_similar_hunts("password spraying", workspace=tmp_path, include_sessions=True, threshold=0)
    assert all(row["source"] != "session" for row in results)


def test_adding_and_deleting_hunts_does_not_reread_survivors(tmp_path, monkeypatch):
    root = tmp_path / "hunts"
    first = write_hunt(root, 1)
    _find_similar_hunts("kerberos", workspace=tmp_path)
    second = write_hunt(root, 2)
    first.unlink()
    reads = watch_reads(monkeypatch)
    results = _find_similar_hunts("kerberos", workspace=tmp_path, threshold=0)
    assert reads == [second]
    assert [row["hunt_id"] for row in results] == ["H-0002"]


def test_concurrent_searches_build_one_matrix_per_workspace(tmp_path, monkeypatch):
    write_hunt(tmp_path / "hunts", 1)
    fits = watch_fits(monkeypatch)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _find_similar_hunts("kerberos", workspace=tmp_path), range(3)))
    assert len(fits) == 1
    assert all(rows == results[0] for rows in results)


def test_research_listing_and_reuse_are_warm_across_manager_instances(tmp_path, monkeypatch):
    root = tmp_path / "research"
    root.mkdir()
    path = root / "R-0001.md"
    path.write_text(
        f"---\nresearch_id: R-0001\ntopic: Kerberos ticket theft\nstatus: completed\ncreated_date: {date.today().isoformat()}\nlinked_hunts: []\n---\n## 5. Research Synthesis\nGrounded research.\n"
    )
    manager = ResearchManager(root)
    first = manager.find_recent_match("Kerberos ticket theft")
    assert first["research_id"] == "R-0001"
    reads = watch_reads(monkeypatch)
    assert ResearchManager(root).find_recent_match("Kerberos ticket theft") == first
    assert reads == []
    manager.link_hunt_to_research("R-0001", "H-0002")
    reads.clear()
    updated = ResearchManager(root).find_recent_match("Kerberos ticket theft")
    assert updated["frontmatter"]["linked_hunts"] == ["H-0002"]
    assert all(file == path for file in reads)
    path.unlink()
    assert ResearchManager(root).find_recent_match("Kerberos ticket theft") is None
    with sqlite3.connect(tmp_path / ".hecate/catalog.sqlite3") as conn:
        assert conn.execute("SELECT count(*) FROM documents WHERE namespace LIKE '%research-document-v1'").fetchone()[0] == 0


def test_research_relative_file_path_contract_is_preserved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    root = Path("research")
    root.mkdir()
    (root / "R-0001.md").write_text("---\nresearch_id: R-0001\nstatus: completed\n---\nBody\n")
    manager = ResearchManager(root)
    assert manager.list_research()[0]["file_path"] == "research/R-0001.md"
    assert manager.get_research("R-0001")["file_path"] == "research/R-0001.md"


def test_workspace_indexes_cannot_cross_contaminate(tmp_path):
    workspaces = [tmp_path / "one", tmp_path / "two"]
    for workspace, title in zip(workspaces, ["Kerberos ticket theft", "Cloud credential abuse"]):
        workspace.mkdir()
        write_hunt(workspace / "hunts", 1, title=title)
    assert _find_similar_hunts("kerberos", workspace=workspaces[0], threshold=0)[0]["title"] == "Kerberos ticket theft"
    assert _find_similar_hunts("cloud", workspace=workspaces[1], threshold=0)[0]["title"] == "Cloud credential abuse"
