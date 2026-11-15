"""Compare local Qwen and configured Claude in private, isolated subprocesses.

No production workspace, routing, services, outboxes or demotion stamps change.
Only ANTHROPIC_API_KEY is accepted from an explicitly selected dotenv file.
"""

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def isolated_environment(directory: Path, api_key: str | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
    home = directory / "home"
    home.mkdir(mode=0o700)
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        HECATE_SERVICE_ISOLATED="1",
        PYTHON_DOTENV_DISABLED="1",
        HECATE_WORKSPACE=str(directory),
        HECATE_OLLAMA_THINK="false",
        HECATE_OLLAMA_NUM_CTX="16384",
        HECATE_OLLAMA_TIMEOUT_SEC="600",
        HECATE_LLM_MAX_RETRIES="0",
        LITELLM_LOG="ERROR",
        LITELLM_LOCAL_MODEL_COST_MAP="true",
    )
    # Explicitly evaluate this checkout rather than another editable installation.
    checkout = Path(__file__).resolve().parents[1]
    if (checkout / "hecate_agent").is_dir():
        env["PYTHONPATH"] = str(checkout)
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
    return env


def local_model_metadata(model: str) -> dict:
    """Record the installed digest; a mutable Ollama tag alone is insufficient."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10) as response:
            models = json.load(response).get("models", [])
        selected = next((m for m in models if m.get("name") == model), {})
        return {"name": model, "digest": selected.get("digest"), "details": selected.get("details")}
    except Exception as exc:
        return {"name": model, "metadata_error": type(exc).__name__}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-model", default="qwen3.6:35b-a3b-q4_K_M")
    parser.add_argument("--claude-model", default="anthropic/claude-sonnet-4-5-20250929")
    parser.add_argument("--credential-env-file", type=Path, help="Read only ANTHROPIC_API_KEY; never source the file")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--repeats", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--max-cost-usd", type=float, default=1.0, help="Remote API estimate cap; not an invoice guarantee")
    parser.add_argument("--local-only", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.max_cost_usd) or args.max_cost_usd <= 0:
        parser.error("--max-cost-usd must be positive and finite")
    key = os.getenv("ANTHROPIC_API_KEY")
    if args.credential_env_file:
        from dotenv import dotenv_values

        key = dotenv_values(args.credential_env_file, interpolate=False).get("ANTHROPIC_API_KEY")
    if not args.local_only and not key:
        parser.error("ANTHROPIC_API_KEY is missing; export it or provide --credential-env-file")
    if not args.claude_model.startswith("anthropic/claude-"):
        parser.error("--claude-model must select an Anthropic Claude model")
    os.umask(0o077)
    if args.output_root:
        args.output_root.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="hecate-quality-", dir=args.output_root)).resolve()
    checkout = Path(__file__).resolve().parents[1]
    source_snapshot = root / "evaluator-source"
    for relative in (
        "hecate_agent/core/model_quality.py",
        "hecate_agent/commands/model_quality.py",
        "hecate_agent/data/evals/model-quality-v1.yaml",
        "scripts/compare_model_quality.py",
    ):
        destination = source_snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checkout / relative, destination)
    metadata = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "local_model": local_model_metadata(args.local_model),
        "remote_model": None if args.local_only else args.claude_model,
        "repeats": args.repeats,
        "max_api_estimate_usd": args.max_cost_usd,
        "production_configuration_changed": False,
    }
    (root / "run-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Private evaluation reports: {root}", flush=True)
    reports = []
    targets = [("qwen", "ollama", args.local_model)]
    if not args.local_only:
        targets.append(("claude", "litellm", args.claude_model))
    status = 0
    for label, provider, model in targets:
        folder = root / label
        folder.mkdir(mode=0o700)
        report = folder / "report.json"
        env = isolated_environment(folder, key if provider != "ollama" else None)
        print(f"Running {label}: {model} ({args.repeats} repetitions)...", flush=True)
        command = [
            sys.executable,
            "-m",
            "hecate_agent.cli",
            "eval-suite",
            "--provider",
            provider,
            "--model",
            model,
            "--repeats",
            str(args.repeats),
            "--max-cost-usd",
            str(args.max_cost_usd),
            "--report",
            str(report),
        ]
        with (folder / "progress.log").open("w") as log:
            completed = subprocess.run(
                command, cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=log, check=False, timeout=7200
            )
        status = 1 if status or completed.returncode else 0
        if not report.is_file():
            status = 1
            print(f"{label}: no report; inspect {folder / 'progress.log'}", flush=True)
            continue
        payload = json.loads(report.read_text())
        reports.append(payload)
        print(
            f"{label}: {payload['passed']}/{payload['total']}, gate={'PASS' if payload['gate_passed'] else 'FAIL'}", flush=True
        )
    if len(reports) == 2:
        # Import this checkout's scorer without loading CLI dotenv discovery.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from hecate_agent.core.model_quality import compare_reports

        comparison = compare_reports(reports)
        comparison["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
        (root / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
        print("Comparison: " + str(root / "comparison.json"), flush=True)
    print("Production routing and services were not changed.", flush=True)
    metadata["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["exit_code"] = status
    (root / "run-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
