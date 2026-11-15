"""Run the CLI's recall checks against local Ollama without changing routing."""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile


def run_evaluation(model: str, output_root: Path | None = None) -> int:
    """Retain private reports, including failures, without inheriting API keys."""
    if output_root is not None:
        output_root.mkdir(parents=True, exist_ok=True)
    result = Path(tempfile.mkdtemp(prefix="hecate-eval-", dir=output_root)).resolve()
    home = result / "home"
    home.mkdir(mode=0o700)
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        HECATE_SERVICE_ISOLATED="1",
        PYTHON_DOTENV_DISABLED="1",
        HECATE_WORKSPACE=str(result),
        HECATE_LLM_PROVIDER="ollama",
        HECATE_LLM_MODEL=model,
        HECATE_LLM_BASE_URL="http://127.0.0.1:11434",
        HECATE_LLM_SIMPLE_PROVIDER="ollama",
        HECATE_LLM_SIMPLE_MODEL=model,
        HECATE_LLM_SIMPLE_BASE_URL="http://127.0.0.1:11434",
        HECATE_LLM_COMPLEX_PROVIDER="ollama",
        HECATE_LLM_COMPLEX_MODEL=model,
        HECATE_LLM_COMPLEX_BASE_URL="http://127.0.0.1:11434",
        HECATE_OLLAMA_TIMEOUT_SEC="600",
        HECATE_OLLAMA_NUM_CTX="16384",
        HECATE_OLLAMA_THINK="false",
        HECATE_LLM_CALL_LOG=str(result / "calls.jsonl"),
        HECATE_LLM_DEMOTION_GATES=str(result / "unused-gates.json"),
    )
    metadata = {
        "model": model,
        "threshold": 0.8,
        "think": False,
        "num_ctx": 16384,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "gate_stamp_requested": False,
    }
    print(f"Evaluation artifacts: {result}", flush=True)
    command = [
        sys.executable,
        "-m",
        "hecate_agent.cli",
        "eval",
        "--tier",
        "simple",
        "--fail-under",
        "0.8",
        "--output",
        "json",
    ]
    (result / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with (result / "report.json").open("w") as out, (result / "stderr.log").open("w") as err:
        completed = subprocess.run(command, cwd=result, env=env, stdout=out, stderr=err, check=False)
    metadata.update(finished_at=datetime.now(timezone.utc).isoformat(), exit_code=completed.returncode)
    (result / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    try:
        report = json.loads((result / "report.json").read_text())
        print(json.dumps({key: report[key] for key in ("model", "passed", "total", "score")}))
    except (ValueError, KeyError, TypeError):
        print("No complete report; inspect report.json and stderr.log.", file=sys.stderr)
        return completed.returncode or 1
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen3.6:35b-a3b-q4_K_M")
    parser.add_argument("--output-root", type=Path, help="Parent directory for private run folders")
    args = parser.parse_args()
    return run_evaluation(args.model, args.output_root)


if __name__ == "__main__":
    raise SystemExit(main())
