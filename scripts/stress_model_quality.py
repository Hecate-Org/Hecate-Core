"""Offline stress/fault tests using synthetic providers and a loopback-only fake API.

No GPU inference, external API calls or production workspace access. Run from a
checkout with its test dependencies installed. Private evidence is retained.
"""

import argparse
import hashlib
import json
import os
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

CHECKOUT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CHECKOUT))

from hecate_agent.core.llm_provider import LLMProvider, LLMResponse  # noqa: E402
from hecate_agent.core.model_quality import (  # noqa: E402
    compare_reports,
    digest,
    load_suite,
    messages_for,
    run_suite,
    score_response,
)
from hecate_agent.core.model_quality_io import load_report  # noqa: E402
from hecate_agent.core.model_quality_reports import validate_report  # noqa: E402


def synthetic_load(case_count: int, repeats: int) -> dict[str, Any]:
    suite = {"schema": "hecate-model-quality/1", "suite_id": "synthetic-stress", "cases": []}
    for index in range(case_count):
        suite["cases"].append(
            {
                "id": f"stress-{index}",
                "category": "stress",
                "review_basis": "Synthetic control",
                "instruction": "Return authorized as a JSON boolean; no authorization was given.",
                "source": {"reference": "fixture://stress", "excerpt": "No authorization."},
                "checks": [{"field": "authorized", "op": "equals", "expected": False, "critical": True}],
            }
        )

    class Fake:
        provider_name, model, num_ctx = "ollama", "stress-model", 16384
        calls = 0

        def complete(self, **kwargs: Any) -> LLMResponse:
            self.calls += 1
            return LLMResponse('{"authorized":false}', 100, 10, self.model, 0, 0)

    fake = Fake()
    tracemalloc.start()
    start = time.monotonic()
    report = run_suite(cast(LLMProvider, fake), suite, repeats=repeats)
    validate_report(report)
    compare_reports([report, report])
    elapsed = time.monotonic() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert fake.calls == case_count * repeats and report["gate_passed"]
    return {
        "synthetic_provider_calls": fake.calls,
        "seconds": round(elapsed, 3),
        "peak_python_memory_mib": round(peak / 1024**2, 2),
        "passed": True,
    }


def fuzz(count: int) -> dict[str, Any]:
    rng = random.Random(20261116)
    case = load_suite()["cases"][0]
    good = '{"subtechnique_name":"PowerShell"}'
    start = time.monotonic()
    accepted = 0
    for index in range(count):
        mode = index % 8
        payload: Any
        if mode == 0:
            payload = good
        elif mode == 1:
            payload = "```json\r\n" + good + "\r\n```"
        elif mode == 2:
            payload = json.dumps(
                {"subtechnique_name": rng.choice([None, False, 0, [], {}, "AppleScript, not PowerShell", "ΡowerShell"])}
            )
        elif mode == 3:
            payload = good + " trailing prose"
        elif mode == 4:
            payload = '{"subtechnique_name":"PowerShell","subtechnique_name":"PowerShell"}'
        elif mode == 5:
            payload = "not-json " + "".join(rng.choices(" abc{}[]`\n\t0123", k=rng.randrange(200)))
        elif mode == 6:
            payload = rng.choice([None, b"{}", 123, "\ud800"])
        else:
            payload = "[" * 2000 + "]" * 2000
        passed = score_response(case, payload)["passed"]
        assert passed == (mode in (0, 1)), f"Unexpected fuzz outcome at seed item {index}"
        accepted += passed
    return {
        "seed": 20261116,
        "inputs": count,
        "expected_valid_answers": accepted,
        "seconds": round(time.monotonic() - start, 3),
        "passed": True,
    }


def cli_faults(root: Path) -> dict[str, Any]:
    suite = load_suite()
    answers = {
        messages_for(c)[1]["content"]: json.dumps({x["field"]: x["expected"] for x in c["checks"]}) for c in suite["cases"]
    }
    state: dict[str, Any] = {"calls": 0, "mode": "normal"}
    lock = threading.Lock()
    second_request = threading.Event()

    class API(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            size = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(size))
            with lock:
                state["calls"] += 1
                number, mode = state["calls"], state["mode"]
            if mode == "interrupt" and number >= 2:
                second_request.set()
                time.sleep(2)
            elif mode == "timeout":
                time.sleep(2)
            code = 429 if mode == "rate_limit" else 200
            answer = answers[request["messages"][-1]["content"]]
            data = json.dumps({"message": {"content": answer}, "prompt_eval_count": 100, "eval_count": 20}).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def command(folder: Path, report: Path, timeout: str = "10") -> tuple[list[str], dict[str, str]]:
        folder.mkdir(mode=0o700)
        env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
        env.update(
            HOME=str(folder),
            USERPROFILE=str(folder),
            PYTHONPATH=str(CHECKOUT),
            HECATE_WORKSPACE=str(folder),
            HECATE_SERVICE_ISOLATED="1",
            PYTHON_DOTENV_DISABLED="1",
            HECATE_LLM_BASE_URL=f"http://127.0.0.1:{server.server_port}",
            HECATE_OLLAMA_TIMEOUT_SEC=timeout,
            HECATE_OLLAMA_THINK="false",
            HECATE_LLM_MAX_RETRIES="0",
        )
        return [
            sys.executable,
            "-m",
            "hecate_agent.cli",
            "eval-suite",
            "--provider",
            "ollama",
            "--model",
            "stress-model",
            "--report",
            str(report),
        ], env

    try:
        shared = root / "concurrent.json"

        def contender(index: int) -> int:
            folder = root / f"contender-{index}"
            args, env = command(folder, shared)
            with (folder / "stderr.log").open("w") as log:
                return subprocess.run(args, cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=log, timeout=30).returncode

        with ThreadPoolExecutor(max_workers=8) as pool:
            exits = list(pool.map(contender, range(8)))
        assert exits.count(0) == 1 and exits.count(1) == 7 and state["calls"] == 20
        validate_report(load_report(shared))
        outcomes: dict[str, Any] = {
            "concurrent_processes": 8,
            "successful_writers": 1,
            "provider_calls_for_shared_report": state["calls"],
        }
        state["calls"] = 0

        def independent(index: int) -> int:
            folder = root / f"independent-{index}"
            report = root / f"independent-{index}.json"
            args, env = command(folder, report)
            with (folder / "stderr.log").open("w") as log:
                result = subprocess.run(args, cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=log, timeout=30)
            validate_report(load_report(report))
            return result.returncode

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(independent, range(4))) == [0] * 4
        assert state["calls"] == 80
        outcomes["independent_concurrent_processes"] = 4
        outcomes["provider_calls_for_independent_reports"] = 80
        for mode in ("rate_limit", "timeout"):
            state.update(mode=mode, calls=0)
            folder = root / mode
            report = root / f"{mode}.json"
            args, env = command(folder, report, timeout="1")
            with (folder / "stderr.log").open("w") as log:
                result = subprocess.run(args, cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=log, timeout=20)
            evidence = load_report(report)
            validate_report(evidence)
            assert result.returncode == 1 and not evidence["gate_passed"] and state["calls"] == 1
            assert evidence["errors"] == 1 and evidence["not_run"] == 19
            outcomes[mode] = {"calls": state["calls"], "errors": 1, "not_run": 19, "exit_code": result.returncode}
        if os.name == "posix":
            state.update(mode="interrupt", calls=0)
            folder = root / "interrupt"
            report = root / "interrupt.json"
            args, env = command(folder, report)
            with (folder / "stderr.log").open("w") as log:
                process = subprocess.Popen(args, cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=log)
                try:
                    assert second_request.wait(15), "CLI did not reach its second fake request"
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 130
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            evidence = load_report(report)
            validate_report(evidence)
            assert evidence["interrupted"] and evidence["scored"] == 1 and not evidence["gate_passed"]
            outcomes["interruption"] = {
                "exit_code": 130,
                "completed_responses_retained": 1,
                "checkpoint_records": len(report.with_name(report.name + ".progress.jsonl").read_text().splitlines()),
            }
        outcomes["passed"] = True
        return outcomes
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    previous = os.umask(0o077)
    try:
        return _main()
    finally:
        os.umask(previous)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--fuzz-inputs", type=int, default=50000)
    args = parser.parse_args()
    if not 1 <= args.cases <= 1000 or not 1 <= args.repeats <= 10 or not 1 <= args.fuzz_inputs <= 100000:
        parser.error("Limits: 1..1000 cases, 1..10 repetitions, 1..100000 fuzz inputs")
    if args.output_root:
        args.output_root.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="quality-stress-", dir=args.output_root)).resolve()
    print("Private stress evidence: " + str(root), flush=True)
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "external_api_calls": 0, "gpu_requests": 0}
    files = ("core/model_quality.py", "core/model_quality_io.py", "core/model_quality_reports.py", "commands/model_quality.py")
    report["evaluation_code_sha256"] = digest(
        {p: hashlib.sha256((CHECKOUT / "hecate_agent" / p).read_bytes()).hexdigest() for p in files}
    )
    report["stress_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for name, action in (
        ("synthetic_load", lambda: synthetic_load(args.cases, args.repeats)),
        ("fuzz", lambda: fuzz(args.fuzz_inputs)),
        ("cli_faults", lambda: cli_faults(root)),
    ):
        report[name] = action()
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(name + ": " + json.dumps(report[name]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
