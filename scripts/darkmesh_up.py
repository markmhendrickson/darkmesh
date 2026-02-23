import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = REPO_ROOT / ".darkmesh"


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (REPO_ROOT / candidate).resolve()


def venv_python(venv_path: str) -> str:
    venv = resolve_path(venv_path)
    if os.name == "nt":
        return str(venv / "Scripts" / "python.exe")
    return str(venv / "bin" / "python")


def load_config(path: str) -> Dict:
    config_path = resolve_path(path)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def pid_path(name: str) -> Path:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR / f"{name}.pid"


def log_path(name: str) -> Path:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR / f"{name}.log"


def is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_pid(name: str) -> Optional[int]:
    path = pid_path(name)
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def write_pid(name: str, pid: int) -> None:
    pid_path(name).write_text(str(pid), encoding="utf-8")


def read_tail(path: Path, lines: int = 25) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(content[-lines:])


def spawn(name: str, args: List[str]) -> bool:
    existing = read_pid(name)
    if existing and is_running(existing):
        print(f"{name} already running (pid {existing})")
        return True

    log_file = log_path(name)
    with open(log_file, "ab") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=log, cwd=str(REPO_ROOT))
    write_pid(name, proc.pid)

    # Detect immediate crashes so follow-up commands do not fail mysteriously.
    time.sleep(0.6)
    if not is_running(proc.pid):
        print(f"Failed to start {name}. See {log_file} for details.")
        tail = read_tail(log_file)
        if tail:
            print("--- recent log ---")
            print(tail)
        return False

    print(f"Started {name} (pid {proc.pid})")
    return True


def start_node(py: str, config_path: str) -> bool:
    config_file = resolve_path(config_path)
    config = load_config(str(config_file))
    port = int(config.get("port", 8001))
    node_id = config.get("node_id", "node")

    node_ok = spawn(
        f"darkmesh_node_{node_id}",
        [py, str(REPO_ROOT / "scripts" / "run_darkmesh.py"), "--config", str(config_file), "--port", str(port)],
    )

    listener_ok = spawn(
        f"darkmesh_listener_{node_id}",
        [py, str(REPO_ROOT / "scripts" / "darkmesh_listener.py"), "--config", str(config_file)],
    )

    return node_ok and listener_ok


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["demo", "local", "join"], default="demo")
    parser.add_argument("--config")
    parser.add_argument("--venv", default=".venv")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--relay-key", default=os.environ.get("DARKMESH_RELAY_KEY", ""))
    args = parser.parse_args()

    py = venv_python(args.venv)
    if not os.path.exists(py):
        print("Virtualenv not found. Run: python3 scripts/darkmesh_setup.py")
        sys.exit(1)

    if args.mode in {"demo", "local"}:
        if not args.relay_key.strip():
            print("--relay-key is required for mode demo/local")
            sys.exit(1)
        relay_ok = spawn(
            "darkmesh_relay",
            [
                py,
                str(REPO_ROOT / "scripts" / "run_darkmesh_relay.py"),
                "--port",
                str(args.relay_port),
                "--relay-key",
                args.relay_key,
            ],
        )
        if not relay_ok:
            sys.exit(1)

    if args.mode == "demo":
        ok_a = start_node(py, "config/node_a.json")
        ok_b = start_node(py, "config/node_b.json")
        if not (ok_a and ok_b):
            sys.exit(1)
        return

    if args.mode in {"local", "join"}:
        if not args.config:
            print("--config is required for mode local/join")
            sys.exit(1)
        ok = start_node(py, args.config)
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
