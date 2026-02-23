import argparse
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def venv_python(venv_path: str) -> str:
    venv = Path(venv_path)
    if not venv.is_absolute():
        venv = REPO_ROOT / venv
    if os.name == "nt":
        return str(venv / "Scripts" / "python.exe")
    return str(venv / "bin" / "python")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", default=".venv")
    args = parser.parse_args()

    py = venv_python(args.venv)
    if not os.path.exists(py):
        print("Virtualenv not found. Run: python3 scripts/darkmesh_setup.py")
        sys.exit(1)

    subprocess.check_call([py, str(REPO_ROOT / "scripts" / "darkmesh_demo_seed.py")], cwd=str(REPO_ROOT))
    subprocess.check_call([py, str(REPO_ROOT / "scripts" / "darkmesh_demo_warm_intro.py")], cwd=str(REPO_ROOT))


if __name__ == "__main__":
    main()
