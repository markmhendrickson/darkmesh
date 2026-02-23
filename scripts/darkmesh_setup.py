import argparse
import os
import subprocess
import sys
import venv


def venv_python(venv_path: str) -> str:
    if os.name == "nt":
        return os.path.join(venv_path, "Scripts", "python.exe")
    return os.path.join(venv_path, "bin", "python")


def ensure_venv(path: str) -> None:
    if os.path.exists(path) and os.path.isdir(path):
        return
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", default=".venv")
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--upgrade-pip", action="store_true")
    args = parser.parse_args()

    ensure_venv(args.venv)
    py = venv_python(args.venv)

    if args.upgrade_pip:
        subprocess.check_call([py, "-m", "pip", "install", "--upgrade", "pip"])

    if not os.path.exists(args.requirements):
        print(f"requirements file not found: {args.requirements}")
        sys.exit(1)

    subprocess.check_call([py, "-m", "pip", "install", "-r", args.requirements])

    os.makedirs(".darkmesh", exist_ok=True)
    print("Darkmesh environment ready.")


if __name__ == "__main__":
    main()
