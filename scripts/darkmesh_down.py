import argparse
import os
import signal
import time
from typing import List


def list_pid_files() -> List[str]:
    if not os.path.isdir(".darkmesh"):
        return []
    return [os.path.join(".darkmesh", name) for name in os.listdir(".darkmesh") if name.endswith(".pid")]


def read_pid(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        return int(f.read().strip())


def stop_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    pid_files = list_pid_files()
    if not pid_files:
        print("No running services found.")
        return

    for path in pid_files:
        try:
            pid = read_pid(path)
        except (OSError, ValueError):
            continue
        stop_pid(pid)

    time.sleep(0.5)

    if args.force:
        for path in pid_files:
            try:
                pid = read_pid(path)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    for path in pid_files:
        try:
            os.remove(path)
        except OSError:
            pass

    print("Stopped services.")


if __name__ == "__main__":
    main()
