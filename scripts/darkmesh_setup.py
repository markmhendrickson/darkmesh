"""Darkmesh setup helper: provisions the Python venv, installs deps, and
optionally auto-provisions this node's Neotoma ``agent_grant``.

The optional ``--auto-provision-grant`` flag is intended for CI / fleet
automation runs where ``DARKMESH_AAUTH_PRIVATE_JWK*`` and
``DARKMESH_AAUTH_SUB`` are already exported (via
``scripts/aauth_env.sh``) and ``NEOTOMA_TOKEN`` is set. It calls
``scripts/neotoma_grants_provision.py --auto`` in the venv so the node's
identity is bound to an ``agent_grant`` before first boot. Without the
flag the script just prints the same hint that ``aauth_env.sh`` prints,
to keep interactive setup non-surprising.
"""

import argparse
import os
import subprocess
import sys
import venv
from typing import List


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def venv_python(venv_path: str) -> str:
    if os.name == "nt":
        return os.path.join(venv_path, "Scripts", "python.exe")
    return os.path.join(venv_path, "bin", "python")


def ensure_venv(path: str) -> None:
    if os.path.exists(path) and os.path.isdir(path):
        return
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(path)


def _provision_grant(py: str, neotoma_url: str | None) -> int:
    """Call scripts/neotoma_grants_provision.py --auto using the venv python.

    Returns the script's exit code so the caller can decide whether to
    fail the overall setup. We deliberately do not crash on a non-zero
    exit because grant provisioning can be done out-of-band; the warning
    is enough.
    """
    script = os.path.join(REPO_ROOT, "scripts", "neotoma_grants_provision.py")
    cmd: List[str] = [py, script, "--auto"]
    if neotoma_url:
        cmd += ["--neotoma-url", neotoma_url]
    if not os.environ.get("NEOTOMA_TOKEN"):
        print(
            "WARNING: --auto-provision-grant requested but NEOTOMA_TOKEN is "
            "not set; skipping. Export the operator's Neotoma user token, "
            "then run scripts/neotoma_grants_provision.py --auto manually."
        )
        return 0
    return subprocess.call(cmd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", default=".venv")
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--upgrade-pip", action="store_true")
    parser.add_argument(
        "--auto-provision-grant",
        action="store_true",
        help=(
            "After installing deps, run scripts/neotoma_grants_provision.py "
            "--auto to create/update this node's agent_grant in Neotoma. "
            "Requires NEOTOMA_TOKEN and DARKMESH_AAUTH_* env vars."
        ),
    )
    parser.add_argument(
        "--neotoma-url",
        default=os.environ.get("NEOTOMA_URL"),
        help="Override Neotoma base URL passed to the provisioning script",
    )
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

    if args.auto_provision_grant:
        rc = _provision_grant(py, args.neotoma_url)
        if rc != 0:
            print(
                "WARNING: grant provisioning exited non-zero. The node will "
                "still start, but Neotoma writes/reads under the AAuth "
                "identity will be denied until the grant is in place."
            )
    else:
        print(
            "\nNext step (one-time per node, after `source scripts/aauth_env.sh <node>`):\n"
            "  python scripts/neotoma_grants_provision.py --dry-run    # preview\n"
            "  python scripts/neotoma_grants_provision.py --auto       # create or update\n"
            "See docs/neotoma_integration.md for the full grants playbook."
        )


if __name__ == "__main__":
    main()
