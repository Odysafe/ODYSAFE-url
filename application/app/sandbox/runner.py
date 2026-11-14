from __future__ import annotations

import os
import subprocess
import sys

from app.sandbox.network_policy import validate_worker_url


def main() -> int:
    url = os.environ.get("ODYSAFE_SCAN_URL", "")
    if not url:
        print("ODYSAFE_SCAN_URL is required", file=sys.stderr)
        return 2
    try:
        validate_worker_url(url)
    except ValueError as exc:
        print(f"URL rejected: {exc}", file=sys.stderr)
        return 2
    profile = os.environ.get("ODYSAFE_PROFILE", "desktop")
    return subprocess.run([sys.executable, "-m", "app", "scan", url, "--profile", profile],
                          check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
