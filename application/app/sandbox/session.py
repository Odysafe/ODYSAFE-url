from __future__ import annotations

import os
from pathlib import Path


def interactive_settings(profile: dict, runtime_dir: Path = Path("/run/odysafe")) -> dict:
    """Return capture settings for a bounded Xpra-backed session."""
    timeout = int(os.environ.get("ODYSAFE_INTERACTIVE_TIMEOUT", "300"))
    if not 15 <= timeout <= 28800:
        raise ValueError("ODYSAFE_INTERACTIVE_TIMEOUT must be between 15 and 28800 seconds")
    configured = dict(profile)
    configured.update(headless=False, _remote_headfull=True,
                      _interactive_finish_file=str(runtime_dir / "finish"),
                      _interactive_timeout_sec=timeout)
    return configured
