"""Logging configuration.

Console output goes to stderr, which systemd captures into the journal; a
rotating copy is kept under ``general.log_dir`` so that the notification can
point a human at a file that survives ``journalctl --vacuum``.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys

CONSOLE_FORMAT = "%(levelname)s %(message)s"
FILE_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(log_dir: str = "", level: str = "INFO", *, quiet: bool = False,
                  verbose: bool = False) -> str:
    """Configure the root logger and return the log file path (or "")."""
    if verbose:
        level = "DEBUG"
    numeric = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.ERROR if quiet else numeric)
    console.setFormatter(logging.Formatter(CONSOLE_FORMAT))
    root.addHandler(console)

    if not log_dir:
        return ""
    try:
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        path = os.path.join(log_dir, "aptai.log")
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=8 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG if verbose else numeric)
        file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
        root.addHandler(file_handler)
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
        return path
    except OSError as exc:
        logging.getLogger("aptai").warning("cannot write to %s: %s", log_dir, exc)
        return ""
