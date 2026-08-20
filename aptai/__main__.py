"""``python3 -m aptai`` entry point."""

from __future__ import annotations

import sys

from aptai.cli import main

if __name__ == "__main__":
    sys.exit(main())
