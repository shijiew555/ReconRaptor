#!/usr/bin/env python3
from __future__ import annotations

"""Executable entrypoint for ReconRaptor.

This mirrors the prototype's behavior by delegating to the package CLI.
"""

from .cli import main as cli_main


if __name__ == "__main__":
    raise SystemExit(cli_main())



