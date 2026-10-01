#!/usr/bin/env python3
"""Check BULL's local MCP gateway without cloud credentials on a Linux host."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.run_codespace_agent_gateway import main

if __name__ == "__main__":
    raise SystemExit(main(default_local=True))
