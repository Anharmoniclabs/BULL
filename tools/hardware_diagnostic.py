#!/usr/bin/env python3
"""Compatibility entrypoint for the packaged diagnostic; never grants approval."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from bulldog.hardware_approval.diagnostic import main
if __name__ == '__main__':
    main()
