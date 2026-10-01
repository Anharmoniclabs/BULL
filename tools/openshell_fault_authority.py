#!/usr/bin/env python3
"""Test-only fault authority process. Never use this entrypoint for deployment."""
import argparse
import json
from pathlib import Path
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from bulldog.openshell.authority import OpenShellAuthority
from bulldog.openshell.server import main

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--fault-file', type=Path, required=True)
args, remaining = parser.parse_known_args()
original = OpenShellAuthority.evaluate_request

def faulted(self, **kwargs):
    fault = json.loads(args.fault_file.read_text())
    time.sleep(float(fault.get('delay_ms', 0)) / 1000)
    if fault.get('disconnect'):
        raise ConnectionResetError('injected test reset')
    return original(self, **kwargs)

OpenShellAuthority.evaluate_request = faulted
raise SystemExit(main(remaining))
