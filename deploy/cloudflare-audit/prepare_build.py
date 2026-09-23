#!/usr/bin/env python3
"""Prepare a local Wrangler build config; never provision, upload, or deploy."""
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent


def prepare(database_id, root=ROOT):
    try:
        parsed = uuid.UUID(database_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("set BULL_D1_DATABASE_ID to the existing D1 database UUID") from exc
    if str(parsed) != database_id or parsed.int == 0:
        raise ValueError("BULL_D1_DATABASE_ID must be a canonical nonzero UUID")
    config = json.loads((root / "wrangler.jsonc").read_text())
    databases = config.get("d1_databases", [])
    if len(databases) != 1 or databases[0].get("binding") != "DB":
        raise ValueError("expected exactly one existing DB binding in the template")
    databases[0]["database_id"] = database_id
    data = json.dumps(config, indent=2) + "\n"
    output = root / "wrangler.build.json"
    try:
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if output.is_symlink() or not output.is_file() or output.read_text() != data:
            raise ValueError("generated config differs; review and remove it before preparing new configuration")
    else:
        with os.fdopen(fd, "w") as stream:
            stream.write(data)
    return output


if __name__ == "__main__":
    try:
        output = prepare(os.environ.get("BULL_D1_DATABASE_ID"))
    except (OSError, ValueError) as exc:
        print("Build configuration refused: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
    print("Prepared " + output.name + "; no upload or deployment performed.")
