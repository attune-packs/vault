#!/usr/bin/env python3
"""Attune action entry point. All behavior is selected from the action ref."""

import json
import sys

import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.runtime import PackError, dispatch  # noqa: E402


def run(operation: str) -> None:
    try:
        params = json.loads(sys.stdin.read() or "{}")
        if not isinstance(params, dict):
            raise PackError("invalid_input")
        result = dispatch(operation, params)
        json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
    except PackError as exc:
        # Error codes are fixed strings and never contain Vault/secret material.
        json.dump({"ok": False, "error": exc.code}, sys.stdout)
        sys.stdout.write("\n")
        raise SystemExit(1)
    except Exception:
        json.dump({"ok": False, "error": "operation_failed"}, sys.stdout)
        sys.stdout.write("\n")
        raise SystemExit(1)


if __name__ == "__main__":
    json.dump({"ok": False, "error": "direct_entry_denied"}, sys.stdout)
    sys.stdout.write("\n")
    raise SystemExit(1)
