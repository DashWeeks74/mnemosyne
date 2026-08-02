#!/usr/bin/env bash
# mnemosyne.sh - Mac/Linux/Git-Bash launcher. Calls the venv's own python directly (not the
# .cmd file, which Windows-only cmd.exe association layers can mis-parse from a POSIX shell).
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "$here/.venv/bin/python" ]; then
    PY="$here/.venv/bin/python"          # Mac/Linux venv layout
elif [ -x "$here/.venv/Scripts/python.exe" ]; then
    PY="$here/.venv/Scripts/python.exe"  # Windows venv layout, run from Git Bash
else
    echo "mnemosyne: no venv found at $here/.venv - run setup.sh (or setup.ps1 on Windows) first." >&2
    exit 1
fi
"$PY" "$here/mnemosyne.py" "$@"
