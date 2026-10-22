#!/usr/bin/env bash
# mnemosyne.sh - Mac/Linux/Git-Bash launcher. Calls the venv's own python directly (not the
# .cmd file, which Windows-only cmd.exe association layers can mis-parse from a POSIX shell).
# Does not change your current folder, so relative paths you pass resolve against where YOU are.
# Exit codes pass through unchanged; 97 means this launcher found a broken install.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 97
if [ -x "$here/.venv/bin/python" ]; then
    PY="$here/.venv/bin/python"          # Mac/Linux venv layout
elif [ -x "$here/.venv/Scripts/python.exe" ]; then
    PY="$here/.venv/Scripts/python.exe"  # Windows venv layout, run from Git Bash
else
    echo "mnemosyne: no venv found at $here/.venv - run setup.sh (or setup.ps1 on Windows) first." >&2
    exit 97
fi
if [ ! -f "$here/mnemosyne.py" ]; then
    echo "mnemosyne: mnemosyne.py is missing from $here - re-copy the install." >&2
    exit 97
fi
exec "$PY" "$here/mnemosyne.py" "$@"
