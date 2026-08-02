#!/usr/bin/env bash
# setup.sh - one-time setup for Mac/Linux. Run this once, then use ./mnemosyne.sh
# Creates a private Python environment in this folder (.venv) and installs what Mnemosyne needs.
# Safe to re-run if something goes wrong partway through.
set -e
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Mnemosyne setup starting..."

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY="$candidate"
        break
    fi
done
if [ -z "$PY" ]; then
    echo ""
    echo "Could not find Python on this computer."
    echo "Install Python 3.11 or newer (macOS: 'brew install python3', or python.org/downloads),"
    echo "then run this script again."
    exit 1
fi
echo "Found Python: $($PY --version)"

echo "Creating a private environment in .venv (this is normal, only takes a few seconds)..."
"$PY" -m venv "$here/.venv"

echo "Installing what Mnemosyne needs (this can take a minute or two, it's downloading things)..."
"$here/.venv/bin/python" -m pip install -q -r "$here/requirements.txt"

echo ""
echo "Done! Mnemosyne is set up."
echo ""
echo "Try it:"
echo "  ./mnemosyne.sh status"
echo ""
echo "The first real query or ingest will download a small local AI model (~130MB, one time,"
echo "needs internet); after that everything runs fully offline."
echo ""
echo "Want Claude to use this automatically in conversation? Copy the 'skill' folder into:"
echo "  ~/.claude/skills/mnemosyne/"
echo "(see README.md for the full walkthrough)"
