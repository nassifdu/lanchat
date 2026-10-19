#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
echo "Done. Run:  .venv/bin/python lanchat.py -p \"your password\""
