@echo off
cd /d "%~dp0"
py -3 -m venv .venv || python -m venv .venv
.venv\Scripts\pip install -q -r requirements.txt
echo Done. Run:  .venv\Scripts\python lanchat.py -p "your password" -c HOST_IP
