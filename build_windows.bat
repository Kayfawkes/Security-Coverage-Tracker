@echo off
py -m venv .venv
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pyinstaller --noconfirm --onefile --name SecurityCoverageTracker --add-data "app\static;app\static" run.py
copy dist\SecurityCoverageTracker.exe .
echo Build complete: SecurityCoverageTracker.exe
pause
