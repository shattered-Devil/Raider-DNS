@echo off
setlocal
cd /d "%~dp0"
python --version >nul 2>&1
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 or newer and add it to PATH.
  pause
  exit /b 1
)
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if errorlevel 1 (
  echo Python 3.11 or newer is required.
  pause
  exit /b 1
)
python -c "import PySide6" >nul 2>&1
if errorlevel 1 (
  echo Installing the required PySide6 package...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo PySide6 installation failed.
    pause
    exit /b 1
  )
)
python main.py
if errorlevel 1 pause
