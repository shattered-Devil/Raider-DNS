$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python --version
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" 2>$null
if ($LASTEXITCODE -ne 0) { throw "Python 3.11 or newer is required." }
python -c "import PySide6" 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Could not install PySide6. Check your internet connection and Python/pip installation." }
}
python .\main.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
