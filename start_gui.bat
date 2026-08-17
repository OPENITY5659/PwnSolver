@echo off
rem PwnSolver GUI one-click launcher -- Windows
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [-] python not found in PATH. Install Python 3.10+ and check "Add python.exe to PATH".
  pause
  exit /b 1
)

echo [*] PwnSolver GUI (Windows)
python pwnsolver.py gui
if errorlevel 1 pause
endlocal
