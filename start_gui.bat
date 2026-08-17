@echo off
cd /d "%~dp0"
echo [*] PwnSolver GUI (Windows)
where python >nul 2>nul
if errorlevel 1 (
  echo python not found in PATH
  pause
  exit /b 1
)
python pwnsolver.py gui
if errorlevel 1 pause
