@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo AntiSkid environment was not found. Run install.bat first.
  pause
  exit /b 1
)
.venv\Scripts\python.exe antiskid.py
if errorlevel 1 (
  echo.
  echo AntiSkid exited with an error. Review the traceback above.
  pause
)
