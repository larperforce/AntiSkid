@echo off
setlocal
cd /d "%~dp0"
echo ============================================
echo   ANTISKID - DIGITAL FORENSICS INSTALLER
echo ============================================
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher (py) was not found.
  echo Install Python 3.10 or newer and enable "Add Python to PATH".
  pause
  exit /b 1
)
py -3 -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+'"
if errorlevel 1 (
  echo AntiSkid requires Python 3.10 or newer.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto failed
)
.venv\Scripts\python.exe -c "import tkinter; print('Tkinter: OK')"
if errorlevel 1 (
  echo This Python installation does not include Tkinter.
  echo Reinstall Python and include the Tcl/Tk and IDLE feature.
  pause
  exit /b 1
)
echo.
echo Installation completed. No third-party packages or internet access are required.
echo Start AntiSkid with run.bat
pause
exit /b 0
:failed
echo.
echo Installation failed. Check the messages above.
pause
exit /b 1
