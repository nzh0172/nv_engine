@echo off
REM ========================================
REM launch_av_with_terminal.bat
REM Usage: launch_av_with_terminal.bat "C:\some\folder\to\scan"
REM ========================================

REM 1) Move into the script’s directory so python can find ai_powered_detector.py
cd /d "%~dp0"

echo.
echo ✅  AI‐Powered Malware Scanner
echo     Scanning target: "%~1"
echo ==================================================

REM 2) Run the detector on the passed‐in path
python backend/ai_powered_detector.py "%~1" --scan-existing

echo.
echo ==================================================
echo ✅  Scan finished. Press any key to close this window.
pause >nul
