@echo off
REM File: launch_av_with_terminal.bat
REM Purpose: Launch AV Flutter app + Ollama backend terminal on Windows and close both on AV exit

echo 🔒 Launching Antivirus Engine and Ollama Backend...

REM Launch Ollama backend in new terminal
start "Ollama Backend" cmd /k python backend/setup_script.py

REM Launch Flutter antivirus desktop app and wait for it to close
start /wait "Antivirus App" "build\windows\x64\runner\Release\nv_engine.exe"

REM After AV app exits, kill Ollama backend terminal
taskkill /FI "WINDOWTITLE eq Ollama Backend*" /T /F

echo ✅ Antivirus session ended. All processes closed.