@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title Mobile Security Agent - Quick Stop
color 0C

set "PORT=8001"
set "OLLAMA_MODEL=qwen2.5-coder:1.5b"

echo ==========================================================
echo        MOBILE SECURITY AGENT - QUICK STOP
echo ==========================================================
echo.

:: Step 1: Clear LLM cache
echo [*] Clearing LLM cache...
powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri 'http://localhost:%PORT%/api/llm/clear-cache' -Method POST -TimeoutSec 5; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [OK]   LLM cache cleared.
) else (
    echo [--]   Server not responding. Skipped.
)

:: Step 2: Stop server
echo [*] Checking for running server process on port %PORT%...
set "KILLED=0"
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    echo [*]   Terminating server process PID %%a...
    taskkill /f /t /pid %%a >nul 2>&1
    set "KILLED=1"
)

if "!KILLED!"=="1" (
    echo [OK]   Server stopped.
) else (
    echo [--]   Server was not running.
)

:: Step 3: Unload Ollama model
echo [*] Unloading Ollama model from GPU/RAM...
ollama stop %OLLAMA_MODEL% >nul 2>&1
echo [OK]   Model unloaded.

echo.
echo ==========================================================
echo             ALL SERVICES STOPPED
echo ==========================================================
echo.
echo   All services stopped successfully.
echo   Press any key to close this window...
pause >nul
exit /b

