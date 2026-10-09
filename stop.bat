@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title Mobile Security Agent - Shutdown
mode con: cols=72 lines=32
color 0C

set "ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"
set "BACKEND_PORT=8001"
set "OLLAMA_MODEL=qwen2.5-coder:1.5b"

echo.
echo   ________________________________________________________
echo  ^|                                                        ^|
echo  ^|        MOBILE SECURITY AGENT - SHUTDOWN                ^|
echo  ^|________________________________________________________^|
echo.

:: Clear LLM cache before stopping (prevent stale cache on next start)
echo   ----------------------------------------------------------
color 0E
echo     [STEP 0]  CLEAR LLM CACHE
color 0F
echo   ----------------------------------------------------------
powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri 'http://localhost:%BACKEND_PORT%/api/llm/clear-cache' -Method POST -TimeoutSec 5; Write-Host $r.message; exit 0 } catch { exit 1 }" 2>nul | findstr /C:"Successfully" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   LLM cache cleared.
) else (
    echo     [--]   Server not responding. Cache clear skipped.
)
color 0F
echo.

:: Stop Backend Server
echo   ----------------------------------------------------------
color 0E
echo     [STEP 1]  BACKEND SERVER (Port %BACKEND_PORT%)
color 0F
echo   ----------------------------------------------------------
set "KILLED=0"
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":%BACKEND_PORT% " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F /T >nul 2>&1
    set "KILLED=1"
)
if "!KILLED!"=="1" (
    color 0A
    echo     [OK]   Server stopped successfully.
) else (
    echo     [--]   Server was not running.
)
color 0F
echo.

:: Stop Frida Server
echo   ----------------------------------------------------------
color 0E
echo     [STEP 2]  FRIDA INSTRUMENTATION
color 0F
echo   ----------------------------------------------------------
if exist "%ADB%" (
    "%ADB%" shell "pkill frida-server" >nul 2>&1
    color 0A
    echo     [OK]   Frida server stopped on device.
) else (
    echo     [--]   ADB not found. Skipped.
)
color 0F
echo.

:: Stop Emulator
echo   ----------------------------------------------------------
color 0E
echo     [STEP 3]  ANDROID EMULATOR
color 0F
echo   ----------------------------------------------------------
if exist "%ADB%" (
    "%ADB%" devices 2>nul | findstr /C:"emulator-" >nul 2>&1
    if !errorlevel!==0 (
        "%ADB%" emu kill >nul 2>&1
        timeout /t 2 /nobreak >nul 2>&1
        color 0A
        echo     [OK]   Emulator shutdown initiated.
    ) else (
        echo     [--]   No emulator was running.
    )
) else (
    echo     [--]   ADB not found. Skipped.
)
color 0F
echo.

:: Stop Ollama model (unload from RAM)
echo   ----------------------------------------------------------
color 0E
echo     [STEP 4]  OLLAMA MODEL (%OLLAMA_MODEL%)
color 0F
echo   ----------------------------------------------------------
ollama stop %OLLAMA_MODEL% >nul 2>&1
color 0A
echo     [OK]   Model unloaded from GPU/RAM.
color 0F
echo.

color 0A
echo   ========================================================
echo   ^|                                                      ^|
echo   ^|             ALL SERVICES STOPPED                      ^|
echo   ^|                                                      ^|
echo   ========================================================
echo.
color 0F
echo   Press any key to exit...
pause >nul
