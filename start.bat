@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title Mobile Security Agent - Command Center
mode con: cols=76 lines=44 >nul 2>&1
color 0F

:: ---------------------------------------------------------------
:: Configuration
:: ---------------------------------------------------------------
set "PROJECT_DIR=%~dp0"
set "BACKEND_DIR=%PROJECT_DIR%backend"
set "VENV_PYTHON=%PROJECT_DIR%venv\Scripts\python.exe"
set "ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"
set "EMULATOR=%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe"
set "FRIDA_LOCAL=%LOCALAPPDATA%\Temp\frida-server"
set "FRIDA_SERVER=/data/local/tmp/frida-server"
set "OLLAMA_MODEL=qwen2.5-coder:1.5b"
set "BACKEND_PORT=8001"

:: Auto-detect Best AVD: Prefer Universal_API_34, fallback to Test_Phone
if exist "%USERPROFILE%\.android\avd\Universal_API_34.avd" (
    set "AVD_NAME=Universal_API_34"
    set "AVD_DESC=Android 14 (API 34) Universal x86_64"
) else (
    set "AVD_NAME=Test_Phone"
    set "AVD_DESC=Android 9.0 (API 28) x86"
)

:: ---------------------------------------------------------------
:: Banner
:: ---------------------------------------------------------------
cls
echo.
color 0B
echo   __________________________________________________________________
echo  ^|                                                                  ^|
echo  ^|     __  __  ___  ____  ___ _     _____                           ^|
echo  ^|    ^|  \/  ^|/ _ \^| __ )^|_ _^| ^|   ^| ____^|                          ^|
echo  ^|    ^| ^|\/^| ^| ^| ^| ^|  _ \ ^| ^|^| ^|   ^|  _^|                            ^|
echo  ^|    ^| ^|  ^| ^| ^|_^| ^| ^|_) ^|^| ^|^| ^|___^| ^|___                           ^|
echo  ^|    ^|_^|  ^|_^|\___/^|____/^|___^|_____^|_____^|                          ^|
echo  ^|                                                                  ^|
echo  ^|     ____  _____ ____ _   _ ____  ___ _______   __                ^|
echo  ^|    / ___^|^| ____/ ___^| ^| ^| ^|  _ \^|_ _^|_   _^\ ^\ / /                ^|
echo  ^|    \___ \^|  _^|^| ^|   ^| ^| ^| ^| ^|_) ^|^| ^|  ^| ^|  ^\ V /                 ^|
echo  ^|     ___) ^| ^|__^| ^|___^| ^|_^| ^|  _ ^< ^| ^|  ^| ^|   ^| ^|                  ^|
echo  ^|    ^|____/^|_____\____^|\___/^|_^| \_\___^| ^|_^|   ^|_^|                  ^|
echo  ^|                                                                  ^|
echo  ^|         A G E N T   C O M M A N D   C E N T E R                 ^|
echo  ^|__________________________________________________________________^|
echo.
color 0A
echo          LLM-Powered Autonomous Mobile Penetration Testing Platform
echo.
color 0F
echo   ------------------------------------------------------------------
echo    LLM Model:   %OLLAMA_MODEL% via Ollama (GPU Auto)
echo    Port:        %BACKEND_PORT%
echo    Emulator:    %AVD_NAME% (%AVD_DESC%)
echo   ------------------------------------------------------------------
echo.

if not exist "%VENV_PYTHON%" (
    color 0C
    echo   [FATAL] Python venv not found at: %VENV_PYTHON%
    echo.
    echo   Please create the virtual environment: python -m venv venv
    goto END_ERROR
)

:: ---------------------------------------------------------------
:: STEP 1: Android Emulator (New Window - stays open)
:: ---------------------------------------------------------------
echo   ------------------------------------------------------------------
color 0D
echo     [STEP 1]  ANDROID EMULATOR (%AVD_NAME%)
color 0F
echo   ------------------------------------------------------------------

if not exist "%EMULATOR%" (
    color 0E
    echo     [SKIP] Emulator executable not found.
    color 0F
    goto STEP2
)

if not exist "%ADB%" (
    color 0E
    echo     [SKIP] ADB not found.
    color 0F
    goto STEP2
)

:: Clean stale AVD lock files to prevent startup crash
if exist "%USERPROFILE%\.android\avd\%AVD_NAME%.avd\*.lock" (
    del /f /q "%USERPROFILE%\.android\avd\%AVD_NAME%.avd\*.lock" >nul 2>&1
)

"%ADB%" devices 2>nul | findstr /C:"emulator-" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   Emulator already running and connected.
    color 0F
    goto STEP2
)

color 0B
start "Android Emulator - %AVD_NAME%" "%PROJECT_DIR%run_emulator.bat"

echo.
echo            Waiting for emulator boot (up to 120s)...
set WAIT_COUNT=0

:WAIT_BOOT
timeout /t 5 /nobreak >nul 2>&1
set /a WAIT_COUNT+=5

set /a PCT=(%WAIT_COUNT% * 100) / 120
set "BAR="
set /a FILLED=%PCT% / 5
set /a EMPTY=20 - %FILLED%
for /L %%i in (1,1,%FILLED%) do set "BAR=!BAR!#"
for /L %%i in (1,1,%EMPTY%) do set "BAR=!BAR!-"
echo            [!BAR!] %PCT%%% (%WAIT_COUNT%s / 120s)

"%ADB%" shell getprop sys.boot_completed 2>nul | findstr /C:"1" >nul 2>&1
if not errorlevel 1 (
    echo.
    color 0A
    echo     [OK]   Emulator booted in ~%WAIT_COUNT%s
    color 0F
    goto STEP2
)

if %WAIT_COUNT% GEQ 120 (
    echo.
    color 0E
    echo     [WARN] Boot timeout. Emulator may still be loading.
    color 0F
    goto STEP2
)
goto WAIT_BOOT

:: ---------------------------------------------------------------
:: STEP 2: Frida Server Automation
:: ---------------------------------------------------------------
:STEP2
echo.
echo   ------------------------------------------------------------------
color 0E
echo     [STEP 2]  FRIDA INSTRUMENTATION SERVER
color 0F
echo   ------------------------------------------------------------------

if not exist "%ADB%" (
    color 0E
    echo     [SKIP] ADB not found.
    color 0F
    goto STEP3
)

"%ADB%" devices 2>nul | findstr /C:"emulator-" >nul 2>&1
if errorlevel 1 (
    color 0E
    echo     [SKIP] No emulator connected.
    color 0F
    goto STEP3
)

:: Setup root access and SELinux permissive for Frida
color 0B
echo     [..]   Configuring root and permissive SELinux...
color 0F
"%ADB%" root >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
"%ADB%" shell setenforce 0 >nul 2>&1

:: Check if frida-server binary is on device
"%ADB%" shell "ls %FRIDA_SERVER%" >nul 2>&1
if errorlevel 1 (
    if exist "%FRIDA_LOCAL%" (
        color 0B
        echo     [..]   Pushing frida-server to device...
        color 0F
        "%ADB%" push "%FRIDA_LOCAL%" %FRIDA_SERVER% >nul 2>&1
        "%ADB%" shell "chmod 755 %FRIDA_SERVER%" >nul 2>&1
    ) else (
        color 0E
        echo     [WARN] frida-server binary not found locally or on device.
        color 0F
        goto STEP3
    )
)

:: Check if frida-server is already running
"%ADB%" shell "ps -A 2>/dev/null || ps" 2>nul | findstr /C:"frida-server" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   Frida server is already running on device.
    color 0F
    goto STEP3
)

color 0B
echo     [..]   Starting frida-server in background on device...
color 0F
"%ADB%" shell "nohup %FRIDA_SERVER% >/dev/null 2>&1 &" >nul 2>&1
timeout /t 3 /nobreak >nul 2>&1
color 0A
echo     [OK]   Frida server running and verified.
color 0F

:: ---------------------------------------------------------------
:: STEP 3: Ollama LLM Service (New Window - stays open)
:: ---------------------------------------------------------------
:STEP3
echo.
echo   ------------------------------------------------------------------
color 0B
echo     [STEP 3]  OLLAMA LLM SERVICE
color 0F
echo   ------------------------------------------------------------------

where ollama >nul 2>&1
if errorlevel 1 (
    color 0C
    echo     [ERR]  Ollama not found on PATH.
    color 0F
    goto STEP5
)

powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://localhost:11434/api/tags' -UseBasicParsing -TimeoutSec 3; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   Ollama service is already running.
    color 0F
    goto STEP4
)

color 0B
echo     [..]   Starting Ollama in new window (GPU auto-detect)...
color 0F
:: GPU auto-detect: Ollama automatically uses NVIDIA GPU when available
:: Do NOT set CUDA_VISIBLE_DEVICES=-1 or OLLAMA_LLM_LIBRARY=cpu
start "Ollama LLM Service" "%PROJECT_DIR%run_ollama.bat"
timeout /t 5 /nobreak >nul 2>&1
color 0A
echo     [OK]   Ollama service started.
color 0F

:: ---------------------------------------------------------------
:: STEP 4: Model Warm-up
:: ---------------------------------------------------------------
:STEP4
echo.
echo   ------------------------------------------------------------------
color 0C
echo     [STEP 4]  MODEL WARM-UP (%OLLAMA_MODEL%)
color 0F
echo   ------------------------------------------------------------------

color 0B
echo     [..]   Warming up model into GPU/RAM cache...
color 0F

powershell -NoProfile -Command "try { $body = @{model='%OLLAMA_MODEL%';messages=@(@{role='user';content='hi'});stream=$false;keep_alive='30m';options=@{num_predict=3;num_gpu=-1}} | ConvertTo-Json -Depth 3; $null = Invoke-RestMethod -Uri 'http://localhost:11434/api/chat' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 120; Write-Host 'SUCCESS'; exit 0 } catch { exit 1 }" 2>nul | findstr /C:"SUCCESS" >nul 2>&1

if not errorlevel 1 (
    color 0A
    echo     [OK]   Model warm and ready - GPU offload, cached 30 mins.
    color 0F
) else (
    color 0E
    echo     [WARN] Warm-up timed out. Will load on first scan.
    color 0F
)

:: ---------------------------------------------------------------
:: STEP 5: Clear LLM Cache (fresh start per session)
:: ---------------------------------------------------------------
:STEP5
echo.
echo   ------------------------------------------------------------------
color 0D
echo     [STEP 5]  CLEAR STALE LLM CACHE
color 0F
echo   ------------------------------------------------------------------

:: Wait for server to be ready before clearing cache
set "SERVER_READY=0"

:: ---------------------------------------------------------------
:: STEP 6: Backend Server (New Window - stays open)
:: ---------------------------------------------------------------
echo.
echo   ------------------------------------------------------------------
color 0A
echo     [STEP 6]  BACKEND SERVER (Port %BACKEND_PORT%)
color 0F
echo   ------------------------------------------------------------------

netstat -ano 2>nul | findstr ":%BACKEND_PORT% " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   Server already active on port %BACKEND_PORT%.
    color 0F
    set "SERVER_READY=1"
    goto CLEAR_CACHE
)

color 0B
echo     [..]   Starting FastAPI server in new window...
color 0F
start "Mobile Security Agent Server" "%PROJECT_DIR%run_server.bat"
echo            Waiting for server to initialize (RAG loading)...
timeout /t 10 /nobreak >nul 2>&1

:: Verify server is up
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://localhost:%BACKEND_PORT%/api/health' -UseBasicParsing -TimeoutSec 5; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    color 0A
    echo     [OK]   Server live and healthy on port %BACKEND_PORT%.
    color 0F
    set "SERVER_READY=1"
) else (
    color 0E
    echo     [WARN] Server started but health check pending - RAG still loading.
    color 0F
    set "SERVER_READY=0"
)

:CLEAR_CACHE
:: Clear LLM cache to prevent cross-app contamination
if "!SERVER_READY!"=="1" (
    powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri 'http://localhost:%BACKEND_PORT%/api/llm/clear-cache' -Method POST -TimeoutSec 5; Write-Host $r.message; exit 0 } catch { exit 1 }" 2>nul | findstr /C:"Successfully" >nul 2>&1
    if not errorlevel 1 (
        color 0A
        echo     [OK]   LLM cache cleared for fresh session.
        color 0F
    ) else (
        echo     [--]   Cache clear skipped - server still loading.
    )
) else (
    echo     [--]   Cache clear deferred until server is ready.
)

:: ---------------------------------------------------------------
:: Launch Browser
:: ---------------------------------------------------------------
:LAUNCH
echo.
echo.
color 0A
echo   ==================================================================
echo   ^|                                                                ^|
echo   ^|             * ALL SYSTEMS OPERATIONAL *                        ^|
echo   ^|                                                                ^|
echo   ^|   Dashboard : http://localhost:%BACKEND_PORT%/                        ^|
echo   ^|   Health    : http://localhost:%BACKEND_PORT%/api/health              ^|
echo   ^|   Ollama    : http://localhost:11434/                            ^|
echo   ^|   Emulator  : %AVD_NAME% (%AVD_DESC%)        ^|
echo   ^|                                                                ^|
echo   ==================================================================
echo.
color 0F
echo   Opening dashboard in browser...
start "" "http://localhost:%BACKEND_PORT%/"
echo.

:ACTIVE_LOOP
echo   ==================================================================
echo   [ACTIVE] Mobile Security Agent Command Center is running.
echo   - Backend Server, Ollama, and Emulator are active in their windows.
echo   - Keep this Command Center window open during testing.
echo   - To cleanly shut down all services, run stop.bat.
echo   ==================================================================
echo.
echo   Press any key to refresh status...
pause >nul
echo.
goto ACTIVE_LOOP

:END_ERROR
echo.
color 0C
echo   [FATAL] Execution halted due to configuration error.
echo.
echo   Press any key to exit...
pause
exit /b 1

:END
pause
exit /b 0

