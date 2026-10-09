@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title Mobile Security Agent - Quick Start
color 0A

set "PROJECT_ROOT=%~dp0"
set "BACKEND_DIR=%PROJECT_ROOT%backend"
set "VENV_PYTHON=%PROJECT_ROOT%venv\Scripts\python.exe"
set "PORT=8001"
set "OLLAMA_MODEL=qwen2.5-coder:1.5b"

echo ==========================================================
echo        MOBILE SECURITY AGENT - QUICK START
echo ==========================================================
echo.

:: Check Python venv
if not exist "%VENV_PYTHON%" (
    color 0C
    echo [FATAL] Python venv not found at: %VENV_PYTHON%
    echo         Run: python -m venv venv
    echo.
    echo Press any key to exit...
    pause
    exit /b 1
)

:: Step 1: Ensure Ollama is running
echo [*] Checking Ollama LLM service...
where ollama >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARN] Ollama not found on PATH. LLM features will be disabled.
    color 0A
    goto START_SERVER
)

powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://localhost:11434/api/tags' -UseBasicParsing -TimeoutSec 3; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [OK]   Ollama service is already running.
) else (
    echo [*]   Starting Ollama service - GPU auto-detect...
    start "Ollama LLM Service" "%PROJECT_ROOT%run_ollama.bat"
    timeout /t 4 /nobreak >nul 2>&1
    echo [OK]   Ollama started.
)

:: Step 2: Warm up model
echo [*] Warming up %OLLAMA_MODEL%...
powershell -NoProfile -Command "try { $body = @{model='%OLLAMA_MODEL%';messages=@(@{role='user';content='hi'});stream=$false;keep_alive='30m';options=@{num_predict=3;num_gpu=-1}} | ConvertTo-Json -Depth 3; $null = Invoke-RestMethod -Uri 'http://localhost:11434/api/chat' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 120; Write-Host 'OK'; exit 0 } catch { exit 1 }" 2>nul | findstr /C:"OK" >nul 2>&1
if not errorlevel 1 (
    echo [OK]   Model loaded and cached - 30 min keep-alive.
) else (
    color 0E
    echo [WARN] Model warm-up timed out. Will load on first scan.
    color 0A
)

:START_SERVER
:: Step 3: Check if server already running
echo.
echo [*] Checking if port %PORT% is already in use...
netstat -ano 2>nul | findstr ":%PORT% " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [OK]   Server is already active and running on port %PORT%.
    echo.
    powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri 'http://localhost:%PORT%/api/llm/clear-cache' -Method POST -TimeoutSec 5; Write-Host $r.message; exit 0 } catch { exit 1 }" 2>nul | findstr /C:"Successfully" >nul 2>&1
    if not errorlevel 1 (
        echo [OK]   LLM cache cleared for fresh session.
    )
    echo.
    echo Opening dashboard in browser...
    start "" "http://localhost:%PORT%/"
    goto ACTIVE_LOOP
)

:: Step 4: Start server
echo [*] Starting FastAPI Server on port %PORT%...
start "Mobile Security Agent Server" "%PROJECT_ROOT%run_server.bat"


echo [*] Waiting for server to initialize (loading RAG engine)...
timeout /t 10 /nobreak >nul 2>&1

:: Verify server health
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://localhost:%PORT%/api/health' -UseBasicParsing -TimeoutSec 5; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [OK]   Server healthy on port %PORT%.
    powershell -NoProfile -Command "try { $null = Invoke-RestMethod -Uri 'http://localhost:%PORT%/api/llm/clear-cache' -Method POST -TimeoutSec 5; exit 0 } catch { exit 1 }" >nul 2>&1
    echo [OK]   LLM cache cleared for fresh session.
) else (
    color 0E
    echo [WARN] Server started but still loading. Dashboard may take a moment.
    color 0A
)

echo.
echo Opening dashboard in browser...
start "" "http://localhost:%PORT%/"

:ACTIVE_LOOP
echo.
echo ==========================================================
echo   * SYSTEM IS ACTIVE AND READY *
echo   Dashboard : http://localhost:%PORT%/
echo   Health    : http://localhost:%PORT%/api/health
echo   LLM Model : %OLLAMA_MODEL% via Ollama (GPU)
echo ==========================================================
echo.
echo   Services are running in background windows.
echo   Keep this launcher window open during testing.
echo   To cleanly shut down all services, run stop_agent.bat
echo.
echo   Press any key to refresh status...
pause >nul
echo.
goto ACTIVE_LOOP

