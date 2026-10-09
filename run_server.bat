@echo off
setlocal
title Mobile Security Agent Server
color 0A

set "PROJECT_DIR=%~dp0"
set "BACKEND_DIR=%PROJECT_DIR%backend"
set "VENV_PYTHON=%PROJECT_DIR%venv\Scripts\python.exe"
set "PORT=8001"

echo ==================================================================
echo         MOBILE SECURITY AGENT - BACKEND SERVER (Port %PORT%)
echo ==================================================================
echo.

if not exist "%VENV_PYTHON%" (
    color 0C
    echo [ERROR] Virtual environment python not found at:
    echo         %VENV_PYTHON%
    echo.
    echo Please create the virtual environment: python -m venv venv
    echo.
    pause
    exit /b 1
)

cd /d "%BACKEND_DIR%"
echo [*] Starting FastAPI ASGI server on http://localhost:%PORT%/ ...
echo [*] RAG engine will initialize on startup (2,075 docs, 34 graph edges).
echo [*] Press Ctrl+C to stop the server at any time.
echo.
"%VENV_PYTHON%" -m uvicorn main:app --host 0.0.0.0 --port %PORT%

echo.
echo ==================================================================
echo [STOPPED] FastAPI Server has terminated.
echo Window will remain open so you can view any tracebacks or logs.
echo ==================================================================
echo.
pause
