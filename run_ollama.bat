@echo off
setlocal
title Ollama LLM Service
color 0B

echo ==================================================================
echo         OLLAMA LLM SERVICE (GPU Auto-Detect)
echo ==================================================================
echo.

where ollama >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] Ollama command not found on PATH.
    echo Please install Ollama or ensure it is added to system PATH.
    echo.
    pause
    exit /b 1
)

echo [*] Starting Ollama service...
echo [*] Models will use NVIDIA GPU automatically when available.
echo.
ollama serve

echo.
echo ==================================================================
echo [STOPPED] Ollama service has terminated.
echo Window will remain open for debugging.
echo ==================================================================
echo.
pause
