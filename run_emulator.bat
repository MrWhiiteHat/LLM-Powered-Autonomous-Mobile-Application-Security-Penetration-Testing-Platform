@echo off
setlocal
title Android Emulator - Universal_API_34
color 0D

set "EMULATOR=%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe"
set "ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"

if exist "%USERPROFILE%\.android\avd\Universal_API_34.avd" (
    set "AVD_NAME=Universal_API_34"
) else (
    set "AVD_NAME=Test_Phone"
)

echo ==================================================================
echo         ANDROID EMULATOR (%AVD_NAME%)
echo ==================================================================
echo.

if not exist "%EMULATOR%" (
    color 0C
    echo [ERROR] Android emulator executable not found at:
    echo         %EMULATOR%
    echo.
    pause
    exit /b 1
)

:: Clear stale lock files
if exist "%USERPROFILE%\.android\avd\%AVD_NAME%.avd\*.lock" (
    echo [*] Removing stale lock files...
    del /f /q "%USERPROFILE%\.android\avd\%AVD_NAME%.avd\*.lock" >nul 2>&1
)

echo [*] Launching Android Emulator (%AVD_NAME%) with GPU auto-acceleration...
echo [*] Close the emulator window or press Ctrl+C to stop.
echo.
"%EMULATOR%" -avd %AVD_NAME% -gpu auto -no-audio -no-snapshot-save

echo.
echo ==================================================================
echo [STOPPED] Android Emulator has terminated.
echo Window will remain open for debugging.
echo ==================================================================
echo.
pause
