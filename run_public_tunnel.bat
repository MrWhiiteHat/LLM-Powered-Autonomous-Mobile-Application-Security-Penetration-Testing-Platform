@echo off
setlocal
title Mobile Security Agent - Public Internet Access Tunnel
color 0B

echo ==================================================================
echo   MOBILE SECURITY AGENT (MSA) - PUBLIC INTERNET TUNNEL
echo   Secure Global Access via Cloudflare Edge Network (HTTP/2)
echo ==================================================================
echo.

set "CLOUDFLARED_BIN=C:\Users\MrWhiteHat\cloudflared.exe"
if not exist "%CLOUDFLARED_BIN%" (
    where cloudflared >nul 2>&1
    if %errorlevel% equ 0 (
        set "CLOUDFLARED_BIN=cloudflared"
    ) else (
        color 0C
        echo [ERROR] cloudflared.exe was not found at %CLOUDFLARED_BIN%
        echo Please ensure Cloudflared is installed or placed in the PATH.
        echo.
        pause
        exit /b 1
    )
)

echo [*] Cloudflared utility located: %CLOUDFLARED_BIN%
echo [*] Forwarding target: http://127.0.0.1:8000
echo [*] Protocol: HTTP/2 over TLS (Port 443)
echo.
echo [*] Establishing secure public HTTPS tunnel...
echo [*] Once connected, look for the 'https://*.trycloudflare.com' link below.
echo [*] Anyone anywhere can use this HTTPS link to open the dashboard.
echo [*] Press Ctrl+C at any time to close the tunnel.
echo.
echo ==================================================================
echo.

"%CLOUDFLARED_BIN%" tunnel --protocol http2 --url http://127.0.0.1:8000

echo.
echo ==================================================================
echo [CLOSED] Public tunnel has been disconnected.
echo ==================================================================
pause
