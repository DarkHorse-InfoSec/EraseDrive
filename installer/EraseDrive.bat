@echo off
REM EraseDrive launcher
REM Self-elevates to administrator (required for disk operations), then launches the GUI.

NET FILE 1>NUL 2>NUL
if not '%errorlevel%' == '0' (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-EraseDrive.ps1" %*
