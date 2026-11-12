@echo off
chcp 65001 >nul
title SA Narva Haigla - Phone Directory
cd /d "%~dp0"

echo.
echo   SA Narva Haigla Phone Directory
echo   ================================
echo.

python server.py

echo.
echo   Server stopped.
pause
