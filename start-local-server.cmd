@echo off
cd /d "%~dp0"
title TikTok Ads Pro - Authorization Backend
if not exist node_modules call npm install
call npm start
echo.
echo The authorization backend stopped.
pause
