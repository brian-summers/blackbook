@echo off
rem bbk: run the Blackbook CLI from its Docker image (see bbk.ps1, which this
rem runs). Lets cmd.exe and programs that can't start a PowerShell script
rem themselves, such as MCP clients, use `bbk` too. Prefers PowerShell 7.
setlocal
set "ps=powershell"
where pwsh >nul 2>nul && set "ps=pwsh"
%ps% -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0bbk.ps1" %*
