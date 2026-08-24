@echo off
schtasks /create /tn "Threat2Signal Daily Poll" ^
  /tr "C:\tools\Threat2Signal\.venv\Scripts\python.exe C:\tools\Threat2Signal\threat2signal\poll.py" ^
  /sc daily /st 06:00 /f
echo Task registered: Threat2Signal Daily Poll (daily at 06:00)
