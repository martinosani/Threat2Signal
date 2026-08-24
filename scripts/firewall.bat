@echo off
:: Run as Administrator to allow inbound connections to Threat2Signal dashboard
netsh advfirewall firewall add rule name="Threat2Signal" dir=in action=allow protocol=TCP localport=8001
echo Firewall rule added for port 8001.
pause
