@echo off

sc query AliDDNS>nul
if errorlevel 1 goto :create
echo AliDDNS service detected, press any key to delete it.
pause>nul
sc delete AliDDNS
pause
exit

:create
sc create AliDDNS binPath= "%~dp0aliddns.exe -srv" start= auto obj= "NT AUTHORITY\LocalService" password= ""
echo Press any key to start the service.
pause>nul
sc start AliDDNS
echo Press any key to continue.
pause>nul