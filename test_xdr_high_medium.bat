@echo off
echo =============================================
echo XDR HIGH/MEDIUM DETECTION TEST - KEY 8
echo =============================================
echo.
echo This test will trigger 10 high/medium XDR alerts:
echo.
echo HIGH SEVERITY (7 alerts):
echo   1. Copy process memory file (dd utility)
echo   2. PowerShell removing mailbox export logs
echo   3. API call from Tor exit node
echo   5. Credential dumping via LaZagne
echo   6. Delete Windows Shadow Copies
echo   7. EventLog service disabled
echo   8. Encoded VBScript execution
echo   9. Suspicious exe in .NET directory
echo.
echo MEDIUM SEVERITY (3 alerts):
echo   4. Rundll32 with no arguments
echo   10. Windows logon text changed
echo.
echo =============================================
echo.
echo WARNINGS:
echo - Some functions require admin privileges
echo - Shadow copy deletion will affect backups
echo - Registry changes may affect system behavior
echo - Exchange commands only work on Exchange servers
echo.
echo Press '8' on the server console to execute
echo these high/medium XDR detection functions.
echo.
pause

