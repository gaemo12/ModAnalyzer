@echo off
set "JAVA_CMD=java.exe"
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"
set "P=%~dp0"
"%JAVA_CMD%" -cp "%P%ModScanOpen.jar;%P%lib\*" modscan.ModScanOpen %*
