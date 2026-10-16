@echo off
REM Verifica automatica del corpus: scansiona ogni jar e controlla gli esiti attesi.
REM Uso: verify-corpus.bat [cartella-corpus]
setlocal
cd /d "%~dp0.."
set "CORPUS=%~1"
if "%CORPUS%"=="" set "CORPUS=%TEMP%\opencode\corpus"
set "JAR=modscan-open\target\ModScanOpen.jar"
if not exist "%JAR%" ( echo Build mancante: %JAR% & exit /b 1 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-corpus.ps1" -Corpus "%CORPUS%" -Jar "%JAR%"
exit /b %ERRORLEVEL%
