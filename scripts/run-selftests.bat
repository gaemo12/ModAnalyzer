@echo off
REM Esegue i self-test degli scanner (stile progetto: main(), zero dipendenze di test).
REM Gate rigido su RuleEngineSelfTest + ArchiveIntegritySelfTest.
setlocal
cd /d "%~dp0.."

set "JDIR=C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
set "M2=%USERPROFILE%\.m2\repository"
set "CP=scanners\target\classes;common\target\classes;modscan-open\target\classes;%M2%\org\ow2\asm\asm\9.6\asm-9.6.jar;%M2%\org\slf4j\slf4j-api\2.0.13\slf4j-api-2.0.13.jar"

echo 1/3 Compilo gli scanner...
call "%~dp0..\mvnw.cmd" -q -DskipTests package -pl common,scanners,memagent,modscan-open -am
if errorlevel 1 ( echo Compilazione fallita. & exit /b 1 )

echo 2/3 Compilo i self-test...
if exist "%TEMP%\selftests" rmdir /s /q "%TEMP%\selftests"
mkdir "%TEMP%\selftests"
"%JDIR%\bin\javac.exe" -cp "%CP%" -d "%TEMP%\selftests" scanners\src\test\java\RuleEngineSelfTest.java scanners\src\test\java\ArchiveIntegritySelfTest.java scanners\src\test\java\ModsTimelineSelfTest.java scanners\src\test\java\RuntimeSelfTest.java scanners\src\test\java\ModsAuditSelfTest.java scanners\src\test\java\CrashLogsSelfTest.java scanners\src\test\java\com\jaranalyzer\scanners\engine\UsnJournalSelfTest.java memagent\src\test\java\MemAgentSelfTest.java modscan-open\src\test\java\modscan\MemSkipSelfTest.java
if errorlevel 1 ( echo Compilazione test fallita. & exit /b 1 )

echo 3/3 Eseguo i self-test...
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" RuleEngineSelfTest
if errorlevel 1 ( echo RuleEngineSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" ArchiveIntegritySelfTest
if errorlevel 1 ( echo ArchiveIntegritySelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" ModsTimelineSelfTest
if errorlevel 1 ( echo ModsTimelineSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" RuntimeSelfTest
if errorlevel 1 ( echo RuntimeSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" ModsAuditSelfTest
if errorlevel 1 ( echo ModsAuditSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" CrashLogsSelfTest
if errorlevel 1 ( echo CrashLogsSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" com.jaranalyzer.scanners.engine.UsnJournalSelfTest
if errorlevel 1 ( echo UsnJournalSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" modscan.MemSkipSelfTest
if errorlevel 1 ( echo MemSkipSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -Djdk.attach.allowAttachSelf=true -cp "%TEMP%\selftests;%CP%" MemAgentSelfTest memagent\target\MemAgent.jar
if errorlevel 1 ( echo MemAgentSelfTest FALLITO. & exit /b 1 )

echo.
echo OK: tutti i self-test passano.
exit /b 0
