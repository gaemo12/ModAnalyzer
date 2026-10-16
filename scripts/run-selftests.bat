@echo off
REM Esegue i self-test degli scanner (stile progetto: main(), zero dipendenze di test).
REM Gate rigido su RuleEngineSelfTest + ArchiveIntegritySelfTest.
setlocal
cd /d "%~dp0.."

set "JDIR=C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
set "M2=%USERPROFILE%\.m2\repository"
set "CP=scanners\target\classes;common\target\classes;%M2%\org\ow2\asm\asm\9.6\asm-9.6.jar;%M2%\org\slf4j\slf4j-api\2.0.13\slf4j-api-2.0.13.jar"

echo 1/3 Compilo gli scanner...
call "%~dp0..\mvnw.cmd" -q -DskipTests package -pl common,scanners,memagent -am
if errorlevel 1 ( echo Compilazione fallita. & exit /b 1 )

echo 2/3 Compilo i self-test...
if exist "%TEMP%\selftests" rmdir /s /q "%TEMP%\selftests"
mkdir "%TEMP%\selftests"
"%JDIR%\bin\javac.exe" -cp "%CP%" -d "%TEMP%\selftests" scanners\src\test\java\RuleEngineSelfTest.java scanners\src\test\java\ArchiveIntegritySelfTest.java memagent\src\test\java\MemAgentSelfTest.java
if errorlevel 1 ( echo Compilazione test fallita. & exit /b 1 )

echo 3/3 Eseguo i self-test...
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" RuleEngineSelfTest
if errorlevel 1 ( echo RuleEngineSelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -cp "%TEMP%\selftests;%CP%" ArchiveIntegritySelfTest
if errorlevel 1 ( echo ArchiveIntegritySelfTest FALLITO. & exit /b 1 )
"%JDIR%\bin\java.exe" -Djdk.attach.allowAttachSelf=true -cp "%TEMP%\selftests;%CP%" MemAgentSelfTest memagent\target\MemAgent.jar
if errorlevel 1 ( echo MemAgentSelfTest FALLITO. & exit /b 1 )

echo.
echo OK: tutti i self-test passano.
exit /b 0
