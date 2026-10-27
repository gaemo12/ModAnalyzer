@echo off
REM Crea dist\ModScanOpen\ come .exe nativo (jpackage, runtime Java incluso) e dist\ModScanOpen.zip
setlocal
cd /d "%~dp0.."

set "JDIR=C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
set "DIST=dist"
set "APPVER=1.3.2"

set "MVN=mvn"
where mvn >nul 2>nul
if errorlevel 1 (
    if exist "%~dp0..\mvnw.cmd" (
        set "MVN=%~dp0..\mvnw.cmd"
    ) else if exist "%USERPROFILE%\.m2\wrapper\dists\apache-maven-3.9.16-bin\4200fbc6\apache-maven-3.9.16\bin\mvn.cmd" (
        set "MVN=%USERPROFILE%\.m2\wrapper\dists\apache-maven-3.9.16-bin\4200fbc6\apache-maven-3.9.16\bin\mvn.cmd"
    ) else (
        echo Maven non trovato.
        exit /b 1
    )
)

echo 1/5 Compilo modscan-open...
if exist modscan-open\target\lib rmdir /s /q modscan-open\target\lib
call %MVN% -q -DskipTests package -pl common,scanners,memagent,modscan-open -am
if errorlevel 1 ( echo Compilazione fallita. & exit /b 1 )
if not exist modscan-open\target\ModScanOpen.jar ( echo Jar mancante. & exit /b 1 )
if not exist memagent\target\MemAgent.jar ( echo Agent mancante. & exit /b 1 )

echo 2/5 Runtime Java (jlink)...
if exist "%DIST%\_msruntime" rmdir /s /q "%DIST%\_msruntime"
"%JDIR%\bin\jlink.exe" --add-modules java.base,java.desktop,java.logging,java.management,java.naming,java.net.http,java.sql,java.xml,jdk.attach,jdk.unsupported,jdk.crypto.ec,jdk.crypto.cryptoki,jdk.jsobject,jdk.xml.dom,jdk.zipfs --strip-debug --no-header-files --no-man-pages --compress zip-6 --output "%DIST%\_msruntime"
if errorlevel 1 ( echo jlink fallito. & exit /b 1 )

echo 3/5 Preparo lo stage (jar + lib + javafx distinti, license-core escluso)...
set "STAGE=%DIST%\_msstage"
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%" "%STAGE%\javafx"
copy /Y modscan-open\target\ModScanOpen.jar "%STAGE%\" >nul
copy /Y memagent\target\MemAgent.jar "%STAGE%\" >nul
xcopy /E /I /Y modscan-open\target\lib "%STAGE%\lib" >nul
rem Nota: javafx-media NON è escludibile — javafx.web lo richiede al boot layer. Resta nel pacchetto.
rem license-core è una dipendenza transitiva di common ma l'edizione open non usa la verifica di licenza: escluso.
del /q "%STAGE%\lib\license-core-*.jar" >nul 2>nul
for %%f in ("%STAGE%\lib\javafx*.jar") do (
    echo %%~nxf | findstr /I "win.jar" >nul
    if not errorlevel 1 ( copy /Y "%%f" "%STAGE%\javafx\" >nul )
    del /q "%%f"
)

echo 4/5 jpackage ModScanOpen.exe...
if exist "%DIST%\ModScanOpen" rmdir /s /q "%DIST%\ModScanOpen"
"%JDIR%\bin\jpackage.exe" --type app-image --name ModScanOpen --app-version %APPVER% --input "%STAGE%" --main-jar ModScanOpen.jar --main-class modscan.ModScanOpen --runtime-image "%DIST%\_msruntime" --dest "%DIST%" --java-options "--module-path $APPDIR/javafx" --java-options "--add-modules javafx.controls,javafx.base,javafx.graphics,javafx.web,javafx.media" --java-options "-Dfile.encoding=UTF-8"
if errorlevel 1 ( echo jpackage fallito. & exit /b 1 )

echo 5/6 Doc, jar e ZIP open source...
copy /Y modscan-open\README.md "%DIST%\ModScanOpen\app\" >nul
copy /Y modscan-open\LICENSE "%DIST%\ModScanOpen\app\" >nul
copy /Y modscan-open\target\ModScanOpen.jar "%DIST%\ModScanOpen.jar" >nul
if exist "%DIST%\ModScanOpen.zip" del /q "%DIST%\ModScanOpen.zip"
powershell -NoProfile -Command "Compress-Archive -Path 'dist\ModScanOpen\*' -DestinationPath 'dist\ModScanOpen.zip'"
if errorlevel 1 ( echo ZIP fallito. & exit /b 1 )

echo 6/6 Installer .exe (jpackage + WiX opzionale)...
set "WIXFOUND="
if defined WIX_BIN if exist "%WIX_BIN%\candle.exe" ( set "PATH=%WIX_BIN%;%PATH%" & set "WIXFOUND=1" )
if not defined WIXFOUND if defined WIX if exist "%WIX%\bin\candle.exe" ( set "PATH=%WIX%\bin;%PATH%" & set "WIXFOUND=1" )
if not defined WIXFOUND for %%d in ("C:\Program Files (x86)\WiX Toolset v3.14\bin" "C:\Program Files (x86)\WiX Toolset v3.11\bin" "C:\Program Files\WiX Toolset v3.14\bin") do if exist "%%~d\candle.exe" ( set "PATH=%%~d;%PATH%" & set "WIXFOUND=1" )
if not defined WIXFOUND where candle.exe >nul 2>nul && set "WIXFOUND=1"
if defined WIXFOUND (
    if exist "%DIST%\ModScanOpen-%APPVER%.exe" del /q "%DIST%\ModScanOpen-%APPVER%.exe"
    "%JDIR%\bin\jpackage.exe" --type exe --name ModScanOpen --app-version %APPVER% --vendor "ModAnalyzer" --description "ModScanOpen - scansione mod Minecraft offline" --input "%STAGE%" --main-jar ModScanOpen.jar --main-class modscan.ModScanOpen --runtime-image "%DIST%\_msruntime" --dest "%DIST%" --java-options "--module-path $APPDIR/javafx" --java-options "--add-modules javafx.controls,javafx.base,javafx.graphics,javafx.web,javafx.media" --java-options "-Dfile.encoding=UTF-8" --win-per-user-install --win-menu --win-shortcut --win-dir-chooser
    if errorlevel 1 ( echo Installer .exe fallito. & exit /b 1 )
    if exist "%DIST%\ModScanOpen.exe" del /q "%DIST%\ModScanOpen.exe"
    ren "%DIST%\ModScanOpen-%APPVER%.exe" "ModScanOpen.exe"
    echo Installer: %DIST%\ModScanOpen.exe ^(per-utente, non portable^)
) else (
    echo ATTENZIONE: WiX 3 non trovato: installer .exe non creato.
    echo Imposta WIX_BIN alla cartella che contiene candle.exe e rilancia lo script.
)

echo.
echo OK: %DIST%\ModScanOpen\ModScanOpen.exe, %DIST%\ModScanOpen.zip, %DIST%\ModScanOpen.jar
exit /b 0
