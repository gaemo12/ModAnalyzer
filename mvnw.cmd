@echo off
REM Wrapper minimo: usa la distribuzione Maven gia scaricata in ~/.m2/wrapper
set "MVN=%USERPROFILE%\.m2\wrapper\dists\apache-maven-3.9.16-bin\4200fbc6\apache-maven-3.9.16\bin\mvn.cmd"
if exist "%MVN%" (
    call "%MVN%" %*
) else (
    mvn %*
)
