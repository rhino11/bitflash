@echo off
setlocal
cd /d "%~dp0"
title Bitflash Miner

rem Bitflash Miner: XMRig over Tor, straight to the pool's hidden service.
rem   mine.cmd YOUR_BTF_ADDRESS            mainnet
rem   mine.cmd YOUR_BTF_ADDRESS testnet    testnet pool (testnet address!)
rem Anything after those two is passed to XMRig, e.g. -t 4 to use 4 threads.
rem Double-clicked with no address, it asks for one.

set POOL=mddjuyuctouv62eqdaofvwf4timxxmp72d2ghmc6qp5mdey6f5au56id.onion:8436
set SOCKS=127.0.0.1:9251

if exist xmrig\xmrig.exe goto have_xmrig
echo.
echo   xmrig\xmrig.exe is missing. Antivirus products remove XMRig on sight
echo   because cryptojacking malware also uses it. Restore it from quarantine
echo   and add an exclusion for this folder, or unzip the package again.
echo   The file is the official XMRig 6.26.0 build; its hash is in SHA256SUMS.
echo.
pause
exit /b 1

:have_xmrig
set ADDR=%~1
set REST=
if not "%ADDR%"=="" goto from_args

echo.
echo   Bitflash Miner
echo.
echo   Paste your Bitflash payment address -- the one the wallet shows under
echo   Receive, or -newaddress prints. Not a .btf address. The pool pays to it.
echo   Add a space and the word testnet after it to mine the testnet pool.
echo.
set /p LINE=  address:
for /f "tokens=1,* delims= " %%a in ("%LINE%") do (
  set ADDR=%%a
  set REST=%%b
)
goto have_addr

:from_args
shift
:collect
if "%~1"=="" goto have_addr
set REST=%REST% %1
shift
goto collect

:have_addr
if "%ADDR%"=="" (
  echo   no address given.
  pause
  exit /b 1
)

set EXTRA=
for %%w in (%REST%) do call :word %%w
goto run

:word
if /i "%~1"=="testnet" (
  set POOL=vocwzaqll3vzuvs4nkva5fxh6q5odlokkqvfc2uvhcjtmjlygae5l4id.onion:18438
) else (
  set EXTRA=%EXTRA% %~1
)
goto :eof

:run
if not exist tor-data mkdir tor-data
echo.
echo   Starting Tor (own instance, SOCKS on %SOCKS%)...
start "Bitflash Miner - Tor" /min tor\tor.exe --SocksPort %SOCKS% --DataDirectory tor-data --PidFile tor-data\tor.pid --Log "notice file tor-data\tor.log" --ClientOnly 1
echo   Tor bootstraps in 10-60 s; XMRig retries until it is through.
echo   Pool: %POOL%
echo   Address: %ADDR%
echo.

xmrig\xmrig.exe -a rx/0 -x %SOCKS% -o %POOL% -u %ADDR% -p x --retries=100000 --retry-pause=5 %EXTRA%

rem XMRig exited (Ctrl+C or error): stop our Tor, and only ours.
if exist tor-data\tor.pid (
  set /p TORPID=<tor-data\tor.pid
  taskkill /PID %TORPID% /F >nul 2>&1
  del tor-data\tor.pid >nul 2>&1
)
echo.
echo   XMRig stopped.
pause
endlocal
