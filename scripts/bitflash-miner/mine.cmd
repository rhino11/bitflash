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
echo   Pool: %POOL%
echo   Address: %ADDR%
echo.

rem Give Tor time to open its SOCKS port before XMRig starts knocking on it,
rem so the first thing on screen is not a red "connection refused".
set /a WAITED=0
:waittor
netstat -an | find "127.0.0.1:%SOCKS:~10%" >nul 2>&1
if not errorlevel 1 goto torup
if %WAITED% geq 60 (
  echo   Tor did not open %SOCKS% in 60 s. See tor-data\tor.log and the
  echo   "Bitflash Miner - Tor" window. Starting XMRig anyway; it retries.
  goto start_xmrig
)
ping -n 3 127.0.0.1 >nul
set /a WAITED+=2
goto waittor
:torup
echo   Tor is listening on %SOCKS%; it finishes bootstrapping in the background.
echo.

:start_xmrig
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
