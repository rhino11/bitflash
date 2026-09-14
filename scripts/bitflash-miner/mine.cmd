@echo off
setlocal
cd /d "%~dp0"

rem Bitflash Miner: XMRig over Tor, straight to the pool's hidden service.
rem   mine.cmd YOUR_BTF_ADDRESS            mainnet
rem   mine.cmd YOUR_BTF_ADDRESS testnet    testnet pool (testnet address!)
rem Anything after those two is passed to XMRig, e.g. -t 4 to use 4 threads.

set POOL=mddjuyuctouv62eqdaofvwf4timxxmp72d2ghmc6qp5mdey6f5au56id.onion:8436
set SOCKS=127.0.0.1:9251

if "%~1"=="" (
  echo.
  echo   usage: mine.cmd YOUR_BTF_ADDRESS [testnet] [xmrig options]
  echo.
  echo   YOUR_BTF_ADDRESS is a Bitflash payment address -- the kind the Bitflash
  echo   wallet shows under Receive, or -newaddress prints. Not a .btf address.
  echo   The pool pays out to it. Fee 1%%.
  echo.
  exit /b 1
)
set ADDR=%~1
shift
if /i "%~1"=="testnet" (
  set POOL=vocwzaqll3vzuvs4nkva5fxh6q5odlokkqvfc2uvhcjtmjlygae5l4id.onion:18438
  shift
)
set EXTRA=
:collect
if not "%~1"=="" (
  set EXTRA=%EXTRA% %1
  shift
  goto collect
)

if not exist tor-data mkdir tor-data
echo Starting Tor (own instance, SOCKS on %SOCKS%)...
start "Bitflash Miner - Tor" /min tor\tor.exe --SocksPort %SOCKS% --DataDirectory tor-data --PidFile tor-data\tor.pid --Log "notice file tor-data\tor.log" --ClientOnly 1
echo Tor bootstraps in 10-60 s; XMRig retries until it is through.
echo Pool: %POOL%
echo.

xmrig\xmrig.exe -a rx/0 -x %SOCKS% -o %POOL% -u %ADDR% -p x --retries=100000 --retry-pause=5 %EXTRA%

rem XMRig exited (Ctrl+C or error): stop our Tor, and only ours.
if exist tor-data\tor.pid (
  set /p TORPID=<tor-data\tor.pid
  taskkill /PID %TORPID% /F >nul 2>&1
  del tor-data\tor.pid >nul 2>&1
)
endlocal
