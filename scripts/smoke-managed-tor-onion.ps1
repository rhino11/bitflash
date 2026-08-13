param(
    [string]$Bitflash,
    [string]$Tor,
    [string]$WorkDir,
    [int]$TimeoutSec = 600,
    [int]$OnionWarmupSec = 120
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir "..")).Path
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-RegexInFile {
    param(
        [string]$Path,
        [string]$Pattern,
        [datetime]$Deadline,
        [string]$Label
    )

    while ((Get-Date) -lt $Deadline) {
        if (Test-Path $Path) {
            $text = Get-Content -Raw -ErrorAction SilentlyContinue $Path
            if ($null -ne $text) {
                $m = [regex]::Match($text, $Pattern)
                if ($m.Success) {
                    return $m
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out waiting for $Label"
}

function Stop-TestProcesses {
    param(
        [System.Diagnostics.Process[]]$Processes,
        [string[]]$DataDirKeys
    )

    foreach ($p in $Processes) {
        try {
            $p.Refresh()
            if (!$p.HasExited) {
                Stop-Process -Id $p.Id -Force
            }
        }
        catch {}
    }

    foreach ($key in $DataDirKeys) {
        if ([string]::IsNullOrWhiteSpace($key)) {
            continue
        }
        try {
            Get-CimInstance Win32_Process -Filter "name = 'tor.exe'" |
                Where-Object { $_.CommandLine -like "*$key*" } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
        }
        catch {}
    }
}

$repo = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($Bitflash)) {
    $Bitflash = Join-Path $repo "src\bitflash.exe"
}
if ([string]::IsNullOrWhiteSpace($Tor)) {
    $candidates = @(
        (Join-Path $repo "src\tor\tor.exe"),
        (Join-Path $repo "Bitflash-$(Select-String -Path (Join-Path $repo 'Makefile') -Pattern '^VERSION[ ]*:=' | ForEach-Object { ($_.Line -split ':=')[1].Trim() })-windows\tor\tor.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $Tor = $candidate
            break
        }
    }
}
if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP ("bitflash-managed-tor-two-node-" + (Get-Date -Format "yyyyMMddHHmmss"))
}

if (!(Test-Path $Bitflash)) {
    throw "Bitflash binary not found: $Bitflash"
}
if (!(Test-Path $Tor)) {
    throw "Tor binary not found. Pass -Tor or build the Windows-with-Tor package."
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$dataA = Join-Path $WorkDir "node-a"
$dataB = Join-Path $WorkDir "node-b"
New-Item -ItemType Directory -Force -Path $dataA | Out-Null
New-Item -ItemType Directory -Force -Path $dataB | Out-Null

$portA = Get-FreeTcpPort
$portB = Get-FreeTcpPort
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$oldPath = $env:PATH
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:PATH

$procA = $null
$procB = $null
$dataKeys = @((Split-Path $WorkDir -Leaf))

try {
    $argsA = @(
        "-datadir=$dataA",
        "-port=$portA",
        "-managedtor=$Tor",
        "-nogui",
        "-debug",
        "-checkblocks=0"
    )
    $procA = Start-Process -FilePath $Bitflash -ArgumentList $argsA -WorkingDirectory (Split-Path $Bitflash -Parent) -PassThru -WindowStyle Hidden
    $logA = Join-Path $dataA "debug.log"

    $btfMatch = Wait-RegexInFile -Path $logA -Pattern "Nostr: node \.btf address = ([a-z2-7]+\.btf)" -Deadline $deadline -Label "node A .btf address"
    $btfA = $btfMatch.Groups[1].Value

    $onionMatch = Wait-RegexInFile -Path $logA -Pattern "Managed Tor hidden service ready: ([a-z2-7]{56}\.onion:\d+)" -Deadline $deadline -Label "node A managed onion"
    $onionA = $onionMatch.Groups[1].Value

    Wait-RegexInFile -Path $logA -Pattern "Nostr: \.btf self-resolve OK via .*" -Deadline $deadline -Label "node A descriptor self-resolve" | Out-Null
    if ($OnionWarmupSec -gt 0) {
        Write-Host "Waiting $OnionWarmupSec second(s) for Tor hidden-service descriptor propagation"
        Start-Sleep -Seconds $OnionWarmupSec
    }

    $argsB = @(
        "-datadir=$dataB",
        "-port=$portB",
        "-managedtor=$Tor",
        "-oniononly",
        "-connectbtf=$btfA",
        "-nogui",
        "-debug",
        "-checkblocks=0"
    )
    $procB = Start-Process -FilePath $Bitflash -ArgumentList $argsB -WorkingDirectory (Split-Path $Bitflash -Parent) -PassThru -WindowStyle Hidden
    $logB = Join-Path $dataB "debug.log"

    Wait-RegexInFile -Path $logB -Pattern ("connected " + [regex]::Escape($btfA) + " via direct onion ") -Deadline $deadline -Label "node B direct onion connection to node A" | Out-Null

    Write-Host "Managed Tor two-node onion smoke test passed"
    Write-Host "  node A .btf:   $btfA"
    Write-Host "  node A onion:  $onionA"
    Write-Host "  node A port:   $portA"
    Write-Host "  node B port:   $portB"
    Write-Host "  work dir:      $WorkDir"
}
finally {
    $env:PATH = $oldPath
    $procs = @()
    if ($null -ne $procA) { $procs += $procA }
    if ($null -ne $procB) { $procs += $procB }
    Stop-TestProcesses -Processes $procs -DataDirKeys $dataKeys
}
