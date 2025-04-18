$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$CommonURLPart = 'bostr.exe'
$DownloadURL1 = 'https://raw.githubusercontent.com/adasjusk/OrangeBooster/main/' + $CommonURLPart

$rand = Get-Random -Maximum 99999999
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$AppDataPath = Join-Path -Path $env:APPDATA -ChildPath 'InterJava-Programs'
if (-not (Test-Path -Path $AppDataPath)) {
    New-Item -Path $AppDataPath -ItemType Directory | Out-Null
}

$FilePath = Join-Path -Path $AppDataPath -ChildPath "bostr_$rand.exe"

try {
    Invoke-WebRequest -Uri $DownloadURL1 -OutFile $FilePath -UseBasicParsing
} catch {
    Write-Host "Failed to download the executable from $DownloadURL1"
    Write-Host "Error: $_"
    exit 1
}
Start-Process -FilePath $FilePath -Verb RunAs -Wait
