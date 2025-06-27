$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Relaunch script as Administrator
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define download URL and path
$CommonURLPart = 'bostr.exe'
$DownloadURL1 = 'https://raw.githubusercontent.com/adasjusk/OrangeBooster/main/' + $CommonURLPart

$rand = Get-Random -Maximum 99999999
$AppDataPath = Join-Path -Path $env:APPDATA -ChildPath 'InterJava-Programs'

# Create directory if it doesn't exist
if (-not (Test-Path -Path $AppDataPath)) {
    New-Item -Path $AppDataPath -ItemType Directory | Out-Null
}

# Set file path for the downloaded executable
$FilePath = Join-Path -Path $AppDataPath -ChildPath "bostr_$rand.exe"

# Download the executable
try {
    Invoke-WebRequest -Uri $DownloadURL1 -OutFile $FilePath -UseBasicParsing
} catch {
    Write-Host "Failed to download the executable from $DownloadURL1"
    Write-Host "Error: $_"
    exit 1
}

# Run the downloaded executable
$process = Start-Process -FilePath $FilePath -PassThru
$process.WaitForExit()

# Report the result
if ($process.ExitCode -eq 0) {
    Write-Host "Program executed successfully."
} else {
    Write-Host "Program exited with code $($process.ExitCode)."
}
