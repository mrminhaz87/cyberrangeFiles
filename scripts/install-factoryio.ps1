# Purpose: Installs FactoryIO

mkdir "C:\Installer\"
$factoryIOPath = "C:\Installer\factoryio-installer-latest.exe"

# Microsoft likes TLSv1.2 as well
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading FactoryIO..."
(New-Object System.Net.WebClient).DownloadFile('https://realgames.b-cdn.net/fio/factoryio-installer-latest.exe', $factoryIOPath)

C:\Installer\factoryio-installer-latest.exe --mode unattended
