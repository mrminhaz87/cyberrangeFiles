# Purpose: Install additional packages from Chocolatey.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing additional Choco packages..."

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  Write-Host "Installing Chocolatey"
  iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
  Write-Host "Chocolatey is already installed."
}

Write-Host "Installing Chocolatey extras..."
#choco install -y --limit-output --no-progress wireshark winpcap
choco install -y --limit-output --no-progress wireshark #winpcap

<#
#install winpcap
New-Item -Force -ItemType directory -Path "C:\Installer\"
#mkdir "C:\Installer\"
$path = "C:\Installer\WinPcap_4_1_3.exe"

# Microsoft likes TLSv1.2 as well
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading WinPCap..."
(New-Object System.Net.WebClient).DownloadFile('https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe', $path)

C:\Installer\WinPcap_4_1_3.exe --mode unattended

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Choco addons complete!"
#>
