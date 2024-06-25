# Purpose: Installs velociraptor on the host

#Stop-Service -name wazuh
#if (Test-Path -Path "C:\Program Files (x86)\ossec-agent\") {
#  echo "Removing resedues"
#  rm -r "C:\Program Files (x86)\ossec-agent\"
#}

#msiexec.exe /x wazuh-agent-4.3.9-1.msi /qn
#Start-Sleep -Seconds 10

# Downloading, installing and connecting with the wazuh server
echo "Attempting to download the wazuh agent"
#Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.9-1.msi -OutFile ${env:tmp}\wazuh-agent-4.3.9.msi; msiexec.exe /i ${env:tmp}\wazuh-agent-4.3.9.msi /q WAZUH_MANAGER='192.168.38.106' WAZUH_REGISTRATION_SERVER='192.168.38.106'
#Start-Sleep -Seconds 10

# Starting the service
echo "Starting the Wazuh Service"
# NET START WazuhSvc
Start-Service -Name wazuh

# Updating the config file to connect with sysmon
function Format-XML ([xml]$xml, $indent=2)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = $Indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    Write-Output $StringWriter.ToString()
}

echo "Adding Sysmon in config"
[regex]$pattern="<localfile>"
$newString=$pattern.replace((get-content "C:\Program Files (x86)\ossec-agent\ossec.conf"), "<localfile> <location>Microsoft-Windows-Sysmon/Operational</location> <log_format>eventchannel</log_format> </localfile> <localfile>", 1)

$string=$(get-content "C:\Program Files (x86)\ossec-agent\ossec.conf")
if( -not (Select-String -InputObject $string -pattern "Sysmon")) {
  echo (Format-XML([xml]$newString) -indent 2) > "C:\Program Files (x86)\ossec-agent\ossec.conf"
}

$MyPath="C:\Program Files (x86)\ossec-agent\ossec.conf"
$MyRawString = Get-Content -Raw $MyPath
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($MyPath, $MyRawString, $Utf8NoBomEncoding)

# Restarting the service
echo "Restarting the service after config update"
Restart-Service -Name wazuh
