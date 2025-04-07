param(
    [string]$AlertID,
    [string]$SourceIP
)

# Définir le chemin de journalisation
$logFolder = "C:\ProgramData\Wazuh\logs"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force
}
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$logPath = "$logFolder\antivirus_scan_$timestamp.log"

# Lancer une analyse antivirus avec Windows Defender et journaliser les résultats
# Utilisation explicite de PowerShell avec bypass
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -Command `"Start-MpScan -ScanType QuickScan | Out-File -FilePath '$logPath' -Encoding utf8`"" -Wait

# Ajouter une trace dans le journal Wazuh
"[$timestamp] Antivirus scan triggered by AlertID: $AlertID from IP: $SourceIP" | Out-File -FilePath $logPath -Append
Write-Output "Antivirus scan logged in $logPath"
