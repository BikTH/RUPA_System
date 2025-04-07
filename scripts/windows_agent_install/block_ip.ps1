param(
    [string]$AlertID,
    [string]$SourceIP
)

# Définir le chemin de journalisation
$logFolder = "C:\Program Files (x86)\ossec-agent\logs"
# s'il n'existe pas, le créer
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force
}
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$logPath = "$logFolder\block_ip_$timestamp.log"


# Vérifier que l'adresse IP est valide
if ($SourceIP -match '^(\d{1,3}\.){3}\d{1,3}$') {
    # Lancer la commande pour bloquer l'IP via pare-feu Windows
    # Utilisation explicite de PowerShell avec bypass
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -Command `"New-NetFirewallRule -DisplayName 'Block $SourceIP' -Direction Inbound -Action Block -RemoteAddress $SourceIP -Profile Any -Protocol Any`"" -Wait

    # Journaliser l'action dans un fichier
    "[$timestamp] Blocked IP: $SourceIP due to AlertID: $AlertID" | Out-File -FilePath $logPath -Encoding utf8
    Write-Output "IP $SourceIP blocked and logged in $logPath"
} else {
    Write-Output "Adresse Ip invalide: $SourceIP"
}
