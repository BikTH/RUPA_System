param(
    [string]$AlertID,
    [string]$SourceIP
)

# Vérifier que l'adresse IP est valide
if ($SourceIP -match '^(\d{1,3}\.){3}\d{1,3}$') {
    # Créer une nouvelle règle de pare-feu pour bloquer l'IP
    New-NetFirewallRule -DisplayName "Block $SourceIP" -Direction Inbound -Action Block -RemoteAddress $SourceIP
    
    # Optionnel : Enregistrer l'action dans un fichier journal
    $logPath = "C:\ProgramData\Wazuh\logs\block_ip_$((Get-Date).ToString('yyyyMMddHHmmss')).log"
    "Blocked IP: $SourceIP due to AlertID: $AlertID" | Out-File -FilePath $logPath -Encoding utf8
    
    # Envoyer une notification via Wazuh ou un autre mécanisme si nécessaire
    Write-Output "IP $SourceIP has been blocked due to AlertID: $AlertID"
} else {
    Write-Output "Invalid IP address provided: $SourceIP"
}
