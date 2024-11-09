param(
    [string]$AlertID,
    [string]$SourceIP
)

# Démarrer une analyse rapide avec Windows Defender
Start-MpScan -ScanType QuickScan

# Optionnel : Enregistrer les résultats de l'analyse dans un fichier journal
$logPath = "C:\ProgramData\Wazuh\logs\antivirus_scan_$((Get-Date).ToString('yyyyMMddHHmmss')).log"
Start-MpScan -ScanType QuickScan | Out-File -FilePath $logPath -Encoding utf8

# Envoyer une notification via Wazuh ou un autre mécanisme si nécessaire
# Exemple : Ajouter une entrée dans le journal Wazuh
Write-Output "Antivirus scan initiated due to AlertID: $AlertID from IP: $SourceIP"
