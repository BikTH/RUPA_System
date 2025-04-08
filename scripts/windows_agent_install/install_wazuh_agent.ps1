# Verifier si le script est execute en tant qu'administrateur
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Veuillez executer ce script en tant qu'administrateur." -ForegroundColor Red
    exit
}

# Variables
$wazuhAgentInstaller = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi"
$installPath = "C:\Program Files (x86)\ossec-agent"
$activeResponsePath = "$installPath\active-response"
$antivirusScript = "antivirus_scan.ps1"
$blockIpScript = "block_ip.ps1"

# Demander à l'utilisateur l'adresse du serveur Wazuh Manager
do {
    $WazuhManager = Read-Host "Entrez l'adresse du serveur Wazuh (IP ou FQDN)"

    $ipRegex = '^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.|$)){4}$'
    $fqdnRegex = '^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$'

    $valid = ($WazuhManager -match $ipRegex) -or ($WazuhManager -match $fqdnRegex)

    if (-not $valid) {
        Write-Host "Adresse invalide. Veuillez entrer une adresse IP ou un FQDN valide." -ForegroundColor Yellow
    }
} while (-not $valid)

# Définir automatiquement le nom de l'agent et les groupes
$ComputerName = $env:COMPUTERNAME
$SerialNumber = (Get-WmiObject Win32_BIOS).SerialNumber.Trim()
if (-not $SerialNumber) {
    $SerialNumber = "UnknownSerialNumber"
    Write-Host "Aucun numéro de série trouvé. Utilisation de 'UnknownSerialNumber'." -ForegroundColor Yellow
}

$WazuhAgentName = "$ComputerName-$SerialNumber"
$WazuhAgentGroup = "default,windows"

# Télécharger et installer le Wazuh Agent avec les paramètres
Write-Host ">>> Téléchargement et installation du Wazuh Agent..."
$msiPath = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri $wazuhAgentInstaller -OutFile $msiPath

Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /q WAZUH_MANAGER=`"$WazuhManager`" WAZUH_AGENT_GROUP=`"$WazuhAgentGroup`" WAZUH_AGENT_NAME=`"$WazuhAgentName`"" -Wait


# Vérifier l'installation
if (-Not (Test-Path $installPath)) {
    Write-Host "Erreur : L'installation du Wazuh Agent a échoué." -ForegroundColor Red
    exit
} else {
    Write-Host "Wazuh Agent installé avec succès." -ForegroundColor Green
}

# Creer le repertoire des reponses actives si il n'existe pas
Write-Host ">>> Creation du repertoire des reponses actives..."
if (-Not (Test-Path $activeResponsePath)) {
    New-Item -Path $activeResponsePath -ItemType Directory -Force
    Write-Host "Repertoire des reponses actives cree." -ForegroundColor Green
} else {
    Write-Host "Repertoire des reponses actives deja existant." -ForegroundColor Yellow
}

# Deployer les scripts de reponse active
Write-Host ">>> Deploiement des scripts de reponse active..."
# Assurez-vous que les scripts antivirus_scan.ps1 et block_ip.ps1 sont dans le meme repertoire que ce script
Copy-Item -Path ".\antivirus_scan.ps1" -Destination "$activeResponsePath\$antivirusScript" -Force
Copy-Item -Path ".\block_ip.ps1" -Destination "$activeResponsePath\$blockIpScript" -Force

Write-Host "Scripts de reponse active deployes avec succes." -ForegroundColor Green

# Configurer ossec.conf !"
Write-Host ">>> Configuration de ossec.conf pour les reponses actives..."
# Sauvegarder une copie de securite de ossec.conf
Copy-Item -Path "$installPath\ossec.conf" -Destination "$installPath\ossec.conf.bak" -Force
Write-Host "Sauvegarde de ossec.conf effectuee." -ForegroundColor Green

# Charger le contenu actuel de ossec.conf
[xml]$ossecConfig = Get-Content "$installPath\ossec.conf"

# Fonction pour ajouter un <command> si il n'existe pas
function Add-Command($name, $executable, $timeout) {
    # Verifier si la commande existe deja
    $existingCommand = $ossecConfig.ossec_config.command | Where-Object { $_.name -eq $name }
    if (-not $existingCommand) {
        $commandElement = $ossecConfig.CreateElement("command")

        $nameElement = $ossecConfig.CreateElement("name")
        $nameElement.InnerText = $name
        $commandElement.AppendChild($nameElement) | Out-Null

        $executableElement = $ossecConfig.CreateElement("executable")
        $executableElement.InnerText = $executable
        $commandElement.AppendChild($executableElement) | Out-Null

        $timeoutElement = $ossecConfig.CreateElement("timeout")
        $timeoutElement.InnerText = $timeout
        $commandElement.AppendChild($timeoutElement) | Out-Null

        $ossecConfig.ossec_config.AppendChild($commandElement) | Out-Null
        Write-Host "Commande '$name' ajoutée dans <ossec_config>." -ForegroundColor Green
    } else {
        Write-Host "Commande '$name' déjà présente." -ForegroundColor Yellow
    }
}

# Ajouter les commandes pour les scripts de réponse active
Add-Command "antivirus_scan" "antivirus_scan.ps1" "600"
Add-Command "block_ip" "block_ip.ps1" "600"

# Fonction pour ajouter un <active-response> si il n'existe pas
function Add-ActiveResponse($command, $location, $rules_id, $timeout) {
    # Vérifier si la réponse active existe déjà
    $existingResponse = $ossecConfig.ossec_config.'active-response' | Where-Object { $_.command -eq $command -and $_.rules_id -eq $rules_id }
    if (-not $existingResponse) {
        $activeResponseElement = $ossecConfig.CreateElement("active-response")

        $commandElement = $ossecConfig.CreateElement("command")
        $commandElement.InnerText = $command
        $activeResponseElement.AppendChild($commandElement) | Out-Null

        $locationElement = $ossecConfig.CreateElement("location")
        $locationElement.InnerText = $location
        $activeResponseElement.AppendChild($locationElement) | Out-Null

        $rulesIdElement = $ossecConfig.CreateElement("rules_id")
        $rulesIdElement.InnerText = $rules_id
        $activeResponseElement.AppendChild($rulesIdElement) | Out-Null

        $timeoutElement = $ossecConfig.CreateElement("timeout")
        $timeoutElement.InnerText = $timeout
        $activeResponseElement.AppendChild($timeoutElement) | Out-Null

        $ossecConfig.ossec_config.AppendChild($activeResponseElement) | Out-Null
        Write-Host "Réponse active '$command' ajoutée dans <ossec_config>." -ForegroundColor Green
    } else {
        Write-Host "Réponse active '$command' avec rules_id '$rules_id' déjà présente." -ForegroundColor Yellow
    }
}

# Ajouter les reponses actives
Add-ActiveResponse "block_ip" "local" "100010,100011,100012,100013,100014" "600" # ID de la regle pour malware
Add-ActiveResponse "antivirus_scan" "local" "100020,100021,100022,100023,100024" "600" # ID de la regle pour IP suspecte

# Sauvegarder le fichier ossec.conf
$ossecConfig.Save("$installPath\ossec.conf")
Write-Host "Configuration de ossec.conf mise a jour avec succes." -ForegroundColor Green

# Redemarrer le service Wazuh Agent
Write-Host ">>> Redemarrage du service Wazuh Agent..."
Restart-Service -Name "WazuhSvc"

Write-Host "Wazuh Agent et les reponses actives ont ete configures avec succes." -ForegroundColor Green
