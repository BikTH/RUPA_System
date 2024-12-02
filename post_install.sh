#!/bin/bash

set -e  # Arrêter le script en cas d'erreur

# Vérifier si les variables sont passées
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 [variables...]"
    exit 1
fi

# Déclaration des variables passées en arguments
declare -A GLOBAL_VARS
index=0
keys=( "ORG_NAME" "ORG_UNIT" "EMAIL_ADDRESS" "INTERFACE_RESEAU" "WAZUH_MANAGER_IP" "WAZUH_SURICATA_IP" "WAZUH_SURICATA_SUBNET" "WAZUH_SURICATA_GATEWAY" "PUID" "PGID" )
for value in "$@"; do
    GLOBAL_VARS["${keys[index]}"]=$value
    index=$((index + 1))
done

echo ">>> Configuration post-installation en cours..."

# 1. Configuration de Suricata avec Wazuh
echo ">>> Intégration de Suricata à Wazuh..."

# Supposons que l'intégration nécessite de configurer Suricata pour envoyer des logs à Wazuh
# Vous pouvez adapter cette section selon le procédé spécifique que vous souhaitez utiliser

# Exemple : Modification de la configuration de Suricata pour envoyer les logs à Wazuh
SURICATA_CONF_PATH="wazuh/config/wazuh_suricata/suricata.yaml"

if [ -f "$SURICATA_CONF_PATH" ]; then
    # Ajouter ou modifier les paramètres pour intégrer Suricata à Wazuh
    # Exemple : Configuration d'une sortie syslog vers Wazuh Manager
    cat <<EOF >> "$SURICATA_CONF_PATH"

outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/eve.json

  - syslog:
      enabled: yes
      facility: local5
      level: info
      server: ${GLOBAL_VARS["WAZUH_MANAGER_IP"]}
      port: 514
      udp: yes
EOF
    echo "Suricata configuré pour envoyer des logs à Wazuh Manager."
else
    echo "Erreur : Le fichier de configuration de Suricata n'a pas été trouvé à l'emplacement $SURICATA_CONF_PATH."
    exit 1
fi

# Redémarrer le conteneur Suricata pour appliquer les modifications
echo ">>> Redémarrage du conteneur Suricata..."
docker-compose restart wazuh.suricata

# 2. Configuration des e-mails dans Wazuh
echo ">>> Configuration des e-mails pour les alertes dans Wazuh..."

# Demander les informations SMTP à l'utilisateur
read -r -p "Entrez le serveur SMTP (exemple : smtp.votre_domaine.com) : " SMTP_SERVER

# Validation de l'adresse du serveur SMTP
while [[ ! "$SMTP_SERVER" =~ ^[a-zA-Z0-9._%-]+\.[a-zA-Z]{2,6}$ ]]; do
    echo "Adresse du serveur SMTP invalide. Veuillez réessayer."
    read -r -p "Entrez le serveur SMTP (exemple : smtp.votre_domaine.com) : " SMTP_SERVER
done

read -r -p "Entrez le port SMTP (par défaut 587) : " SMTP_PORT
SMTP_PORT=${SMTP_PORT:-587}

# Vérifier que le port est un nombre entre 1 et 65535
while ! [[ "$SMTP_PORT" =~ ^[0-9]+$ ]] || [ "$SMTP_PORT" -lt 1 ] || [ "$SMTP_PORT" -gt 65535 ]; do
    echo "Port SMTP invalide. Veuillez entrer un nombre entre 1 et 65535."
    read -r -p "Entrez le port SMTP (par défaut 587) : " SMTP_PORT
done

read -r -p "Utilisez-vous une connexion sécurisée (TLS/SSL) ? (y/n) : " SMTP_SECURE

# Validation de l'entrée utilisateur
while [[ ! "$SMTP_SECURE" =~ ^[YyNn]$ ]]; do
    echo "Veuillez entrer 'y' pour oui ou 'n' pour non."
    read -r -p "Utilisez-vous une connexion sécurisée (TLS/SSL) ? (y/n) : " SMTP_SECURE
done

read -r -p "Entrez l'adresse e-mail de l'expéditeur : " EMAIL_FROM

# Validation de l'adresse e-mail
while [[ ! "$EMAIL_FROM" =~ ^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$ ]]; do
    echo "Adresse e-mail invalide. Veuillez réessayer."
    read -r -p "Entrez l'adresse e-mail de l'expéditeur : " EMAIL_FROM
done

read -r -p "Entrez l'adresse e-mail du destinataire : " EMAIL_TO

# Validation de l'adresse e-mail
while [[ ! "$EMAIL_TO" =~ ^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$ ]]; do
    echo "Adresse e-mail invalide. Veuillez réessayer."
    read -r -p "Entrez l'adresse e-mail du destinataire : " EMAIL_TO
done

read -r -p "Le serveur SMTP nécessite-t-il une authentification ? (y/n) : " SMTP_AUTH

# Validation de l'entrée utilisateur
while [[ ! "$SMTP_AUTH" =~ ^[YyNn]$ ]]; do
    echo "Veuillez entrer 'y' pour oui ou 'n' pour non."
    read -r -p "Le serveur SMTP nécessite-t-il une authentification ? (y/n) : " SMTP_AUTH
done

if [[ "$SMTP_AUTH" =~ ^[Yy]$ ]]; then
    read -r -p "Entrez le nom d'utilisateur SMTP : " SMTP_USER
    read -r -s -p "Entrez le mot de passe SMTP : " SMTP_PASS
    echo
fi

# Générer le bloc de configuration XML pour les e-mails
EMAIL_CONFIG="<global>
  <email_notification>yes</email_notification>
  <email_from>${EMAIL_FROM}</email_from>
  <smtp_server>${SMTP_SERVER}</smtp_server>
  <smtp_port>${SMTP_PORT}</smtp_port>
  <email_to>${EMAIL_TO}</email_to>
  <email_alert_level>7</email_alert_level>
"

if [[ "$SMTP_SECURE" =~ ^[Yy]$ ]]; then
    EMAIL_CONFIG+="  <smtp_secure>yes</smtp_secure>
"
else
    EMAIL_CONFIG+="  <smtp_secure>no</smtp_secure>
"
fi

if [[ "$SMTP_AUTH" =~ ^[Yy]$ ]]; then
    EMAIL_CONFIG+="  <smtp_auth>yes</smtp_auth>
  <smtp_user>${SMTP_USER}</smtp_user>
  <smtp_password>${SMTP_PASS}</smtp_password>
"
else
    EMAIL_CONFIG+="  <smtp_auth>no</smtp_auth>
"
fi

EMAIL_CONFIG+="</global>"

# Créer un fichier temporaire avec la configuration
echo "$EMAIL_CONFIG" > email_config.xml

# Copier le fichier dans le conteneur
docker cp email_config.xml wazuh.manager:/var/ossec/etc/shared/email_config.xml

# Supprimer le fichier temporaire
rm email_config.xml

# Modifier le fichier ossec.conf dans le conteneur
docker exec -it wazuh.manager bash -c "sed -i '/<\/ossec_config>/i \\    <include>shared/email_config.xml</include>' /var/ossec/etc/ossec.conf"

# Redémarrer le service Wazuh Manager
echo ">>> Redémarrage du service Wazuh Manager..."
docker exec -it wazuh.manager bash -c "service wazuh-manager restart"

echo ">>> Configuration des e-mails dans Wazuh terminée."
sleep 30

# 3. Envoi d'un e-mail de test

echo ">>> Envoi d'un e-mail de test..."

# Installer mailutils dans le conteneur Wazuh Manager si nécessaire
docker exec -it wazuh.manager bash -c "apt-get update && apt-get install -y mailutils || true"

# Exécuter la commande sendmail pour tester
docker exec -it wazuh.manager bash -c "echo 'Test e-mail from Wazuh Manager' | mail -s 'Wazuh Test Email' '${EMAIL_TO}'"

echo "Un e-mail de test a été envoyé à ${EMAIL_TO}. Veuillez vérifier votre boîte de réception."
echo "Remarque : Si l'envoi de l'e-mail de test échoue, veuillez vérifier la configuration SMTP et les logs du conteneur wazuh.manager."
echo "Ou reconfigurer Wazuh pour l'envoi de mails via le dashboard."

# 4. Création de workflows de réponse dans Shuffle

echo ">>> Création de workflows de réponse dans Shuffle..."

# Demander les informations pour l'API Wazuh
read -r -p "Entrez l'URL de l'API Wazuh (par défaut : https://wazuh.manager:55000) : " WAZUH_API_URL
WAZUH_API_URL=${WAZUH_API_URL:-"https://wazuh.manager:55000"}

# Validation de l'URL
while [[ ! "$WAZUH_API_URL" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?$ ]]; do
    echo "URL invalide. Veuillez réessayer."
    read -r -p "Entrez l'URL de l'API Wazuh (par défaut : https://wazuh.manager:55000) : " WAZUH_API_URL
done

# Demander le nom d'utilisateur et le mot de passe de l'API Wazuh
read -r -p "Entrez le nom d'utilisateur de l'API Wazuh (par défaut: wazuh-wui) : " WAZUH_API_USER
WAZUH_API_USER=${WAZUH_API_USER:-"wazuh-wui"}
read -r -s -p "Entrez le mot de passe de l'API Wazuh (par défaut: MyS3cr37P450r.*-) : " WAZUH_API_PASS
WAZUH_API_PASS=${WAZUH_API_PASS:-"MyS3cr37P450r.*-"}
echo

# Ajouter l'application Wazuh dans Shuffle via l'API Shuffle
echo ">>> Configuration de l'application Wazuh dans Shuffle..."

SHUFFLE_BACKEND_URL="http://localhost:${GLOBAL_VARS["BACKEND_PORT"]}"

# Vérifier que Shuffle Backend est accessible
if curl --output /dev/null --silent --head --fail "$SHUFFLE_BACKEND_URL"; then
    echo "Shuffle Backend est accessible."
else
    echo "Erreur : Shuffle Backend n'est pas accessible. Veuillez vérifier que le conteneur est en cours d'exécution."
    exit 1
fi

# Authentification auprès de l'API Shuffle
echo ">>> Authentification auprès de l'API Shuffle..."

SHUFFLE_DEFAULT_USERNAME="admin"
SHUFFLE_DEFAULT_PASSWORD="admin"

SHUFFLE_AUTH_RESPONSE=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/auth" \
    -H "Content-Type: application/json" \
    -d '{"username": "'"$SHUFFLE_DEFAULT_USERNAME"'", "password": "'"$SHUFFLE_DEFAULT_PASSWORD"'"}')

SHUFFLE_API_KEY=$(echo "$SHUFFLE_AUTH_RESPONSE" | jq -r '.access_token')

if [ "$SHUFFLE_API_KEY" == "null" ]; then
    echo "Erreur : Impossible de s'authentifier auprès de Shuffle. Vérifiez les identifiants."
    exit 1
else
    echo "Authentification réussie."
fi

# Ajouter l'application Wazuh dans Shuffle
WAZUH_APP_CONFIG=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/apps" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "name": "Wazuh",
        "app": "wazuh",
        "fields": {
            "url": "'"${WAZUH_API_URL}"'",
            "username": "'"${WAZUH_API_USER}"'",
            "password": "'"${WAZUH_API_PASS}"'",
            "ssl_verify": false
        }
    }')

WAZUH_APP_ID=$(echo "$WAZUH_APP_CONFIG" | jq -r '.appid')

if [ "$WAZUH_APP_ID" == "null" ]; then
    echo "Erreur : Échec de la configuration de l'application Wazuh dans Shuffle."
    exit 1
else
    echo "Application Wazuh configurée avec succès dans Shuffle."
fi

# Intégration avec Mikrotik
echo ">>> Configuration de l'application Mikrotik dans Shuffle..."

read -r -p "Entrez l'adresse IP du routeur Mikrotik : " MIKROTIK_IP

# Validation de l'adresse IP
while ! [[ "$MIKROTIK_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
    echo "Adresse IP invalide. Veuillez réessayer."
    read -r -p "Entrez l'adresse IP du routeur Mikrotik : " MIKROTIK_IP
done

read -r -p "Entrez le nom d'utilisateur du routeur Mikrotik : " MIKROTIK_USER
read -r -s -p "Entrez le mot de passe du routeur Mikrotik : " MIKROTIK_PASS
echo

MIKROTIK_APP_CONFIG=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/apps" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "name": "Mikrotik",
        "app": "mikrotik",
        "fields": {
            "host": "'"$MIKROTIK_IP"'",
            "username": "'"$MIKROTIK_USER"'",
            "password": "'"$MIKROTIK_PASS"'"
        }
    }')

MIKROTIK_APP_ID=$(echo "$MIKROTIK_APP_CONFIG" | jq -r '.appid')

if [ "$MIKROTIK_APP_ID" == "null" ]; then
    echo "Erreur : Échec de la configuration de l'application Mikrotik dans Shuffle."
    exit 1
else
    echo "Application Mikrotik configurée avec succès dans Shuffle."
fi

# 5. Préconfiguration des workflows dans Shuffle

echo ">>> Préconfiguration des workflows dans Shuffle..."

# Fonction pour valider les entrées utilisateur (par exemple, adresses e-mail)
validate_email() {
    local EMAIL=$1
    if [[ "$EMAIL" =~ ^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Demander l'adresse e-mail pour l'envoi des rapports
read -r -p "Entrez l'adresse e-mail pour recevoir les rapports d'incident : " INCIDENT_EMAIL
while ! validate_email "$INCIDENT_EMAIL"; do
    echo "Adresse e-mail invalide. Veuillez réessayer."
    read -r -p "Entrez l'adresse e-mail pour recevoir les rapports d'incident : " INCIDENT_EMAIL
done

# Préparer les workflows JSON
WORKFLOW_TERMINAL=$(cat <<EOF
{
    "name": "Réponse aux incidents sur les terminaux",
    "description": "Workflow de réponse aux incidents sur les terminaux via Wazuh et Mikrotik.",
    "workflow": {
        "nodes": [
            {
                "id": "1",
                "app_id": "$WAZUH_APP_ID",
                "action": "get_alerts",
                "name": "Get Alerts from Wazuh",
                "parameters": {
                    "interval": "5m"
                }
            },
            {
                "id": "2",
                "app_id": "$MIKROTIK_APP_ID",
                "action": "block_ip",
                "name": "Block Victim Terminal",
                "parameters": {
                    "ip": "{{node.1.data.alert.source.ip}}"
                }
            },
            {
                "id": "3",
                "app_id": "email",
                "action": "send_email",
                "name": "Send Incident Report",
                "parameters": {
                    "to": "$INCIDENT_EMAIL",
                    "subject": "Incident Report - Terminal",
                    "body": "Incident detected and actions taken."
                }
            }
        ],
        "edges": [
            {"source": "1", "target": "2"},
            {"source": "2", "target": "3"}
        ]
    }
}
EOF
)

WORKFLOW_RESEAU=$(cat <<EOF
{
    "name": "Réponse aux incidents réseau",
    "description": "Workflow de réponse aux incidents réseau via Suricata, Wazuh et Mikrotik.",
    "workflow": {
        "nodes": [
            {
                "id": "1",
                "app_id": "$WAZUH_APP_ID",
                "action": "get_alerts",
                "name": "Get Alerts from Wazuh (Suricata)",
                "parameters": {
                    "interval": "5m",
                    "query": "rule.groups:suricata"
                }
            },
            {
                "id": "2",
                "app_id": "$MIKROTIK_APP_ID",
                "action": "block_ip",
                "name": "Block Malicious IP",
                "parameters": {
                    "ip": "{{node.1.data.alert.source.ip}}"
                }
            },
            {
                "id": "3",
                "app_id": "email",
                "action": "send_email",
                "name": "Send Incident Report",
                "parameters": {
                    "to": "$INCIDENT_EMAIL",
                    "subject": "Incident Report - Network",
                    "body": "Network incident detected and actions taken."
                }
            }
        ],
        "edges": [
            {"source": "1", "target": "2"},
            {"source": "2", "target": "3"}
        ]
    }
}
EOF
)

WORKFLOW_INCIDENT_REPORT=$(cat <<EOF
{
    "name": "Rapport d'Incident de Sécurité",
    "description": "Workflow pour récupérer les alertes récentes de Wazuh, filtrer les alertes pertinentes, générer un rapport et l'envoyer par email.",
    "workflow": {
        "nodes": [
            {
                "id": "1",
                "app_id": "$WAZUH_APP_ID",
                "action": "get_alerts",
                "name": "Obtenir les alertes de Wazuh",
                "parameters": {
                    "query": "",
                    "limit": "100"
                }
            },
            {
                "id": "2",
                "app_id": "shuffle-tools",
                "action": "code",
                "name": "Filtrer les alertes pertinentes",
                "parameters": {
                    "code": "def handler(inputs, data):\n    alerts = inputs['data']['data']['alerts']\n    relevant_alerts = [alert for alert in alerts if alert['rule']['id'] in ['100003', '100002']]\n    return {'relevant_alerts': relevant_alerts}"
                }
            },
            {
                "id": "3",
                "app_id": "shuffle-tools",
                "action": "code",
                "name": "Générer le rapport",
                "parameters": {
                    "code": "def handler(inputs, data):\n    alerts = inputs['relevant_alerts']\n    report = 'Rapport d\'Incident de Sécurité\\n\\n'\n    for alert in alerts:\n        report += f\"ID d'alerte: {alert['id']}\\nID de règle: {alert['rule']['id']}\\nDescription: {alert['rule']['description']}\\nAgent: {alert['agent']['name']}\\nHorodatage: {alert['timestamp']}\\n\\n\"\n    return {'report': report}"
                }
            },
            {
                "id": "4",
                "app_id": "email",
                "action": "send_email",
                "name": "Envoyer le rapport par email",
                "parameters": {
                    "to": "$INCIDENT_EMAIL",
                    "subject": "Rapport d'Incident de Sécurité",
                    "body": "{{node.3.report}}"
                }
            }
        ],
        "edges": [
            {"source": "1", "target": "2"},
            {"source": "2", "target": "3"},
            {"source": "3", "target": "4"}
        ]
    }
}
EOF
)

# Importer le workflow pour les incidents sur les terminaux
TERMINAL_WORKFLOW_RESPONSE=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d "$WORKFLOW_TERMINAL")

TERMINAL_WORKFLOW_ID=$(echo "$TERMINAL_WORKFLOW_RESPONSE" | jq -r '.workflow_id')

if [ "$TERMINAL_WORKFLOW_ID" == "null" ]; then
    echo "Erreur : Échec de l'importation du workflow des incidents sur les terminaux."
else
    echo "Workflow des incidents sur les terminaux importé avec succès. ID: $TERMINAL_WORKFLOW_ID"
fi

# Importer le workflow pour les incidents réseau
RESEAU_WORKFLOW_RESPONSE=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d "$WORKFLOW_RESEAU")

RESEAU_WORKFLOW_ID=$(echo "$RESEAU_WORKFLOW_RESPONSE" | jq -r '.workflow_id')

if [ "$RESEAU_WORKFLOW_ID" == "null" ]; then
    echo "Erreur : Échec de l'importation du workflow des incidents réseau."
else
    echo "Workflow des incidents réseau importé avec succès. ID: $RESEAU_WORKFLOW_ID"
fi

# Importer le workflow de rapport d'incident
INCIDENT_REPORT_WORKFLOW_RESPONSE=$(curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d "$WORKFLOW_INCIDENT_REPORT")

INCIDENT_REPORT_WORKFLOW_ID=$(echo "$INCIDENT_REPORT_WORKFLOW_RESPONSE" | jq -r '.workflow_id')

if [ "$INCIDENT_REPORT_WORKFLOW_ID" == "null" ]; then
    echo "Erreur : Échec de l'importation du workflow de rapport d'incident."
else
    echo "Workflow de rapport d'incident importé avec succès. ID: $INCIDENT_REPORT_WORKFLOW_ID"
fi

# Activer les workflows pour qu'ils s'exécutent à interval régulier
echo ">>> Activation des workflows pour une exécution programmée..."

# Pour le workflow des incidents sur les terminaux
curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows/$TERMINAL_WORKFLOW_ID/schedule" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "interval": "5m"
    }'

# Pour le workflow des incidents réseau
curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows/$RESEAU_WORKFLOW_ID/schedule" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "interval": "5m"
    }'

# Activer le workflow de rapport d'incident pour une exécution programmée
curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows/$INCIDENT_REPORT_WORKFLOW_ID/schedule" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "interval": "5m"
    }'

echo ">>> Workflow de rapport d'incident activé avec succès."

echo ">>> Workflows activés avec succès."

# 5. Finalisation

echo "-----------------------------------------------------------"
echo "       CONFIGURATION POST INSTALLATION TERMINÉE           "
echo "-----------------------------------------------------------"

echo "Vous pouvez maintenant accéder à votre plateforme et utiliser les fonctionnalités configurées."

exit 0
