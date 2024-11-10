#!/bin/bash

clear

# 1. DÉBUT DE L'INSTALLATION
echo "''*************************************************''"
echo "''                                                 ''"
echo "''   RESPONSE UNIFIED PREVENTION & ANALYSIS SYSTEM ''"
echo "''                V1.1.6                           ''"
echo "''                                                 ''"
echo "''*************************************************''"

cat <<\EOF

 ____    __  __  ____    ______                      
/\  _`\ /\ \/\ \/\  _`\ /\  _  \                     
\ \ \L\ \ \ \ \ \ \ \L\ \ \ \L\ \                    
 \ \ ,  /\ \ \ \ \ \ ,__/\ \  __ \                   
  \ \ \\ \\ \ \_\ \ \ \/  \ \ \/\ \                  
   \ \_\ \_\ \_____\ \_\   \ \_\ \_\                 
    \/_/\/ /\/_____/\/_/    \/_/\/_/                 
                                                     
                                                     
 ____                     __                         
/\  _`\                  /\ \__                      
\ \,\L\_\  __  __    ____\ \ ,_\    __    ___ ___    
 \/_\__ \ /\ \/\ \  /',__\\ \ \/  /'__`\/' __` __`\  
   /\ \L\ \ \ \_\ \/\__, `\\ \ \_/\  __//\ \/\ \/\ \ 
   \ `\____\/`____ \/\____/ \ \__\ \____\ \_\ \_\ \_\
    \/_____/`/___/> \/___/   \/__/\/____/\/_/\/_/\/_/
               /\___/                                
               \/__/                                 


EOF



echo "-----------------------------------------------------"
echo "           INITIATION DE L'INSTALLATION              "
echo "-----------------------------------------------------"

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    echo "Veuillez exécuter ce script en tant que root (sudo)."
    exit 1
fi

# 2. Mise à jour du système
echo ">>> Mise à jour du système..."
apt update -y && apt upgrade -y

# 3. Appliquer la configuration sysctl
echo ">>> Configuration du paramètre vm.max_map_count..."
sysctl -w vm.max_map_count=262144
sysctl -p

# Rendre la configuration persistante
echo ">>> Rendre vm.max_map_count=262144 persistant..."
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
fi

# 4. Installation des prérequis
echo ">>> Installation des prérequis..."
apt install -y gnome-terminal ca-certificates curl gnupg lsb-release openssl

# 5. Installation de Docker
echo ">>> Installation de Docker..."

# Vérifier si Docker est déjà installé
if ! command -v docker &> /dev/null; then
    # Ajouter la clé GPG officielle de Docker
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Ajouter le dépôt Docker aux sources APT
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

    # Mettre à jour les paquets APT
    apt update

    # Installer Docker et Docker Compose
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-compose

    # Vérifier l'installation de Docker
    echo ">>> Vérification de l'installation de Docker..."
    if ! command -v docker &> /dev/null; then
        echo "Docker n'a pas pu être installé. Veuillez vérifier les erreurs précédentes."
        exit 1
    else
        echo "Docker installé avec succès."
    fi

    # Ajouter l'utilisateur actuel au groupe docker
    usermod -aG docker "$USER"
else
    echo "Docker est déjà installé. Skipping installation."
fi

# 6. Télécharger les images Docker nécessaires
echo ">>> Téléchargement des images Docker requises..."

IMAGES=(
    "wazuh/wazuh-manager:4.9.2"
    "wazuh/wazuh-indexer:4.9.2"
    "wazuh/wazuh-dashboard:4.9.2"
    "nginx:latest"
    "ghcr.io/shuffle/shuffle-frontend:latest"
    "ghcr.io/shuffle/shuffle-backend:latest"
    "ghcr.io/shuffle/shuffle-orborus:latest"
    "opensearchproject/opensearch:2.14.0"
    "jasonish/evebox:latest"
    "rupadante/suricata-wazuh:latest"
    "rupadante/wazuh-certs-generator:0.0.2"
)

for IMAGE in "${IMAGES[@]}"; do
    if [[ "$(docker images -q "$IMAGE" 2> /dev/null)" == "" ]]; then
        docker pull "$IMAGE"
    else
        echo "Image \"$IMAGE\" déjà présente localement."
    fi
done

echo "-----------------------------------------------------------"
echo "   PRÉREQUIS INSTALLÉS ET IMAGES DOCKER PRÊTES             "
echo "-----------------------------------------------------------"

# 8. Création des variables globales et des dossiers nécessaires

# Déclarer un tableau pour stocker les variables globales
declare -A GLOBAL_VARS

echo ">>> Création des dossiers nécessaires..."

# Créer le dossier ./shuffle/shuffle-database
echo ">>> Création du dossier ./shuffle/shuffle-database..."
mkdir -p shuffle/shuffle-database
chown -R 1000:1000 shuffle/shuffle-database

# Désactiver le swap
echo ">>> Désactivation du swap..."
swapoff -a

# Vérifier et ajouter l'utilisateur 'opensearch' si nécessaire
if ! id "opensearch" &>/dev/null; then
    useradd opensearch
fi

# Générer les certificats auto-signés pour Wazuh
echo ">>> Génération des certificats auto-signés pour Wazuh..."
docker-compose -f wazuh/generate-indexer-certs.yml run --rm generator

# Créer le répertoire ./reverse_proxy/nginx/ssl
echo ">>> Création du répertoire ./reverse_proxy/nginx/ssl..."
mkdir -p reverse_proxy/nginx/ssl

# Demander les informations pour le certificat SSL
echo ">>> Génération des certificats SSL pour le portail RUPA..."

read -r -p "Entrez le nom de votre organisation : " ORG_NAME
GLOBAL_VARS["ORG_NAME"]=$ORG_NAME

read -r -p "Entrez le nom de votre unité organisationnelle : " ORG_UNIT
GLOBAL_VARS["ORG_UNIT"]=$ORG_UNIT

read -r -p "Entrez votre adresse e-mail : " EMAIL_ADDRESS
GLOBAL_VARS["EMAIL_ADDRESS"]=$EMAIL_ADDRESS

# Générer le certificat SSL auto-signé
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout reverse_proxy/nginx/ssl/rupa_portal.key \
    -out reverse_proxy/nginx/ssl/rupa_portal.crt \
    -subj "/C=CM/ST=CENTRE/L=YAOUNDE/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=localhost/emailAddress=${EMAIL_ADDRESS}"

# 9. Gestion des interfaces réseau

echo ">>> Détection des interfaces réseau disponibles..."

# Lister les interfaces réseau Ethernet disponibles
mapfile -t ETH_INTERFACES < <(find /sys/class/net -maxdepth 1 -regex ".*/\(\(e\|en\|eth\)[a-z0-9]*\)$" -exec basename {} \;)

if [ ${#ETH_INTERFACES[@]} -lt 2 ]; then
    echo "Erreur : Au moins deux interfaces réseau Ethernet sont requises."
    exit 1
fi

echo "Interfaces réseau Ethernet disponibles :"
for i in "${!ETH_INTERFACES[@]}"; do
    echo "[$i] ${ETH_INTERFACES[$i]}"
done

# Demander à l'utilisateur de choisir l'interface pour Suricata
read -r -p "Entrez le numéro de l'interface à utiliser pour Suricata : " SURICATA_IF_INDEX
while ! [[ "$SURICATA_IF_INDEX" =~ ^[0-9]+$ ]] || [ "$SURICATA_IF_INDEX" -lt 0 ] || [ "$SURICATA_IF_INDEX" -ge ${#ETH_INTERFACES[@]} ]; do
    echo "Numéro d'interface invalide. Veuillez réessayer."
    read -r -p "Entrez le numéro de l'interface à utiliser pour Suricata : " SURICATA_IF_INDEX
done

SURICATA_INTERFACE=${ETH_INTERFACES[$SURICATA_IF_INDEX]}
GLOBAL_VARS["INTERFACE_RESEAU"]=$SURICATA_INTERFACE

# Récupérer les informations de l'interface Suricata
SURICATA_IP=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}' | cut -d/ -f1)
SURICATA_SUBNET=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}')
SURICATA_GATEWAY=$(ip route | grep "dev $SURICATA_INTERFACE" | grep default | awk '{print $3}')

GLOBAL_VARS["WAZUH_SURICATA_IP"]=$SURICATA_IP
GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]=$SURICATA_SUBNET
GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]=$SURICATA_GATEWAY

# Retirer l'interface sélectionnée de la liste
temp_array=()
for i in "${!ETH_INTERFACES[@]}"; do
    # Ajouter tous les éléments sauf celui à l'index $SURICATA_IF_INDEX
    if [[ $i -ne $SURICATA_IF_INDEX ]]; then
        temp_array+=("${ETH_INTERFACES[i]}")
    fi
done

# Réassigner le tableau sans découpage
ETH_INTERFACES=("${temp_array[@]}")

# Demander à l'utilisateur de choisir l'interface pour les autres services
echo "Interfaces réseau restantes pour les autres services :"
for i in "${!ETH_INTERFACES[@]}"; do
    echo "[$i] ${ETH_INTERFACES[$i]}"
done

read -r -p "Entrez le numéro de l'interface à utiliser pour les autres services : " SERVICES_IF_INDEX
while ! [[ "$SERVICES_IF_INDEX" =~ ^[0-9]+$ ]] || [ "$SERVICES_IF_INDEX" -lt 0 ] || [ "$SERVICES_IF_INDEX" -ge ${#ETH_INTERFACES[@]} ]; do
    echo "Numéro d'interface invalide. Veuillez réessayer."
    read -r -p "Entrez le numéro de l'interface à utiliser pour les autres services : " SERVICES_IF_INDEX
done

SERVICES_INTERFACE=${ETH_INTERFACES[$SERVICES_IF_INDEX]}

# Récupérer l'adresse IP de l'interface des services
SERVICES_IP=$(ip -o -f inet addr show "$SERVICES_INTERFACE" | awk '{print $4}' | cut -d/ -f1)
GLOBAL_VARS["WAZUH_MANAGER_IP"]=$SERVICES_IP

# Récupérer le PUID et PGID de l'utilisateur actuel
PUID=$(id -u)
PGID=$(id -g)
GLOBAL_VARS["PUID"]=$PUID
GLOBAL_VARS["PGID"]=$PGID

# 10. Création du fichier .env local

echo ">>> Création du fichier .env à la racine du projet..."

cat > .env <<EOF
####################### Reverse_Proxy #######################
NGINX_HOST=localhost
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443

####################### WAZUH #######################
# Variables pour le Wazuh Manager
INDEXER_URL=https://wazuh.indexer:9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=SecretPassword
API_USERNAME=wazuh-wui
API_PASSWORD=MyS3cr37P450r.*-

# Variables pour la sécurité des certificats SSL
FILEBEAT_SSL_VERIFICATION_MODE=full
SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
SSL_CERTIFICATE=/etc/ssl/filebeat.pem
SSL_KEY=/etc/ssl/filebeat.key

# Variables pour le Wazuh Dashboard
WAZUH_API_URL=https://wazuh.manager
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=kibanaserver

# Variables pour Suricata Wazuh
WAZUH_MANAGER_IP=${GLOBAL_VARS["WAZUH_MANAGER_IP"]}
WAZUH_SURICATA_IP=${GLOBAL_VARS["WAZUH_SURICATA_IP"]}
WAZUH_SURICATA_SUBNET=${GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]}
WAZUH_SURICATA_GATEWAY=${GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]}
INTERFACE_RESEAU=${GLOBAL_VARS["INTERFACE_RESEAU"]}
PUID=${GLOBAL_VARS["PUID"]}
PGID=${GLOBAL_VARS["PGID"]}

####################### SHUFFLE #######################
# Default execution environment for workers
ORG_ID=Shuffle
ENVIRONMENT_NAME=RUPA_Shuffle

# Sanitize liquid.py input
LIQUID_SANITIZE_INPUT=true

# Remote github config for first load
SHUFFLE_DOWNLOAD_WORKFLOW_LOCATION=
SHUFFLE_DOWNLOAD_WORKFLOW_USERNAME=
SHUFFLE_DOWNLOAD_WORKFLOW_PASSWORD=
SHUFFLE_DOWNLOAD_WORKFLOW_BRANCH=

SHUFFLE_APP_DOWNLOAD_LOCATION=https://github.com/shuffle/python-apps
SHUFFLE_DOWNLOAD_AUTH_USERNAME=
SHUFFLE_DOWNLOAD_AUTH_PASSWORD=
SHUFFLE_DOWNLOAD_AUTH_BRANCH=
SHUFFLE_APP_FORCE_UPDATE=false

# User config for first load. Username & PW: min length 3
SHUFFLE_DEFAULT_USERNAME=admin
SHUFFLE_DEFAULT_PASSWORD=admin
SHUFFLE_DEFAULT_APIKEY=

# Local location of your app directory. Can't use ~/
SHUFFLE_APP_HOTLOAD_FOLDER=./shuffle/shuffle-apps
SHUFFLE_APP_HOTLOAD_LOCATION=./shuffle/shuffle-apps
SHUFFLE_FILE_LOCATION=./shuffle/shuffle-files

# Encryption modifier
SHUFFLE_ENCRYPTION_MODIFIER=

# Other configs
BASE_URL=http://shuffle-backend:5001
SSO_REDIRECT_URL=http://localhost:3001
BACKEND_HOSTNAME=shuffle-backend
BACKEND_PORT=5001
FRONTEND_PORT=3001
FRONTEND_PORT_HTTPS=3443

OUTER_HOSTNAME=shuffle-backend
DB_LOCATION=./shuffle/shuffle-database
DOCKER_API_VERSION=1.40

# Orborus/Proxy configurations
HTTP_PROXY=
HTTPS_PROXY=
SHUFFLE_PASS_WORKER_PROXY=TRUE
SHUFFLE_PASS_APP_PROXY=TRUE
SHUFFLE_INTERNAL_HTTP_PROXY=NOPROXY
SHUFFLE_INTERNAL_HTTPS_PROXY=NOPROXY
TZ=Europe/Amsterdam
ORBORUS_CONTAINER_NAME=
SHUFFLE_ORBORUS_STARTUP_DELAY=
SHUFFLE_SKIPSSL_VERIFY=true
IS_KUBERNETES=false

SHUFFLE_BASE_IMAGE_NAME=shuffle
SHUFFLE_BASE_IMAGE_REGISTRY=ghcr.io
SHUFFLE_BASE_IMAGE_REPOSITORY=frikky
SHUFFLE_BASE_IMAGE_TAG_SUFFIX=latest

SHUFFLE_SWARM_BRIDGE_DEFAULT_INTERFACE=eth0
SHUFFLE_SWARM_BRIDGE_DEFAULT_MTU=1500

SHUFFLE_MEMCACHED=
SHUFFLE_CONTAINER_AUTO_CLEANUP=true
SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=5
SHUFFLE_HEALTHCHECK_DISABLED=false
SHUFFLE_ELASTIC=true
SHUFFLE_LOGS_DISABLED=false
SHUFFLE_CHAT_DISABLED=false
SHUFFLE_DISABLE_RERUN_AND_ABORT=false
SHUFFLE_RERUN_SCHEDULE=300
SHUFFLE_WORKER_SERVER_URL=
SHUFFLE_ORBORUS_PULL_TIME=
SHUFFLE_MAX_EXECUTION_DEPTH=

# DATABASE CONFIGURATIONS
DATASTORE_EMULATOR_HOST=shuffle-database:8000
SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200
SHUFFLE_OPENSEARCH_USERNAME="admin"
SHUFFLE_OPENSEARCH_PASSWORD="StrongShufflePassword321!"
SHUFFLE_OPENSEARCH_CERTIFICATE_FILE=
SHUFFLE_OPENSEARCH_APIKEY=
SHUFFLE_OPENSEARCH_CLOUDID=
SHUFFLE_OPENSEARCH_PROXY=
SHUFFLE_OPENSEARCH_INDEX_PREFIX=
SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true

# Tenzir related
SHUFFLE_TENZIR_URL=

DEBUG_MODE=false
EOF

echo "Fichier .env créé avec succès."

# 11. Mise à jour du fichier suricata.yaml

echo ">>> Mise à jour du fichier suricata.yaml avec l'adresse IP de Suricata..."

SURICATA_YAML_PATH="wazuh/config/wazuh_suricata/suricata.yaml"

if [ -f "$SURICATA_YAML_PATH" ]; then
    sed -i "s/\${SURICATA_IP}/${GLOBAL_VARS["WAZUH_SURICATA_IP"]}\/24/g" "$SURICATA_YAML_PATH"
    echo "suricata.yaml mis à jour."
else
    echo "Erreur : Le fichier suricata.yaml n'a pas été trouvé à l'emplacement $SURICATA_YAML_PATH."
fi

echo "-----------------------------------------------------------"
echo "   CONFIGURATION TERMINÉE. PRÊT POUR LE DÉPLOIEMENT.      "
echo "-----------------------------------------------------------"

# 12. Lancement de la plateforme Docker
echo ">>> Lancement de la plateforme Docker..."
docker-compose up -d

echo ">>> Attente du démarrage des conteneurs..."
sleep 360 # Attendre 6 minutes

# 13. Vérification que tous les conteneurs fonctionnent correctement

echo ">>> Vérification de l'état des conteneurs Docker..."

# Récupérer la liste des conteneurs définis dans docker-compose
CONTAINERS=$(docker-compose ps -q)

# Initialiser un indicateur d'erreur
ERROR_FOUND=0

for CONTAINER_ID in $CONTAINERS; do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$CONTAINER_ID" | sed 's/^\///')
    CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_ID")
    if [ "$CONTAINER_STATUS" != "running" ]; then
        echo "Le conteneur $CONTAINER_NAME n'est pas en cours d'exécution (état : $CONTAINER_STATUS)."
        ERROR_FOUND=1
    else
        echo "Le conteneur $CONTAINER_NAME est en cours d'exécution."
    fi
done

if [ $ERROR_FOUND -eq 1 ]; then
    echo "Erreur : Un ou plusieurs conteneurs ne fonctionnent pas correctement."
    echo "Veuillez vérifier les logs des conteneurs avec 'docker-compose logs' pour plus d'informations."
    exit 1
else
    echo "Tous les conteneurs fonctionnent correctement."
fi

echo "-----------------------------------------------------------"
echo "           CONFIGURATION POST - DÉPLOIEMENT               "
echo "-----------------------------------------------------------"

# 14. Demander à l'utilisateur s'il souhaite effectuer les configurations post-installation

read -r -p "Souhaitez-vous effectuer les configurations post-installation maintenant ? (y/n) : " POST_INSTALL_CHOICE

# Validation de l'entrée utilisateur
while [[ ! "$POST_INSTALL_CHOICE" =~ ^[YyNn]$ ]]; do
    echo "Veuillez entrer 'y' pour oui ou 'n' pour non."
    read -r -p "Souhaitez-vous effectuer les configurations post-installation maintenant ? (y/n) : " POST_INSTALL_CHOICE
done

if [[ "$POST_INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
    echo ">>> Début des configurations post-installation..."
else
    echo ">>> Configuration post-installation ignorée."
    echo "Installation terminée."

    # 20. Affichage des identifiants par défaut et du message de fin

echo "-----------------------------------------------------------"
echo "        INSTALLATION TERMINÉE AVEC SUCCÈS                  "
echo "-----------------------------------------------------------"

# Affichage de l'ASCII art de remerciement

cat <<\EOF                   
 __                                                         
/\ \                             __                         
\ \ \         __     __   __  __/\_\  _____      __         
 \ \ \  __  /'__`\ /'__`\/\ \/\ \/\ \/\ '__`\  /'__`\       
  \ \ \L\ \/\  __//\ \L\ \ \ \_\ \ \ \ \ \L\ \/\  __/       
   \ \____/\ \____\ \___, \ \____/\ \_\ \ ,__/\ \____\      
    \/___/  \/____/\/___/\ \/___/  \/_/\ \ \/  \/____/      
                        \ \_\           \ \_\               
                         \/_/            \/_/               
  __          ____    __  __  ____    ______        __      
 _\ \ _      /\  _`\ /\ \/\ \/\  _`\ /\  _  \      _\ \ _   
/\_` ' \     \ \ \L\ \ \ \ \ \ \ \L\ \ \ \L\ \    /\_` ' \  
\/_>   <_     \ \ ,  /\ \ \ \ \ \ ,__/\ \  __ \   \/_>   <_ 
  /\_, ,_\     \ \ \\ \\ \ \_\ \ \ \/  \ \ \/\ \    /\_, ,_\
  \/_/\_\/      \ \_\ \_\ \_____\ \_\   \ \_\ \_\   \/_/\_\/
     \/_/        \/_/\/ /\/_____/\/_/    \/_/\/_/      \/_/                                     
 ____                     __                                
/\  _`\                  /\ \__                             
\ \,\L\_\  __  __    ____\ \ ,_\    __    ___ ___           
 \/_\__ \ /\ \/\ \  /',__\\ \ \/  /'__`\/' __` __`\         
   /\ \L\ \ \ \_\ \/\__, `\\ \ \_/\  __//\ \/\ \/\ \        
   \ `\____\/`____ \/\____/ \ \__\ \____\ \_\ \_\ \_\       
    \/_____/`/___/> \/___/   \/__/\/____/\/_/\/_/\/_/       
               /\___/                                       
               \/__/                                        
 __  __                                                     
/\ \/\ \                                                    
\ \ \ \ \    ___   __  __    ____                           
 \ \ \ \ \  / __`\/\ \/\ \  /',__\                          
  \ \ \_/ \/\ \L\ \ \ \_\ \/\__, `\                         
   \ `\___/\ \____/\ \____/\/\____/                         
    `\/__/  \/___/  \/___/  \/___/                                                                                
                                             __             
 _ __    __    ___ ___      __   _ __   ___ /\_\     __     
/\`'__\/'__`\/' __` __`\  /'__`\/\`'__\/'___\/\ \  /'__`\   
\ \ \//\  __//\ \/\ \/\ \/\  __/\ \ \//\ \__/\ \ \/\  __/   
 \ \_\\ \____\ \_\ \_\ \_\ \____\\ \_\\ \____\\ \_\ \____\  
  \/_/ \/____/\/_/\/_/\/_/\/____/ \/_/ \/____/ \/_/\/____/ 
--------------------------------------------------------------
EOF

echo "Accédez à la plateforme via : https://${SERVICES_IP}"

echo "Identifiants WAZUH par défaut :"
echo "Nom d'utilisateur : admin"
echo "Mot de passe : SecretPassword"

echo "Identifiants SHUFFLE par défaut :"
echo "Nom d'utilisateur : $SHUFFLE_DEFAULT_USERNAME"
echo "Mot de passe : $SHUFFLE_DEFAULT_PASSWORD"

echo "Merci d'avoir installé RUPA System !"

    exit 0
fi

# 15. Configuration des e-mails dans Wazuh

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

# 16. Appliquer la configuration des e-mails dans Wazuh

echo ">>> Application de la configuration des e-mails dans Wazuh..."

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

echo ">>> Configuration presque terminée."
sleep 30

echo ">>> Configuration des e-mails dans Wazuh terminée."

# 17. Envoi d'un e-mail de test

echo ">>> Envoi d'un e-mail de test..."

# Exécuter la commande sendmail pour tester
docker exec -it wazuh.manager bash -c "echo 'Test e-mail from Wazuh Manager' | mail -s 'Wazuh Test Email' '${EMAIL_TO}'"

echo "Un e-mail de test a été envoyé à ${EMAIL_TO}. Veuillez vérifier votre boîte de réception."
echo "Remarque : Si l'envoi de l'e-mail de test échoue, veuillez vérifier la configuration SMTP et les logs du conteneur wazuh.manager."
echo "Ou reconfigurer Wazuh pour l'envoi de mails via le dashboard."

# 18. Création de workflows de réponse dans Shuffle

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

# 19. Préconfiguration des workflows dans Shuffle

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
                    "code": "def handler(inputs, data):\n    alerts = inputs['relevant_alerts']\n    report = 'Rapport d'Incident de Sécurité\\n\\n'\n    for alert in alerts:\n        report += f\"ID d'alerte: {alert['id']}\\nID de règle: {alert['rule']['id']}\\nDescription: {alert['rule']['description']}\\nAgent: {alert['agent']['name']}\\nHorodatage: {alert['timestamp']}\\n\\n\"\n    return {'report': report}"
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

# Importer le workflow dans Shuffle
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

# Activer le workflow pour une exécution programmée
echo ">>> Activation du workflow de rapport d'incident pour une exécution programmée..."

curl -s -X POST "$SHUFFLE_BACKEND_URL/api/v1/workflows/$INCIDENT_REPORT_WORKFLOW_ID/schedule" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -d '{
        "interval": "5m"
    }'

echo ">>> Workflow de rapport d'incident activé avec succès."

echo ">>> Workflows activés avec succès."


# 20. Affichage des identifiants par défaut et du message de fin

echo "-----------------------------------------------------------"
echo "        INSTALLATION TERMINÉE AVEC SUCCÈS                  "
echo "-----------------------------------------------------------"

# Affichage de l'ASCII art de remerciement

cat <<\EOF                   
 __                                                         
/\ \                             __                         
\ \ \         __     __   __  __/\_\  _____      __         
 \ \ \  __  /'__`\ /'__`\/\ \/\ \/\ \/\ '__`\  /'__`\       
  \ \ \L\ \/\  __//\ \L\ \ \ \_\ \ \ \ \ \L\ \/\  __/       
   \ \____/\ \____\ \___, \ \____/\ \_\ \ ,__/\ \____\      
    \/___/  \/____/\/___/\ \/___/  \/_/\ \ \/  \/____/      
                        \ \_\           \ \_\               
                         \/_/            \/_/               
  __          ____    __  __  ____    ______        __      
 _\ \ _      /\  _`\ /\ \/\ \/\  _`\ /\  _  \      _\ \ _   
/\_` ' \     \ \ \L\ \ \ \ \ \ \ \L\ \ \ \L\ \    /\_` ' \  
\/_>   <_     \ \ ,  /\ \ \ \ \ \ ,__/\ \  __ \   \/_>   <_ 
  /\_, ,_\     \ \ \\ \\ \ \_\ \ \ \/  \ \ \/\ \    /\_, ,_\
  \/_/\_\/      \ \_\ \_\ \_____\ \_\   \ \_\ \_\   \/_/\_\/
     \/_/        \/_/\/ /\/_____/\/_/    \/_/\/_/      \/_/                                     
 ____                     __                                
/\  _`\                  /\ \__                             
\ \,\L\_\  __  __    ____\ \ ,_\    __    ___ ___           
 \/_\__ \ /\ \/\ \  /',__\\ \ \/  /'__`\/' __` __`\         
   /\ \L\ \ \ \_\ \/\__, `\\ \ \_/\  __//\ \/\ \/\ \        
   \ `\____\/`____ \/\____/ \ \__\ \____\ \_\ \_\ \_\       
    \/_____/`/___/> \/___/   \/__/\/____/\/_/\/_/\/_/       
               /\___/                                       
               \/__/                                        
 __  __                                                     
/\ \/\ \                                                    
\ \ \ \ \    ___   __  __    ____                           
 \ \ \ \ \  / __`\/\ \/\ \  /',__\                          
  \ \ \_/ \/\ \L\ \ \ \_\ \/\__, `\                         
   \ `\___/\ \____/\ \____/\/\____/                         
    `\/__/  \/___/  \/___/  \/___/                                                                                
                                             __             
 _ __    __    ___ ___      __   _ __   ___ /\_\     __     
/\`'__\/'__`\/' __` __`\  /'__`\/\`'__\/'___\/\ \  /'__`\   
\ \ \//\  __//\ \/\ \/\ \/\  __/\ \ \//\ \__/\ \ \/\  __/   
 \ \_\\ \____\ \_\ \_\ \_\ \____\\ \_\\ \____\\ \_\ \____\  
  \/_/ \/____/\/_/\/_/\/_/\/____/ \/_/ \/____/ \/_/\/____/ 
--------------------------------------------------------------
EOF

echo "Accédez à la plateforme via : https://${SERVICES_IP}"

echo "Identifiants WAZUH par défaut :"
echo "Nom d'utilisateur : admin"
echo "Mot de passe : SecretPassword"

echo "Identifiants SHUFFLE par défaut :"
echo "Nom d'utilisateur : $SHUFFLE_DEFAULT_USERNAME"
echo "Mot de passe : $SHUFFLE_DEFAULT_PASSWORD"

echo "Merci d'avoir installé RUPA System !"
