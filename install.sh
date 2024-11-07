#!/bin/bash

# 1. DEBUT DE L'INSTALLATION
echo "''*************************************************''";
echo "''                                                 ''";
echo "''   RESPONSE UNIFIED PREVENTION & ANALYSIS SYSTEM ''";
echo "''                V1.1.6                           ''";
echo "''                                                 ''";
echo "''*************************************************''";
echo "
echo " ____    __  __  ____    ______                      ";
echo "/\  _`\ /\ \/\ \/\  _`\ /\  _  \                     ";
echo "\ \ \L\ \ \ \ \ \ \ \L\ \ \ \L\ \                    ";
echo " \ \ ,  /\ \ \ \ \ \ ,__/\ \  __ \                   ";
echo "  \ \ \\ \\ \ \_\ \ \ \/  \ \ \/\ \                  ";
echo "   \ \_\ \_\ \_____\ \_\   \ \_\ \_\                 ";
echo "    \/_/\/ /\/_____/\/_/    \/_/\/_/                 ";
echo "                                                     ";
echo "                                                     ";
echo " ____                     __                         ";
echo "/\  _`\                  /\ \__                      ";
echo "\ \,\L\_\  __  __    ____\ \ ,_\    __    ___ ___    ";
echo " \/_\__ \ /\ \/\ \  /',__\\ \ \/  /'__`\/' __` __`\  ";
echo "   /\ \L\ \ \ \_\ \/\__, `\\ \ \_/\  __//\ \/\ \/\ \ ";
echo "   \ `\____\/`____ \/\____/ \ \__\ \____\ \_\ \_\ \_\";
echo "    \/_____/`/___/> \/___/   \/__/\/____/\/_/\/_/\/_/";
echo "               /\___/                                ";
echo "               \/__/                                 ";

echo "-----------------------------------------------------"
echo "           INITIATION DE L'INSTALLATION              "
echo "-----------------------------------------------------"

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
  echo "Veuillez exécuter ce script en tant que root (sudo)."
  exit
fi

# 2. Mise à jour du système
echo ">>> Mise à jour du système..."
sudo apt update -y && sudo apt upgrade -y

# 3. Appliquer la configuration sysctl
echo ">>> Configuration du paramètre vm.max_map_count..."
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -p

# Rendre la configuration persistante
echo ">>> Rendre vm.max_map_count=262144 persistant..."
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
fi

# 4. Installation des prérequis
echo ">>> Installation des prérequis..."
sudo apt install -y gnome-terminal ca-certificates curl gnupg lsb-release openssl

# 5. Installation de Docker
echo ">>> Installation de Docker..."

# Ajouter la clé GPG officielle de Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Ajouter le dépôt Docker aux sources APT
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Mettre à jour les paquets APT
sudo apt update

# Installer Docker et Docker Compose
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-compose

# Vérifier l'installation de Docker
echo ">>> Vérification de l'installation de Docker..."
if ! command -v docker &> /dev/null; then
    echo "Docker n'a pas pu être installé. Veuillez vérifier les erreurs précédentes."
    exit 1
else
    echo "Docker installé avec succès."
fi

# Ajouter l'utilisateur actuel au groupe docker
sudo usermod -aG docker $USER

# 6. Télécharger les images Docker nécessaires
echo ">>> Téléchargement des images Docker requises..."
docker pull wazuh/wazuh-manager:4.9.2
docker pull wazuh/wazuh-indexer:4.9.2
docker pull wazuh/wazuh-dashboard:4.9.2
docker pull nginx:latest
docker pull ghcr.io/shuffle/shuffle-frontend:latest
docker pull ghcr.io/shuffle/shuffle-backend:latest
docker pull ghcr.io/shuffle/shuffle-orborus:latest
docker pull opensearchproject/opensearch:2.14.0
docker pull jasonish/evebox:latest

# 7. Construire les images personnalisées
echo ">>> Construction des images Docker personnalisées..."

# Vérifier si le Dockerfile pour suricata-wazuh existe
if [ -f "./build_suricata-wazuh/dockerfile" ]; then
  docker build -t rupa/suricata-wazuh ./build_suricata-wazuh/
else
  echo "Dockerfile pour suricata-wazuh introuvable. Skipping build."
fi

# Vérifier si le Dockerfile pour wazuh/wazuh-certs-generator:0.0.1 existe
if [ -f "./wazuh/Dockerfile" ]; then
  docker build -t wazuh/wazuh-certs-generator:0.0.1 ./wazuh
else
  echo "Dockerfile pour wazuh/wazuh-certs-generator:0.0.1 introuvable. Skipping build."
fi

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
sudo chown -R 1000:1000 shuffle/shuffle-database

# Désactiver le swap
echo ">>> Désactivation du swap..."
sudo swapoff -a

# Vérifier et ajouter l'utilisateur 'opensearch' si nécessaire
if ! id "opensearch" &>/dev/null; then
    sudo useradd opensearch
fi

# Générer les certificats auto-signés pour Wazuh
echo ">>> Génération des certificats auto-signés pour Wazuh..."
docker-compose -f wazuh/generate-indexer-certs.yml run --rm generator

# Créer le répertoire ./reverse_proxy/nginx/ssl
echo ">>> Création du répertoire ./reverse_proxy/nginx/ssl..."
mkdir -p reverse_proxy/nginx/ssl

# Demander les informations pour le certificat SSL
echo ">>> Génération des certificats SSL pour le portail RUPA..."

read -p "Entrez le nom de votre organisation : " ORG_NAME
GLOBAL_VARS["ORG_NAME"]=$ORG_NAME

read -p "Entrez le nom de votre unité organisationnelle : " ORG_UNIT
GLOBAL_VARS["ORG_UNIT"]=$ORG_UNIT

read -p "Entrez votre adresse e-mail : " EMAIL_ADDRESS
GLOBAL_VARS["EMAIL_ADDRESS"]=$EMAIL_ADDRESS

# Générer le certificat SSL auto-signé
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout reverse_proxy/nginx/ssl/rupa_portal.key \
    -out reverse_proxy/nginx/ssl/rupa_portal.crt \
    -subj "/C=CM/ST=CENTRE/L=YAOUNDE/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=localhost/emailAddress=${EMAIL_ADDRESS}"

# 9. Gestion des interfaces réseau

echo ">>> Détection des interfaces réseau disponibles..."

# Lister les interfaces réseau Ethernet disponibles
ETH_INTERFACES=($(ls /sys/class/net | grep -E '^(e|en|eth)[a-z0-9]+$'))

if [ ${#ETH_INTERFACES[@]} -lt 2 ]; then
    echo "Erreur : Au moins deux interfaces réseau Ethernet sont requises."
    exit 1
fi

echo "Interfaces réseau Ethernet disponibles :"
for i in "${!ETH_INTERFACES[@]}"; do
    echo "[$i] ${ETH_INTERFACES[$i]}"
done

# Demander à l'utilisateur de choisir l'interface pour Suricata
read -p "Entrez le numéro de l'interface à utiliser pour Suricata : " SURICATA_IF_INDEX
SURICATA_INTERFACE=${ETH_INTERFACES[$SURICATA_IF_INDEX]}
GLOBAL_VARS["INTERFACE_RESEAU"]=$SURICATA_INTERFACE

# Récupérer les informations de l'interface Suricata
SURICATA_IP=$(ip -o -f inet addr show $SURICATA_INTERFACE | awk '{print $4}' | cut -d/ -f1)
SURICATA_SUBNET=$(ip -o -f inet addr show $SURICATA_INTERFACE | awk '{print $4}')
SURICATA_GATEWAY=$(ip route | grep "dev $SURICATA_INTERFACE" | grep default | awk '{print $3}')

GLOBAL_VARS["WAZUH_SURICATA_IP"]=$SURICATA_IP
GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]=$SURICATA_SUBNET
GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]=$SURICATA_GATEWAY

# Retirer l'interface sélectionnée de la liste
ETH_INTERFACES=(${ETH_INTERFACES[@]:0:$SURICATA_IF_INDEX} ${ETH_INTERFACES[@]:$(($SURICATA_IF_INDEX + 1))})

# Demander à l'utilisateur de choisir l'interface pour les autres services
echo "Interfaces réseau restantes pour les autres services :"
for i in "${!ETH_INTERFACES[@]}"; do
    echo "[$i] ${ETH_INTERFACES[$i]}"
done

read -p "Entrez le numéro de l'interface à utiliser pour les autres services : " SERVICES_IF_INDEX
SERVICES_INTERFACE=${ETH_INTERFACES[$SERVICES_IF_INDEX]}

# Récupérer l'adresse IP de l'interface des services
SERVICES_IP=$(ip -o -f inet addr show $SERVICES_INTERFACE | awk '{print $4}' | cut -d/ -f1)
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
SHUFFLE_DEFAULT_USERNAME=
SHUFFLE_DEFAULT_PASSWORD=
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

