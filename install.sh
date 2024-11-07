#!/bin/bash

# DEBUT DE L'INSTALLATION
echo "''*************************************************''"
echo "''                                                 ''"
echo "''   RESPONSE UNIFIED PREVENTION & ANALYSIS SYSTEM ''"
echo "''                V1.1.6                           ''"
echo "''                                                 ''"
echo "''*************************************************''"
echo ""

echo "-----------------------------------------------------"
echo "           INITIATION DE L'INSTALLATION              "
echo "-----------------------------------------------------"

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
  echo "Veuillez exécuter ce script en tant que root (sudo)."
  exit 1
fi

# Mise à jour du système
echo ">>> Mise à jour du système..."
sudo apt update -y && sudo apt upgrade -y || { echo "Échec de la mise à jour."; exit 1; }

# Configuration sysctl
echo ">>> Configuration du paramètre vm.max_map_count..."
sudo sysctl -w vm.max_map_count=262144 || { echo "Échec de la configuration sysctl."; exit 1; }
sudo sysctl -p

# Rendre la configuration persistante
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
fi

# Installation des prérequis
echo ">>> Installation des prérequis..."
sudo apt install -y gnome-terminal ca-certificates curl gnupg lsb-release openssl || { echo "Échec de l'installation des prérequis."; exit 1; }

# Installation de Docker
echo ">>> Installation de Docker..."

# Ajouter la clé GPG officielle de Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Ajouter le dépôt Docker aux sources APT
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Installer Docker et Docker Compose
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-compose || { echo "Échec de l'installation de Docker."; exit 1; }

# Vérifier l'installation de Docker
if ! command -v docker &> /dev/null; then
    echo "Docker n'a pas pu être installé. Veuillez vérifier les erreurs précédentes."
    exit 1
else
    echo "Docker installé avec succès."
fi

# Ajouter l'utilisateur actuel au groupe docker
sudo usermod -aG docker $USER

# Téléchargement des images Docker nécessaires
echo ">>> Téléchargement des images Docker requises..."
images=("wazuh/wazuh-manager:4.9.2" "wazuh/wazuh-indexer:4.9.2" "wazuh/wazuh-dashboard:4.9.2" "nginx:latest" "ghcr.io/shuffle/shuffle-frontend:latest" "ghcr.io/shuffle/shuffle-backend:latest" "ghcr.io/shuffle/shuffle-orborus:latest" "opensearchproject/opensearch:2.14.0" "jasonish/evebox:latest")
for image in "${images[@]}"; do
    docker pull "$image" || { echo "Échec du téléchargement de l'image Docker $image"; exit 1; }
done

# Construction des images Docker personnalisées
echo ">>> Construction des images Docker personnalisées..."
custom_dirs=("build_suricata-wazuh" "wazuh")
custom_images=("rupa/suricata-wazuh" "wazuh/wazuh-certs-generator:0.0.1")

for i in "${!custom_dirs[@]}"; do
    if [ -f "./${custom_dirs[$i]}/Dockerfile" ]; then
      docker build -t "${custom_images[$i]}" ./"${custom_dirs[$i]}"
    else
      echo "Dockerfile pour ${custom_images[$i]} introuvable. Skipping build."
    fi
done

echo "-----------------------------------------------------------"
echo "   PRÉREQUIS INSTALLÉS ET IMAGES DOCKER PRÊTES             "
echo "-----------------------------------------------------------"

# Création des variables globales et des dossiers nécessaires
declare -A GLOBAL_VARS

echo ">>> Création des dossiers nécessaires..."
mkdir -p shuffle/shuffle-database
sudo chown -R 1000:1000 shuffle/shuffle-database

# Désactivation du swap
sudo swapoff -a

# Vérifier et ajouter l'utilisateur 'opensearch' si nécessaire
if ! id "opensearch" &>/dev/null; then
    sudo useradd opensearch
fi

# Génération des certificats SSL pour le portail
read -p "Entrez le nom de votre organisation : " ORG_NAME
GLOBAL_VARS["ORG_NAME"]=$ORG_NAME
read -p "Entrez le nom de votre unité organisationnelle : " ORG_UNIT
GLOBAL_VARS["ORG_UNIT"]=$ORG_UNIT
read -p "Entrez votre adresse e-mail : " EMAIL_ADDRESS
GLOBAL_VARS["EMAIL_ADDRESS"]=$EMAIL_ADDRESS

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout reverse_proxy/nginx/ssl/rupa_portal.key -out reverse_proxy/nginx/ssl/rupa_portal.crt -subj "/C=CM/ST=CENTRE/L=YAOUNDE/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=localhost/emailAddress=${EMAIL_ADDRESS}"

echo ">>> Configuration presque terminée. Vérifiez les logs Docker pour des erreurs éventuelles."

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

# Choix de l'interface pour Suricata
read -p "Entrez le numéro de l'interface à utiliser pour Suricata : " SURICATA_IF_INDEX
while ! [[ "$SURICATA_IF_INDEX" =~ ^[0-9]+$ ]] || [ "$SURICATA_IF_INDEX" -lt 0 ] || [ "$SURICATA_IF_INDEX" -ge ${#ETH_INTERFACES[@]} ]; do
    echo "Numéro d'interface invalide. Veuillez réessayer."
    read -p "Entrez le numéro de l'interface à utiliser pour Suricata : " SURICATA_IF_INDEX
done

SURICATA_INTERFACE=${ETH_INTERFACES[$SURICATA_IF_INDEX]}
GLOBAL_VARS["INTERFACE_RESEAU"]=$SURICATA_INTERFACE

# Informations de l'interface Suricata
SURICATA_IP=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}' | cut -d/ -f1)
SURICATA_SUBNET=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}')
SURICATA_GATEWAY=$(ip route | grep "dev $SURICATA_INTERFACE" | grep default | awk '{print $3}')

GLOBAL_VARS["WAZUH_SURICATA_IP"]=$SURICATA_IP
GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]=$SURICATA_SUBNET
GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]=$SURICATA_GATEWAY

# Demander à l'utilisateur de choisir l'interface pour les autres services
echo "Interfaces réseau restantes pour les autres services :"
for i in "${!ETH_INTERFACES[@]}"; do
    echo "[$i] ${ETH_INTERFACES[$i]}"
done

read -p "Entrez le numéro de l'interface à utiliser pour les autres services : " SERVICES_IF_INDEX
while ! [[ "$SERVICES_IF_INDEX" =~ ^[0-9]+$ ]] || [ "$SERVICES_IF_INDEX" -lt 0 ] || [ "$SERVICES_IF_INDEX" -ge ${#ETH_INTERFACES[@]} ]; do
    echo "Numéro d'interface invalide. Veuillez réessayer."
    read -p "Entrez le numéro de l'interface à utiliser pour les autres services : " SERVICES_IF_INDEX
done

SERVICES_INTERFACE=${ETH_INTERFACES[$SERVICES_IF_INDEX]}
SERVICES_IP=$(ip -o -f inet addr show "$SERVICES_INTERFACE" | awk '{print $4}' | cut -d/ -f1)
GLOBAL_VARS["WAZUH_MANAGER_IP"]=$SERVICES_IP

# 10. Création du fichier .env local
echo ">>> Création du fichier .env à la racine du projet..."

cat > .env <<EOF
####################### Reverse_Proxy #######################
NGINX_HOST=localhost
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443

####################### WAZUH #######################
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

WAZUH_API_URL=https://wazuh.manager
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=kibanaserver

# Variables pour Suricata Wazuh
WAZUH_MANAGER_IP=${GLOBAL_VARS["WAZUH_MANAGER_IP"]}
WAZUH_SURICATA_IP=${GLOBAL_VARS["WAZUH_SURICATA_IP"]}
WAZUH_SURICATA_SUBNET=${GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]}
WAZUH_SURICATA_GATEWAY=${GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]}
INTERFACE_RESEAU=${GLOBAL_VARS["INTERFACE_RESEAU"]}
PUID=$(id -u)
PGID=$(id -g)
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
docker-compose up -d || { echo "Erreur lors du démarrage de Docker Compose."; exit 1; }

echo ">>> Attente du démarrage des conteneurs..."
sleep 360 # Attendre 6 minutes

# Vérification des conteneurs
echo ">>> Vérification de l'état des conteneurs Docker..."
CONTAINERS=$(docker-compose ps -q)
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

# 13. Affichage des identifiants et message de fin

echo "Accédez à la plateforme via : https://$SERVICES_IP"

echo "Identifiants WAZUH par défaut :"
echo "Nom d'utilisateur : admin"
echo "Mot de passe : SecretPassword"

echo "Identifiants SHUFFLE par défaut :"
echo "Nom d'utilisateur : admin"
echo "Mot de passe : admin"

echo "Merci d'avoir installé RUPA System !"
