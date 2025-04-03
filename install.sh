#!/bin/bash

clear

# 1. DÉBUT DE L'INSTALLATION
echo "''*************************************************''"
echo "''                                                 ''"
echo "''   RESPONSE UNIFIED PREVENTION & ANALYSIS SYSTEM ''"
echo "''                V1.2.0                           ''"
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

# cat <<\EOF
# - - - RU - - -
# - - - PA - - -
# - - System - -
# EOF


echo "-----------------------------------------------------"
echo "           INITIATION DE L'INSTALLATION              "
echo "-----------------------------------------------------"


# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    echo ">>>>>>Veuillez exécuter ce script en tant que root (sudo)."
    exit 1
fi

# 2. Mise à jour du système
echo ">>> Mise à jour du système..."

apt update -y && apt upgrade -y
#apt install -y --fix-missing
#apt update -y && apt upgrade -y

# 3. Appliquer la configuration sysctl
echo ">>> Configuration du paramètre vm.max_map_count..."
sysctl -w vm.max_map_count=262144


# Rendre la configuration persistante
echo ">>> Rendre vm.max_map_count=262144 persistant..."
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
fi

# Appliquer les modifications
sysctl -p

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
    usermod -aG docker "$SUDO_USER"
else
    echo "Docker est déjà installé. Skipping installation."
fi

# 6. Télécharger les images Docker nécessaires

echo ">>> Téléchargement des images Docker requises..."

IMAGES=(
    "nginx:1.26.3"
    "jasonish/evebox:0.20.3"
    "rupadante/wazuh-certs-generator:0.0.2"
    "rupadante/suricata-wazuh:latest"
    "postgres:15"
    "n8nio/n8n:1.42.2"
    "wazuh/wazuh-dashboard:4.9.2"
    "wazuh/wazuh-manager:4.9.2"
    "wazuh/wazuh-indexer:4.9.2" 
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

# 7. Création des variables globales et des dossiers nécessaires

# Déclarer un tableau pour stocker les variables globales
declare -A GLOBAL_VARS

echo ">>> Création des dossiers nécessaires..."

# # Créer le dossier ./shuffle/shuffle-database
# echo ">>> Création du dossier ./shuffle/shuffle-database..."
# mkdir -p shuffle/shuffle-database
# chown -R 1000:1000 shuffle/shuffle-database

# Créer le dossier ./n8n/n8n_data
echo ">>> Création du dossier n8n/n8n_data"
mkdir -p n8n/n8n_data
chown -R 1000:1000 n8n/n8n_data

# Désactiver le swap
echo ">>> Désactivation du swap..."
swapoff -a

# # Vérifier et ajouter l'utilisateur 'opensearch' si nécessaire
# if ! id "opensearch" &>/dev/null; then
#     useradd opensearch
# fi

# Générer les certificats auto-signés pour Wazuh
echo ">>> Génération des certificats auto-signés pour Wazuh..."
docker-compose -f wazuh/generate-indexer-certs.yml run --rm generator

# Créer le répertoire ./reverse_proxy/nginx/ssl
echo ">>> Création du répertoire ./reverse_proxy/nginx/ssl..."
mkdir -p reverse_proxy/nginx/ssl

# Demander les informations pour le certificat SSL
echo ">>> Génération des certificats SSL pour le portail RUPA..."

# Récupération des informations auprés de l'utilisateur
read -r -p "Pays (2 lettres) [ex: CM, FR, BE] : " SSL_COUNTRY
read -r -p "État ou Région : " SSL_STATE
read -r -p "Ville : " SSL_CITY
read -r -p "Nom de l'organisation : " SSL_ORG
read -r -p "Nom de l'unité organisationnelle : " SSL_ORG_UNIT
read -r -p "Nom commun (CN) [ex: domaine ou hostname] : " SSL_CN
read -r -p "Adresse e-mail du contact : " SSL_EMAIL

# Conserver ces valeurs pour les réutiliser si besoin dans le post_install
GLOBAL_VARS["SSL_COUNTRY"]=$SSL_COUNTRY
GLOBAL_VARS["SSL_STATE"]=$SSL_STATE
GLOBAL_VARS["SSL_CITY"]=$SSL_CITY
GLOBAL_VARS["SSL_ORG"]=$SSL_ORG
GLOBAL_VARS["SSL_ORG_UNIT"]=$SSL_ORG_UNIT
GLOBAL_VARS["SSL_CN"]=$SSL_CN
GLOBAL_VARS["SSL_EMAIL"]=$SSL_EMAIL

# Générer le certificat SSL auto-signé
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout reverse_proxy/nginx/ssl/rupa_portal.key \
    -out reverse_proxy/nginx/ssl/rupa_portal.crt \
    -subj "/C=${SSL_COUNTRY}/ST=${SSL_STATE}/L=${SSL_CITY}/O=${SSL_ORG}/OU=${SSL_ORG_UNIT}/CN=${SSL_CN}/emailAddress=${SSL_EMAIL}"


# 8. Configuration de la timezone pour N8N

echo ">>> Configuration de la timezone pour N8N..."

# On tente de récupérer la timezone via timedatectl
detected_tz="$(timedatectl show -p Timezone --value 2>/dev/null)"

# Si c'est vide ou que timedatectl n'est pas dispo, on essaie /etc/timezone
if [ -z "$detected_tz" ]; then
    if [ -f /etc/timezone ]; then
        detected_tz="$(cat /etc/timezone)"
    fi
fi

# Si on n'a toujours rien, on choisit une timezone par défaut
if [ -z "$detected_tz" ]; then
    detected_tz="Africa/Douala"
fi

echo "Fuseau horaire détecté: $detected_tz"
GLOBAL_VARS["TZ"]=$detected_tz
GLOBAL_VARS["GENERIC_TIMEZONE"]=$detected_tz


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
PUID=$(id -u "$SUDO_USER")
PGID=$(id -g "$SUDO_USER")
GLOBAL_VARS["PUID"]=$PUID
GLOBAL_VARS["PGID"]=$PGID


# read -r -p "Entrez l'URL de l'API Wazuh (par défaut : https://${GLOBAL_VARS["WAZUH_MANAGER_IP"]}:55000) : " WAZUH_API_URL
# WAZUH_API_URL=${WAZUH_API_URL:-"https://${GLOBAL_VARS["WAZUH_MANAGER_IP"]}:55000"}
# GLOBAL_VARS["WAZUH_API_URL"]=$WAZUH_API_URL

# read -r -p "Entrez le nom d'utilisateur de l'API Wazuh (par défaut: wazuh-wui) : " API_USERNAME
# API_USERNAME=${API_USERNAME:-"wazuh-wui"}
# GLOBAL_VARS["API_USERNAME"]=$API_USERNAME

# read -r -s -p "Entrez le mot de passe de l'API Wazuh (par défaut: MyS3cr37P450r.*-) : " API_PASSWORD
# API_PASSWORD=${API_PASSWORD:-"MyS3cr37P450r.*-"}
# GLOBAL_VARS["API_PASSWORD"]=$API_PASSWORD
# echo

# echo ">>> Configuration de Shuffle..."

# read -r -p "Entrez le nom d'utilisateur par défaut pour Shuffle (par défaut: admin) : " SHUFFLE_DEFAULT_USERNAME
# SHUFFLE_DEFAULT_USERNAME=${SHUFFLE_DEFAULT_USERNAME:-"admin"}
# GLOBAL_VARS["SHUFFLE_DEFAULT_USERNAME"]=$SHUFFLE_DEFAULT_USERNAME

# read -r -s -p "Entrez le mot de passe par défaut pour Shuffle (par défaut: admin) : " SHUFFLE_DEFAULT_PASSWORD
# SHUFFLE_DEFAULT_PASSWORD=${SHUFFLE_DEFAULT_PASSWORD:-"admin"}
# GLOBAL_VARS["SHUFFLE_DEFAULT_PASSWORD"]=$SHUFFLE_DEFAULT_PASSWORD
# echo

# URL de l'API Wazuh
# WAZUH_API_URL="https://${GLOBAL_VARS["WAZUH_MANAGER_IP"]}:55000"
WAZUH_API_URL="https://wazuh.manager:55000"
GLOBAL_VARS["WAZUH_API_URL"]=$WAZUH_API_URL

# Nom d'utilisateur de l'API Wazuh
API_USERNAME="wazuh-wui"
GLOBAL_VARS["API_USERNAME"]=$API_USERNAME

# Mot de passe de l'API Wazuh
API_PASSWORD="MyS3cr37P450r.*-"
GLOBAL_VARS["API_PASSWORD"]=$API_PASSWORD

# Configuration de N8N
echo ">>> Configuration de N8N..."

# Nom d'utilisateur par défaut pour Shuffle
N8N_DEFAULT_USER="admin"
GLOBAL_VARS["N8N_DEFAULT_USER"]=$N8N_DEFAULT_USER

# Mot de passe par défaut pour Shuffle
N8N_DEFAULT_PASS="superadminpass"
GLOBAL_VARS["N8N_DEFAULT_PASS"]=$N8N_DEFAULT_PASS



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
API_USERNAME=${GLOBAL_VARS["API_USERNAME"]}
API_PASSWORD=${GLOBAL_VARS["API_PASSWORD"]}

# Variables pour la sécurité des certificats SSL
FILEBEAT_SSL_VERIFICATION_MODE=full
SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
SSL_CERTIFICATE=/etc/ssl/filebeat.pem
SSL_KEY=/etc/ssl/filebeat.key

# Variables pour le Wazuh Dashboard
WAZUH_API_URL=${GLOBAL_VARS["WAZUH_API_URL"]}
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

####################### N 8 N #######################
# Variables pour postgre
POSTGRES_USER=n8n
POSTGRES_PASSWORD=supersecretpg
POSTGRES_DB=n8ndb

# Variables pour l'authentification N8N
N8N_BASIC_AUTH_USER=${GLOBAL_VARS["N8N_DEFAULT_USER"]}
N8N_BASIC_AUTH_PASSWORD=${GLOBAL_VARS["N8N_DEFAULT_PASS"]}

GENERIC_TIMEZONE=${GLOBAL_VARS["GENERIC_TIMEZONE"]}
TZ=${GLOBAL_VARS["TZ"]}

N8N_PORT=5678
N8N_HOST=localhost
WEBHOOK_URL=http://localhost:5678

DEBUG_MODE=false
EOF

echo "Fichier .env créé avec succès."


# 11. Mise à jour du fichier suricata.yaml

echo ">>> Mise à jour du fichier suricata.yaml avec l'adresse IP de Suricata..."

SURICATA_YAML_PATH="wazuh/config/wazuh_suricata/suricata.yaml"

if [ -f "$SURICATA_YAML_PATH" ]; then
    sed -i "s/\${SURICATA_IP}/${GLOBAL_VARS["WAZUH_SURICATA_IP"]}\/24/g" "$SURICATA_YAML_PATH"
    sed -i "s/\${SURICATA_INT}/${GLOBAL_VARS["INTERFACE_RESEAU"]}/g" "$SURICATA_YAML_PATH"
    echo "suricata.yaml mis à jour."
else
    echo "Erreur : Le fichier suricata.yaml n'a pas été trouvé à l'emplacement $SURICATA_YAML_PATH."
fi

echo ">>> Mise à jour du fichier index.html avec l'adresse IP de l'app..."

INDEX_HTML_PATH="reverse_proxy/nginx/html/index.html"

if [ -f "$INDEX_HTML_PATH" ]; then
    sed -i "s/\${APP_IP}/${SERVICES_IP}/g" "$INDEX_HTML_PATH"
    echo "index.html mis à jour."
else
    echo "Erreur : Le fichier index.html n'a pas été trouvé à l'emplacement $INDEX_HTML_PATH."
fi

echo "-----------------------------------------------------------"
echo "   CONFIGURATION TERMINÉE. PRÊT POUR LE DÉPLOIEMENT.      "
echo "-----------------------------------------------------------"

# 12. Lancement de la plateforme Docker
echo ">>> Lancement de la plateforme Docker..."
export COMPOSE_HTTP_TIMEOUT=300 # on augmente le délai d'attente de lancement des conteneurs par docker à 5 min pour éviter un bug en cas de lenteur au lancement
docker-compose up -d # Lancer les conteneurs en arrière-plan

echo ">>> Attente du démarrage des conteneurs..."
sleep 60 # Attendre 1 minutes

# 13. Vérification que tous les conteneurs fonctionnent correctement

echo ">>> Vérification de l'état des conteneurs Docker..."

# Initialiser des variables pour stocker les noms des conteneurs
WAZUH_MANAGER_CONTAINER=""
WAZUH_INDEXER_CONTAINER=""
WAZUH_DASHBOARD_CONTAINER=""
WAZUH_SURICATA_CONTAINER=""
EVEBOX_CONTAINER=""
NGINX_CONTAINER=""
POSTGRES_CONTAINER=""
N8N_CONTAINER=""

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

    # Identifier les conteneurs en fonction de leur nom
    if [[ "$CONTAINER_NAME" == *"wazuh.manager"* ]]; then
        WAZUH_MANAGER_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"wazuh.indexer"* ]]; then
        WAZUH_INDEXER_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"wazuh.dashboard"* ]]; then
        WAZUH_DASHBOARD_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"wazuh.suricata"* ]]; then
        WAZUH_SURICATA_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"evebox"* ]]; then
        EVEBOX_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"nginx"* ]]; then
        NGINX_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"n8n_postgres"* ]]; then
        POSTGRES_CONTAINER="$CONTAINER_NAME"
    elif [[ "$CONTAINER_NAME" == *"n8n"* ]]; then
        N8N_CONTAINER="$CONTAINER_NAME"
    fi
done

if [ $ERROR_FOUND -eq 1 ]; then
    echo "Erreur : Un ou plusieurs conteneurs ne fonctionnent pas correctement."
    echo "Veuillez vérifier les logs des conteneurs avec 'docker-compose logs' pour plus d'informations."
    exit 1
else
    echo "Tous les conteneurs fonctionnent correctement."
fi

# Stocker les noms des conteneurs dans le tableau GLOBAL_VARS
GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]="$WAZUH_MANAGER_CONTAINER"
GLOBAL_VARS["WAZUH_INDEXER_CONTAINER"]="$WAZUH_INDEXER_CONTAINER"
GLOBAL_VARS["WAZUH_DASHBOARD_CONTAINER"]="$WAZUH_DASHBOARD_CONTAINER"
GLOBAL_VARS["WAZUH_SURICATA_CONTAINER"]="$WAZUH_SURICATA_CONTAINER"
GLOBAL_VARS["EVEBOX_CONTAINER"]="$EVEBOX_CONTAINER"
GLOBAL_VARS["NGINX_CONTAINER"]="$NGINX_CONTAINER"
GLOBAL_VARS["POSTGRES_CONTAINER"]="$POSTGRES_CONTAINER"
GLOBAL_VARS["N8N_CONTAINER"]="$N8N_CONTAINER"

# Vérifier que tous les conteneurs requis ont été trouvés
# Vérifier que le conteneur wazuh-manager a été trouvé
if [ -z "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" ]; then
    echo "Erreur : Le conteneur Wazuh Manager n'a pas été trouvé."
    exit 1
fi


echo "-----------------------------------------------------------"
echo "     INTÉGRATION DE SURICATA AVEC WAZUH EN COURS...        "
echo "-----------------------------------------------------------"

# 14. Intégration de Suricata avec Wazuh

echo ">>> Attente du démarrage complet des conteneurs..."
sleep 120 # Attendre 2 minutes

# a. Créer un groupe d'agents appelé Suricata
echo ">>> Création du groupe d'agents 'Suricata' dans Wazuh..."

docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/agent_groups -a -g Suricata -q
if [ $? -ne 0 ]; then
    echo "Erreur : Impossible de créer le groupe d'agents 'Suricata'."
    #exit 1
fi

# b. Récupérer l'ID de l'agent Suricata
echo ">>> Récupération de l'ID de l'agent Suricata..."

AGENT_INFO=$(docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_agents -l | grep 'suricata')
if [ $? -ne 0 ]; then
    echo "Erreur : Impossible de récupérer l'ID de l'agent suricata"
    #exit 1
fi

if [ -z "$AGENT_INFO" ]; then
    echo "Erreur : L'agent Suricata n'a pas été trouvé. Veuillez vous assurer que l'agent est enregistré."
else

    # AGENT_ID=$(echo "$AGENT_INFO" | awk '{print $1}')
    AGENT_ID=$(echo "$AGENT_INFO" | grep -oP '(?<=ID: )\d+') # Meuilleure méthode pour extraire l'ID


    echo "ID de l'agent Suricata : $AGENT_ID"

    # c. Ajouter l'agent Suricata au groupe 'Suricata'
    echo ">>> Ajout de l'agent Suricata au groupe 'Suricata'..."

    docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/agent_groups -a -i "$AGENT_ID" -g Suricata -q
    if [ $? -ne 0 ]; then
        echo "Erreur : Impossible d'ajouter l'agent suricata au groupe Suricata"
        #exit 1
    fi

    # d. Ajouter la configuration partagée pour le groupe Suricata
    echo ">>> Configuration du fichier agent.conf pour le groupe 'Suricata'..."

    AGENT_CONF_CONTENT='<agent_config>
    <localfile>
        <log_format>json</log_format>
        <location>/var/log/suricata/eve.json</location>
    </localfile>
    </agent_config>'

    # Créer le fichier agent.conf localement
    echo "$AGENT_CONF_CONTENT" > agent.conf

    # Copier le fichier dans le conteneur
    docker cp agent.conf "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/shared/Suricata/agent.conf

    # Supprimer le fichier local
    rm agent.conf

    # e. Ajouter les décoders personnalisés pour Suricata
    echo ">>> Ajout des décoders personnalisés pour Suricata..."

    LOCAL_DECODER_CONTENT='<decoder name="json">
    <prematch>^{\s*"</prematch>
    </decoder>
    <decoder name="json_child">
    <parent>json</parent>
    <regex type="pcre2">"src_ip":"([^"]+)"</regex>
    <order>srcip</order>
    </decoder>
    <decoder name="json_child">
    <parent>json</parent>
    <plugin_decoder>JSON_Decoder</plugin_decoder>
    </decoder>'

    # Créer le fichier local_decoder.xml localement
    echo "$LOCAL_DECODER_CONTENT" > local_decoder.xml

    # Copier le fichier dans le conteneur
    docker cp local_decoder.xml "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/decoders/local_decoder.xml

    # Supprimer le fichier local
    rm local_decoder.xml

    # f. Ajouter les règles personnalisées pour Suricata
    echo ">>> Ajout des règles personnalisées pour Suricata..."

    LOCAL_RULES_CONTENT='<group name="custom_active_response_rules,">
    <rule id="100200" level="12">
        <if_sid>86600</if_sid>
        <field name="event_type">^alert$</field>
        <match>ET DOS Inbound GoldenEye DoS attack</match>
        <description>GoldenEye DoS attack has been detected. </description>
        <mitre>
        <id>T1498</id>
        </mitre>
    </rule>
    <rule id="100201" level="12">
        <if_sid>86600</if_sid>
        <field name="event_type">^alert$</field>
        <match>ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)</match>
        <description>Nmap scripting engine detected. </description>
        <mitre>
        <id>T1595</id>
        </mitre>
    </rule>
    </group>'

    # Créer le fichier local_rules.xml localement
    echo "$LOCAL_RULES_CONTENT" > local_rules.xml

    # Copier le fichier dans le conteneur
    docker cp local_rules.xml "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/rules/local_rules.xml

    # Supprimer le fichier local
    rm local_rules.xml

    # # g. Configuration de l'active response
    # echo ">>> Configuration de l'active response dans Wazuh..."

    # # Vérifier si la section 'command' pour 'firewall-drop' existe déjà
    # FIREWALL_DROP_EXIST=$(docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" grep -c "<name>firewall-drop</name>" /var/ossec/etc/ossec.conf || true)

    # if [ "$FIREWALL_DROP_EXIST" -eq 0 ]; then
    #     echo ">>> Ajout de la commande 'firewall-drop' dans ossec.conf..."

    #     COMMAND_BLOCK='<command>
    #     <name>firewall-drop</name>
    #     <executable>firewall-drop</executable>
    #     <timeout_allowed>yes</timeout_allowed>
    # </command>'

    #     # Ajouter le bloc 'command' dans ossec.conf
    #     docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" sed -i "/<\/commands>/i \  $COMMAND_BLOCK" /var/ossec/etc/ossec.conf
    # fi

    # # Ajouter la configuration de l'active response
    # ACTIVE_RESPONSE_BLOCK='<active-response>
    #     <command>firewall-drop</command>
    #     <location>local</location>
    #     <rules_id>100200,100201</rules_id>
    #     <timeout>180</timeout>
    # </active-response>'

    # # Ajouter le bloc 'active-response' dans ossec.conf
    # docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" sed -i "/<\/active-response>/i \  $ACTIVE_RESPONSE_BLOCK" /var/ossec/etc/ossec.conf
    #Pas nécessaire pour le moment ! RUPA

    # h. Redémarrer le service Wazuh Manager
    echo ">>> Redémarrage du service Wazuh Manager..."
    sleep 10 # On se rassure que le conteneur est totalement libéré de tout usage !

    docker restart "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" #Méthode de redémarage 1
    # docker-compose restart wazuh.manager #Méthode de redémarage 2
    echo "...   Redémarrage en cours    ..."
    sleep 120 # Attendre 2 minutes le temps qu'il redémarre !

    echo ">>> Wazuh Manager est de nouveau démarré..."

    # Vérifier à nouveau l'état des conteneurs
    echo ">>> Vérification de l'état des conteneurs Docker..."

    # Réinitialiser l'indicateur d'erreur
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
fi
echo ">>> Intégration de Suricata avec Wazuh terminée."
echo ">>> Veuillez patienter quelques minutes ..."
sleep 120 # Attendre 2 minutes le temps qu'il redémarre complétement !



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
    chmod +x post_install.sh
    ./post_install.sh "${GLOBAL_VARS[@]}"
else
    echo ">>> Configuration post-installation ignorée."
    echo "Installation terminée."
    echo " "
    echo " "
fi

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
echo " "
echo " "

echo "Identifiants WAZUH par défaut :"
echo "Nom d'utilisateur : admin"
echo "Mot de passe : SecretPassword"
echo " "
echo " "

echo "Identifiants N8N par défaut :"
echo "Nom d'utilisateur : ${GLOBAL_VARS["N8N_DEFAULT_USER"]}"
echo "Mot de passe : ${GLOBAL_VARS["N8N_DEFAULT_PASS"]}"
echo " "
echo " "

echo "Merci d'avoir installé RUPA System <3"

exit 0

