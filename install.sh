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

# CONST
RUPA_STATE_DIR="/var/lib/rupa"
RUPA_ENV_FILE="${RUPA_STATE_DIR}/.env"
DEPLOYED_FLAG="RUPA_DEPLOYED"
chmod +x post_install.sh #rendre le script post_install.sh exécutable

# -----------------------------------------------------------------------------
# 0.  PERSISTANCE PREMIER OU SECOND LANCEMENT
# -----------------------------------------------------------------------------
if [ ! -d "$RUPA_STATE_DIR" ]; then
    echo ">>> Premier lancement : création de ${RUPA_STATE_DIR}"
    mkdir -p "$RUPA_STATE_DIR"
    touch "$RUPA_ENV_FILE"
    echo "${DEPLOYED_FLAG}=false"   >> "$RUPA_ENV_FILE"
    echo "DEPLOY_DATE=$(date +%F)" >> "$RUPA_ENV_FILE"
else
    # charger les anciennes variables
    set -a
    # shellcheck source=/dev/null #Correction auto
    source "$RUPA_ENV_FILE"
    set +a

    if [ "${RUPA_DEPLOYED}" == "true" ]; then
        echo "-----------------------------------------------------------"
        echo "  RUPA System déjà installé le ${DEPLOY_DATE}"
        echo "-----------------------------------------------------------"

        # Vérifier si les conteneurs de la stack sont en cours d'exécution
        if docker compose ps -q | xargs docker inspect --format '{{.State.Status}}' | grep -vq running; then
            echo ">>> Stack non active : redémarrage..."
            docker compose up -d
        else
            echo ">>> Stack déjà active. Pense à exécuter post_install.sh si besoin."
            exit 0
        fi
    fi
fi
# -----------------------------------------------------------------------------

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
while [[ ! "$SSL_COUNTRY" =~ ^[A-Z]{2}$ ]]; do
    echo "Code pays invalide. Utilise 2 lettres majuscules (ex: FR, CM)."
    read -r -p "Pays (2 lettres) [ex: CM, FR, BE] : " SSL_COUNTRY
done
read -r -p "État ou Région : " SSL_STATE
while [[ -z "$SSL_STATE" || ! "$SSL_STATE" =~ ^[[:alpha:][:space:]-]+$ ]]; do
    echo "Nom d'état/région invalide. Utilise uniquement des lettres, espaces ou tirets."
    read -r -p "État ou Région : " SSL_STATE
done
read -r -p "Ville : " SSL_CITY
while [[ -z "$SSL_CITY" || ! "$SSL_CITY" =~ ^[[:alpha:][:space:]-]+$ ]]; do
    echo "Nom de ville invalide. Utilise uniquement des lettres, espaces ou tirets."
    read -r -p "Ville : " SSL_CITY
done
read -r -p "Nom de l'organisation : " SSL_ORG
while [[ -z "$SSL_ORG" ]]; do
    echo "L'organisation ne peut pas être vide."
    read -r -p "Nom de l'organisation : " SSL_ORG
done
read -r -p "Nom de l'unité organisationnelle : " SSL_ORG_UNIT
while [[ -z "$SSL_ORG_UNIT" ]]; do
    echo "L'unité organisationnelle ne peut pas être vide."
    read -r -p "Nom de l'unité organisationnelle : " SSL_ORG_UNIT
done
read -r -p "Nom commun (CN) [ex: domaine ou hostname] : " SSL_CN
# read -r -p "Nom commun (CN) [ex: domaine ou hostname] : " SSL_CN
# while [[ ! "$SSL_CN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; do
#     echo "Nom commun invalide. Fournis un nom de domaine (ex: portail.rupa.local)."
#     read -r -p "Nom commun (CN) [ex: domaine ou hostname] : " SSL_CN
# done
read -r -p "Adresse e-mail du contact : " SSL_EMAIL
while [[ ! "$SSL_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; do
    echo "Adresse e-mail invalide. (ex: contact@exemple.com)"
    read -r -p "Adresse e-mail du contact : " SSL_EMAIL
done

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
##mapfile -t ETH_INTERFACES < <(find /sys/class/net -maxdepth 1 -regex ".*/\(\(e\|en\|eth\)[a-z0-9]*\)$" -exec basename {} \;)
# [NOUVEAU] Détection enrichie des interfaces Ethernet (strictement filaires)
readarray -t ALL_IFACES < <(ls -1 /sys/class/net | sed 's#^.*/##')
ETH_INTERFACES=()
for ifc in "${ALL_IFACES[@]}"; do
    [[ "$ifc" == "lo" ]] && continue
    [[ "$ifc" =~ ^docker.*|^veth.*|^br.*|^tun.*|^tap.*|^wg.*|^wlan.* ]] && continue
    if [[ "$ifc" =~ ^eth[0-9]+$ \
        || "$ifc" =~ ^en[o|s|p][0-9a-zA-Z]+$ \
        || "$ifc" =~ ^em[0-9]+$ \
        || "$ifc" =~ ^p[0-9]+p[0-9]+s[0-9]+$ ]]; then
        ETH_INTERFACES+=("$ifc")
    fi
done

if [ ${#ETH_INTERFACES[@]} -lt 2 ]; then
    echo "Erreur : Au moins deux interfaces réseau Ethernet sont requises."
    printf 'Interfaces trouvées: %s\n' "${ETH_INTERFACES[@]}"
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
##SURICATA_IP=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}' | cut -d/ -f1)
##SURICATA_SUBNET=$(ip -o -f inet addr show "$SURICATA_INTERFACE" | awk '{print $4}')
##SURICATA_GATEWAY=$(ip route | grep "dev $SURICATA_INTERFACE" | grep default | awk '{print $3}')

# [NOUVEAU] Saisie/validation des réseaux internes sous forme CIDR (un ou plusieurs)
validate_cidr() {
    local cidr="$1"
    # Regex IP/mask
    if [[ ! "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        return 1
    fi
    local ip="${cidr%%/*}"; local mask="${cidr##*/}"
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
    done
    (( mask >=0 && mask <=32 )) || return 1
    return 0
}

prompt_and_get_home_nets() {
    local input=""
    while true; do
        echo
        echo "Entrez le(s) réseau(x) interne(s) (A protéger) au format CIDR, séparés par des virgules."
        echo "Exemples : 192.168.60.0/24   ou   192.168.60.0/24,10.0.0.0/8,172.16.0.0/12"
        read -r -p "Réseaux internes (CIDR) : " input
        input="$(echo "$input" | sed 's/[[:space:]]//g')"  # supprimer espaces
        IFS=',' read -r -a cidrs <<< "$input"
        (( ${#cidrs[@]} >= 1 )) || { echo "Veuillez saisir au moins un réseau en CIDR."; continue; }
        local ok=1
        for c in "${cidrs[@]}"; do
            if ! validate_cidr "$c"; then
                echo "CIDR invalide détecté: '$c'. Réessayez."
                ok=0; break
            fi
        done
        (( ok == 1 )) && { echo "Réseaux valides : $input"; SURICATA_HOME_NET="$input"; break; }
    done
}

prompt_and_get_home_nets

#GLOBAL_VARS["WAZUH_SURICATA_IP"]=$SURICATA_IP
GLOBAL_VARS["WAZUH_SURICATA_IP"]=""
#GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]=$SURICATA_SUBNET
GLOBAL_VARS["WAZUH_SURICATA_SUBNET"]="$SURICATA_HOME_NET"
#GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]=$SURICATA_GATEWAY
GLOBAL_VARS["WAZUH_SURICATA_GATEWAY"]=""        
GLOBAL_VARS["SURICATA_HOME_NET"]="$SURICATA_HOME_NET"

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
SURICATA_HOME_NET=${GLOBAL_VARS["SURICATA_HOME_NET"]}
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

N8N_EMAIL_MODE=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tonadresse@gmail.com
SMTP_PASS=ton_mot_de_passe_ou_mot_de_passe_app
N8N_SMTP_SENDER="RUPA System <tonadresse@gmail.com>"
N8N_SMTP_SSL=true
N8N_SMTP_TLS=true

DEBUG_MODE=false
EOF

echo "Fichier .env créé avec succès."


# 11. Mise à jour du fichier suricata.yaml

echo ">>> Mise à jour du fichier suricata.yaml avec l'adresse IP de Suricata..."

SURICATA_YAML_PATH="wazuh/config/wazuh_suricata/suricata.yaml"

if [ -f "$SURICATA_YAML_PATH" ]; then
    sed -i "s/\${SURICATA_IP}/${GLOBAL_VARS["SURICATA_HOME_NET"]}/g" "$SURICATA_YAML_PATH"
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

# Vérifier l'état de chaque conteneur
ERROR_FOUND=0
MAX_RETRIES=10
RETRY_COUNT=0
SLEEP_BETWEEN=15

# Boucle de vérification
while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
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

    if [ "$ERROR_FOUND" -eq 1 ]; then
        ((RETRY_COUNT++))
        echo "Certains conteneurs ne sont pas encore démarrés."
        echo "Tentative $RETRY_COUNT/$MAX_RETRIES. Nouvelle vérification dans $SLEEP_BETWEEN secondes..."
        echo "||--------------------------------------------------------------------------------------||"
        sleep $SLEEP_BETWEEN
    else
        echo "Tous les conteneurs ont bien démarés."
        break
    fi
done

# Renvoyer un message en cas d'erreur ou de réussite
if [ $ERROR_FOUND -eq 1 ]; then
    echo "Erreur : Un ou plusieurs conteneurs ne fonctionnent pas correctement."
    echo "Veuillez vérifier les logs des conteneurs avec 'docker-compose logs' pour plus d'informations."
    exit 1
else
    # Identifier les conteneurs en fonction de leur nom
    for CONTAINER_ID in $CONTAINERS; do
        CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$CONTAINER_ID" | sed 's/^\///')

        case "$CONTAINER_NAME" in
            *wazuh.manager*)   WAZUH_MANAGER_CONTAINER="$CONTAINER_NAME" ;;
            *wazuh.indexer*)   WAZUH_INDEXER_CONTAINER="$CONTAINER_NAME" ;;
            *wazuh.dashboard*) WAZUH_DASHBOARD_CONTAINER="$CONTAINER_NAME" ;;
            *wazuh.suricata*)  WAZUH_SURICATA_CONTAINER="$CONTAINER_NAME" ;;
            *evebox*)          EVEBOX_CONTAINER="$CONTAINER_NAME" ;;
            *nginx*)           NGINX_CONTAINER="$CONTAINER_NAME" ;;
            *n8n_postgres*)    POSTGRES_CONTAINER="$CONTAINER_NAME" ;;
            *n8n*)             N8N_CONTAINER="$CONTAINER_NAME" ;;
        esac
    done
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
    echo "Erreur : Le conteneur 'Wazuh-Manager' n'a pas été trouvé."
    exit 1
fi


echo "-----------------------------------------------------------"
echo "     INTÉGRATION DE SURICATA AVEC WAZUH EN COURS...        "
echo "-----------------------------------------------------------"

# 14. Intégration de Suricata avec Wazuh

echo ">>> Attente du démarrage complet des conteneurs..."
sleep 30 # Attendre 30 secondes

# a. Créer un groupe d'agents appelé Suricata
echo ">>> Création du groupe d'agents 'Suricata' dans Wazuh..."

docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/agent_groups -a -g Suricata -q
if [ $? -ne 0 ]; then
    echo "Erreur : Impossible de créer le groupe d'agents 'Suricata'."
    #exit 1
fi

# b. Récupérer l'ID de l'agent Suricata
echo ">>> Récupération de l'ID de l'agent Suricata..."

AGENT_INFO=$(docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_agents -l | grep -i 'Suricata')
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
    echo ">>> Déploiement de la configuration agent.conf pour Suricata..."
    # Copier le fichier dans le conteneur
    docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/suricata_agent.conf \
    "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/shared/Suricata/agent.conf

    # e. Ajouter les décoders personnalisés pour Suricata
    echo ">>> Déploiement des décoders personnalisés pour Suricata..."
    # Copier le fichier dans le conteneur
    docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/suricata_decoder.xml \
    "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/decoders/local_decoder.xml

    # f. Ajouter les règles personnalisées pour Suricata
    echo ">>> Déploiement des règles personnalisées Suricata dans local_rules.xml..."
    docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/suricata_rules.xml \
    "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/tmp/suricata_rules.xml
    docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" bash -c \
    "cat /tmp/suricata_rules.xml >> /var/ossec/etc/rules/local_rules.xml"

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

    echo ">>> Intégration de Suricata avec Wazuh terminée."

fi


echo "-----------------------------------------------------------"
echo " CONFIGURATIONDE L'ACTIVE RESPONSE POUR TERMINAUX WINDOWS  "
echo "-----------------------------------------------------------"

# 15. Préconfiguration d'active response pour terminaux windows

# On crée un groupe windows pour les agents windows
echo ">>> Création du groupe d'agents 'windows' dans Wazuh..."
docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/agent_groups -a -g windows -q
if [ $? -ne 0 ]; then
    echo "Erreur : Impossible de créer le groupe d'agents 'windows'."
    #exit 1
fi

# Déployer les règles custom (ex: 100010..100014 pour block_ip, 100020..100024 pour antivirus_scan)
echo ">>> Copie de windows_ar_rules.xml dans Wazuh manager..."
docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/windows_ar_rules.xml \
"${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/tmp/windows_ar_rules.xml

echo ">>> Ajout des règles dans local_rules.xml"
docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" bash -c \
"cat /tmp/windows_ar_rules.xml >> /var/ossec/etc/rules/local_rules.xml"

# Déployer le snippet (commands + active-response) pour le groupe windows
echo ">>> Copie de windows_ar_snippet.xml dans Wazuh manager..."
docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/windows_ar_snippet.xml \
"${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/etc/shared/windows/agent.conf

echo ">>> Configuration de l'active response pour terminaux Windows terminée"


#Redémarrer le service Wazuh Manager
echo ">>> Redémarrage du service Wazuh Manager..."
sleep 15 # On se rassure que le conteneur est totalement libéré de tout usage !

docker restart "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" #Méthode de redémarage 1
# docker-compose restart wazuh.manager #Méthode de redémarage 2
echo "...   Redémarrage en cours    ..."
sleep 90 # Attendre 1 minute et 30 secondes le temps qu'il redémarre !

echo ">>> Wazuh Manager est de nouveau démarré..."

# Vérifier à nouveau l'état des conteneurs
echo ">>> Vérification de l'état des conteneurs Docker..."

# Réinitialiser l'indicateur d'erreur et le compteur de tentatives
ERROR_FOUND=0
RETRY_COUNT=0

# Boucle de vérification
while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
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
        ((RETRY_COUNT++))
        echo "Certains conteneurs ne sont pas encore démarrés."
        echo "Tentative $RETRY_COUNT/$MAX_RETRIES . Nouvelle vérification dans $SLEEP_BETWEEN secondes..."
        echo "||---------------------------------------------------------------------------------------||"
        sleep $SLEEP_BETWEEN
    else
        echo "Tous les conteneurs sont en cours d'exécution."
        break
    fi
done

if [ $ERROR_FOUND -eq 1 ]; then
    echo "Erreur : Un ou plusieurs conteneurs ne fonctionnent pas correctement."
    echo "Veuillez vérifier les logs des conteneurs avec 'docker-compose logs' pour plus d'informations."
    exit 1
else
    echo "Tous les conteneurs Ont bien démarés."
fi





# echo "-----------------------------------------------------------"
# echo "           CONFIGURATION POST - DÉPLOIEMENT               "
# echo "-----------------------------------------------------------"

# # 17. Demander à l'utilisateur s'il souhaite effectuer les configurations post-installation

# read -r -p "Souhaitez-vous effectuer les configurations post-installation maintenant ? (y/n) : " POST_INSTALL_CHOICE

# # Validation de l'entrée utilisateur
# while [[ ! "$POST_INSTALL_CHOICE" =~ ^[YyNn]$ ]]; do
#     echo "Veuillez entrer 'y' pour oui ou 'n' pour non."
#     read -r -p "Souhaitez-vous effectuer les configurations post-installation maintenant ? (y/n) : " POST_INSTALL_CHOICE
# done

# if [[ "$POST_INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
#     echo ">>> Début des configurations post-installation..."
#     chmod +x post_install.sh
#     ./post_install.sh "${GLOBAL_VARS[@]}"
# else
#     echo ">>> Configuration post-installation ignorée."
#     echo "Installation terminée."
#     echo " "
#     echo " "
# fi

echo ">>> Sauvegarde des variables globales dans ${RUPA_ENV_FILE}"
{
    echo "${DEPLOYED_FLAG}=true"
    echo "DEPLOY_DATE=$(date +%F)"
    for k in "${!GLOBAL_VARS[@]}"; do
        printf "%s=%q\n" "$k" "${GLOBAL_VARS[$k]}"
    done
} >> "$RUPA_ENV_FILE"


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
echo "Nom d'utilisateur API : ${GLOBAL_VARS["API_USERNAME"]}"
echo "Mot de passe API: ${GLOBAL_VARS["API_PASSWORD"]}"
echo " "

# echo "Identifiants N8N par défaut :"
# echo "Nom d'utilisateur : ${GLOBAL_VARS["N8N_DEFAULT_USER"]}"
# echo "Mot de passe : ${GLOBAL_VARS["N8N_DEFAULT_PASS"]}"
# echo " "
# echo " "

echo " "
echo "Lintégration Wazuh <-> n8n peut se faire via le script post-install.sh"
echo " "
echo " "
echo "Merci d'avoir installé RUPA System <3"

exit 0

