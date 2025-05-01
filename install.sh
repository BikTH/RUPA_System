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
echo "''                                                 ''"
echo "''                                                 ''"

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    echo ">>>>>>Veuillez exécuter ce script en tant que root (sudo)."
    exit 1
fi


set -e
STATE_DIR="/var/lib/rupa"
STATE_FILE="$STATE_DIR/rupa.env"
SCRIPTS_DIR="$(dirname "$0")/scripts/rupa_scripts"

mkdir -p "$STATE_DIR"

if [ ! -f "$STATE_FILE" ] || ! grep -q '^INSTALL_DONE=yes' "$STATE_FILE"; then
    echo "-----------------------------------------------------"
    echo "             INSTALLATION DE RUPA SYSTEME            "
    echo "-----------------------------------------------------"

    # lance le déploiement complet
    bash "$SCRIPTS_DIR/deploy_rupa.sh"

    if [ -f /tmp/global_vars.dump ]; then
        # shellcheck disable=SC1091
        source /tmp/global_vars.dump        # recharge le tableau
    else
        echo "Erreur : /tmp/global_vars.dump introuvable." ; 
        echo "Le déploiement de RUPA a échoué." ; 
        exit 1
    fi

    rm -f /tmp/global_vars.dump            # propre

    # Aprés le déploiement on crée et sauvegarde le fichier d'état
    {
        echo "INSTALL_DONE=yes"
        echo "INSTALL_DATE=\"$(date '+%F %T')\""
        echo "RUPA_VERSION=\"1.4.0\""
        # persiste toutes les clés GLOBAL_VARS
        for k in "${!GLOBAL_VARS[@]}"; do
            printf '%s="%s"\n' "$k" "${GLOBAL_VARS[$k]}"
        done
    } > "$STATE_FILE"

    echo "Installation terminée."
    exit 0

fi

echo "-----------------------------------------------------"
echo "        L'INSTALLATION A ÉTÉ FAITE AVANT             "
echo "-----------------------------------------------------"

# Vérifier si le fichier d'état existe avant de le sourcer
if [ -f "$STATE_FILE" ]; then
    # shellcheck source=/var/lib/rupa/rupa.env
    source "$STATE_FILE"  # On récupére les données sauvegardées dans le fichier /var/lib/rupa/rupa.env
else
    echo "Erreur : Le fichier d'état $STATE_FILE est introuvable."
    exit 1
fi

while true; do
    cat <<'MENU'
╔══════════  MENU RUPA  ═════════╗
║ 1. Lancer / arrêter RUPA       ║
║ 2. Lier (ou relier) N8N ↔ Wazuh║
║ 3. Mettre à jour la plateforme ║
║ 0. Quitter                     ║
╚════════════════════════════════╝
MENU
    read -rp "Choix : " CHOICE
    case "$CHOICE" in
        1) bash "$SCRIPTS_DIR/run_rupa.sh" ;;
        2) bash "$SCRIPTS_DIR/link_n8n_wazuh.sh" ;;
        3) echo "(fonction à venir)"; read -n1 -s -p "Appuyer sur n'importe quel touche" ;;
        0) exit 0 ;;
        *) echo "Choix invalide"; sleep 1 ;;
    esac
done

