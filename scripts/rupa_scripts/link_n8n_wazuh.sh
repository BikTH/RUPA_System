#!/usr/bin/env bash
set -e
source /var/lib/rupa/rupa.env
cd "$(dirname "$0")/../.."   # racine projet docker-compose

echo "-----------------------------------------------------------"
echo "             INTEGRATION WAZUH <-> N8N                     "
echo "-----------------------------------------------------------"

# 16. Intégration de wazuh dans N8N

# a. Création utilisateur API n8n
echo ">>> Vérification de l'utilisateur n8n..."
docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_users -l | grep -q "n8n"
if [ $? -ne 0 ]; then
    echo ">>> Création de l'utilisateur n8n dans la Wazuh API..."
    docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_users -a n8n -r administrator -p "n8np@ss@pi"
else
    echo ">>> Utilisateur n8n déjà existant."
fi

# b. Copie du script d'intégration webhook
echo ">>> Copie du script n8n_webhook.sh dans Wazuh..."
docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/n8n_webhook.sh "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/integrations/n8n_webhook.sh

echo ">>> Rendre le script exécutable..."
docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" chmod +x /var/ossec/integrations/n8n_webhook.sh

# c. Insertion du bloc d'intégration
echo ">>> Copie de n8n_integration_snippet.xml dans Wazuh..."
docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/n8n_integration_snippet.xml "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/tmp/n8n_integration_snippet.xml

echo ">>> Insertion dans ossec.conf..."
docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" bash -c "sed -i '/<\/ossec_config>/e cat /tmp/n8n_integration_snippet.xml' /var/ossec/etc/ossec.conf"

echo ">>> Intégration Wazuh <-> N8N terminée avec succès."


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
