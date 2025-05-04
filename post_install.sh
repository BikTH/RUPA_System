#!/usr/bin/env bash

clear

set -e

echo "-----------------------------------------------------------"
echo "        [RUPA SYSTEM] POST-INSTALLATION SCRIPT             "
echo "-----------------------------------------------------------"

RUPA_ENV="/var/lib/rupa/.env"

if [ ! -f "$RUPA_ENV" ]; then
    echo "Erreur : RUPA System n'est pas encore installé."
    echo "Veuillez exécuter d'abord le script install.sh"
    exit 1
fi

# Charger les variables
source "$RUPA_ENV"
# declare -A GLOBAL_VARS
# while IFS='=' read -r k v; do GLOBAL_VARS[$k]=$v; done < "$RUPA_ENV"

# Vérification de la stack
MAX_RETRIES=6
RETRY_COUNT=0
SLEEP_BETWEEN=15
ERROR_FOUND=0
# Liste des conteneurs à vérifier
CONTAINERS=(
    "$WAZUH_MANAGER_CONTAINER"
    "$WAZUH_INDEXER_CONTAINER"
    "$WAZUH_DASHBOARD_CONTAINER"
    "$WAZUH_SURICATA_CONTAINER"
    "$EVEBOX_CONTAINER"
    "$NGINX_CONTAINER"
    "$POSTGRES_CONTAINER"
    "$N8N_CONTAINER"
)

echo ">>> Vérification initiale des conteneurs..."
while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
    ERROR_FOUND=0
    for CONTAINER_NAME in "${CONTAINERS[@]}"; do
        if [ -z "$CONTAINER_NAME" ]; then continue; fi
        CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo 'notfound')
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
        echo '||---------------------------------------------------------------------------------------||'
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
    echo "Tous les conteneurs ont bien démarré."
fi

echo "-----------------------------------------------------------"
echo "             INTEGRATION WAZUH <-> N8N                     "
echo "-----------------------------------------------------------"

# 1.  Demander l’URL Webhook n8n
read -rp "URL du webhook n8n (ex :http://n8n:5678/webhook/alert) : " N8N_WEBHOOK_URL

# 2.  Générer le script n8n_webhook.sh persistant
INTEG_DIR="./wazuh/config/wazuh_cluster/fichiers_preconfig"
mkdir -p "$INTEG_DIR"

cat > "$INTEG_DIR/n8n_webhook.sh" <<EOF
#!/usr/bin/env bash
hook_url="${N8N_WEBHOOK_URL}"
payload=\$(cat)
curl -s -X POST -H "Content-Type: application/json" -d "\$payload" "\$hook_url"
EOF
chmod +x "$INTEG_DIR/n8n_webhook.sh"

# Copier à chaud dans le conteneur (mais il sera aussi présent via le volume)
docker cp "$INTEG_DIR/n8n_webhook.sh" "${WAZUH_MANAGER_CONTAINER}":/var/ossec/integrations/

# 3.  Injecter le snippet <integration> si absent
TMP="/tmp/n8n_integ.xml"
docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/n8n_integration_snippet.xml "${WAZUH_MANAGER_CONTAINER}":"$TMP"

docker exec "$WAZUH_MANAGER_CONTAINER" grep -q "n8n_webhook_integration" /var/ossec/etc/ossec.conf || \
docker exec "$WAZUH_MANAGER_CONTAINER" bash -c "
    sed -i '/<\/ossec_config>/{
        r $TMP
    }' /var/ossec/etc/ossec.conf
"
docker exec "$WAZUH_MANAGER_CONTAINER" rm -f "$TMP"

# 4.  Créer l’utilisateur API n8n
if ! docker exec "$WAZUH_MANAGER_CONTAINER" /var/ossec/framework/python/bin/python3 \
    /var/ossec/framework/scripts/create_user.py -l | grep -q "^n8n "; then
    
    echo ">>> Création de l'utilisateur API 'n8n' avec le rôle 'administrator'..."
    docker exec "$WAZUH_MANAGER_CONTAINER" /var/ossec/framework/python/bin/python3 \
        /var/ossec/framework/scripts/create_user.py -a -u n8n -p "n8np@ss@pi" -r administrator

    if [ $? -eq 0 ]; then
        echo "Utilisateur API 'n8n' créé avec succès."
    else
        echo "Échec de la création de l'utilisateur API 'n8n'."
    fi
    else
    echo "L'utilisateur API 'n8n' existe déjà. Aucune action nécessaire."
fi

# Restart wazuh
echo "Redémarrage du conteneur $WAZUH_MANAGER_CONTAINER..."
docker restart "$WAZUH_MANAGER_CONTAINER"
sleep 60

echo "-----------------------------------------------------------"
echo "          VÉRIFICATION FINALE DES CONTENEURS               "
echo "-----------------------------------------------------------"

ERROR_FOUND=0
while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
    ERROR_FOUND=0
    for CONTAINER_NAME in "${CONTAINERS[@]}"; do
        if [ -z "$CONTAINER_NAME" ]; then continue; fi
        CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo 'notfound')
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
        echo '||---------------------------------------------------------------------------------------||'
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
    echo "Intégration Wazuh <--> N8N finalisée avec succès."
    exit 0
fi


# echo "-----------------------------------------------------------"
# echo "             INTEGRATION WAZUH <-> N8N                     "
# echo "-----------------------------------------------------------"

# # 16. Intégration de wazuh dans N8N

# # a. Création utilisateur API n8n
# echo ">>> Vérification de l'utilisateur n8n..."
# docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_users -l | grep -q "n8n"
# if [ $? -ne 0 ]; then
#     echo ">>> Création de l'utilisateur n8n dans la Wazuh API..."
#     docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" /var/ossec/bin/manage_users -a n8n -r administrator -p "n8np@ss@pi"
# else
#     echo ">>> Utilisateur n8n déjà existant."
# fi

# # b. Copie du script d'intégration webhook
# echo ">>> Copie du script n8n_webhook.sh dans Wazuh..."
# docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/n8n_webhook.sh "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/var/ossec/integrations/n8n_webhook.sh

# echo ">>> Rendre le script exécutable..."
# docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" chmod +x /var/ossec/integrations/n8n_webhook.sh

# # c. Insertion du bloc d'intégration
# echo ">>> Copie de n8n_integration_snippet.xml dans Wazuh..."
# docker cp ./wazuh/config/wazuh_cluster/fichiers_preconfig/n8n_integration_snippet.xml "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}":/tmp/n8n_integration_snippet.xml

# echo ">>> Insertion dans ossec.conf..."
# docker exec "${GLOBAL_VARS["WAZUH_MANAGER_CONTAINER"]}" bash -c "sed -i '/<\/ossec_config>/e cat /tmp/n8n_integration_snippet.xml' /var/ossec/etc/ossec.conf"

# echo ">>> Intégration Wazuh <-> N8N terminée avec succès."