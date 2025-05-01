#!/usr/bin/env bash
set -e
source /var/lib/rupa/rupa.env
cd "$(dirname "$0")/../.."   # racine docker-compose

# --- liste de conteneurs de référence ---
TARGETS=(
  "$WAZUH_MANAGER_CONTAINER"
  "$WAZUH_INDEXER_CONTAINER"
  "$NGINX_CONTAINER"
  "$WAZUH_DASHBOARD_CONTAINER"
  "$WAZUH_SURICATA_CONTAINER"
  "$EVEBOX_CONTAINER"
  "$POSTGRES_CONTAINER"
  "$N8N_CONTAINER"
)

running_ok=0
for c in "${TARGETS[@]}"; do
    if [ -n "$c" ] && docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        running_ok=1 ; break
    fi
done

if [ "$running_ok" -eq 1 ]; then
    echo "Stack RUPA déjà lancée."
    read -rp "[R]edémarrer / [A]rreter / [X]Retour : " ans
    case "$ans" in
        r|R) docker compose restart ;;
        s|S) docker compose down ;;
        *)   echo "Retour menu";;
    esac
else
    echo "Stack RUPA stoppée --> démarrage…"
    docker compose up -d
fi
