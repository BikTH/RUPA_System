#!/usr/bin/env bash

hook_url="http://n8n:5678/webhook/alert"  # ou "http://localhost:5678/webhook/alert"

# Lire la donnée JSON depuis stdin
alert_data="$(cat)"

# Envoyer vers n8n en POST
curl -X POST -H "Content-Type: application/json" -d "$alert_data" "$hook_url"
