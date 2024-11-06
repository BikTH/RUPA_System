#!/bin/bash

# Remplacer la variable ${WAZUH_MANAGER_IP} dans ossec.conf par la valeur de l'environnement
sed -i "s/\${WAZUH_MANAGER_IP}/${WAZUH_MANAGER_IP}/g" /var/ossec/etc/ossec.conf
# sed -i "s|\${WAZUH_MANAGER_IP}|${WAZUH_MANAGER_IP}|g" /var/ossec/etc/ossec.conf

# Démarrer l'agent Wazuh et Suricata
# service wazuh-agent start
# exec suricata -c /etc/suricata/suricata.yaml

# Démarrer l'agent Wazuh
/var/ossec/bin/wazuh-control start

# Démarrer Suricata
# exec /usr/bin/suricata -c /etc/suricata/suricata.yaml -s /etc/suricata/rules/signatures.rules -i ${INT_TO_LISTEN}
exec /usr/bin/suricata -c /etc/suricata/suricata.yaml -i ${INT_TO_LISTEN}
