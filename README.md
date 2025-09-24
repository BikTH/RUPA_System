# RUPA System – Guide de Déploiement

Ce document explique comment déployer la solution RUPA System sur un serveur de sécurité (Linux) et comment installer les agents sur les postes Windows.

## 1. Déploiement du serveur de sécurité (Linux)

### Prérequis
- Système Linux (Ubuntu recommandé)
- Accès root (sudo)
- Connexion Internet

### Étapes d'installation

#### a. Lancement de l'installation principale

1. **Rendez le script exécutable** (si besoin) :
   ```bash
   chmod +x install.sh post_install.sh
   ```
2. **Lancez le script d'installation** :
   ```bash
   sudo ./install.sh
   ```
   Ce script :
   - Met à jour le système et installe les dépendances (Docker, etc.)
   - Télécharge les images Docker nécessaires
   - Configure les variables d'environnement et les fichiers de configuration
   - Génère les certificats SSL
   - Configure les interfaces réseau (Suricata, services)
   - Lance la stack Docker (Wazuh, Suricata, N8N, Reverse Proxy, etc.)
   - Intègre Suricata à Wazuh et prépare l'active response pour Windows

3. **Suivez les instructions à l'écran** pour renseigner les informations demandées (réseaux, certificats, interfaces, etc.).

#### b. Configuration post-installation (intégration N8N <-> Wazuh)

Après le premier démarrage, il est recommandé d'exécuter le script de post-installation pour finaliser l'intégration avec N8N :

```bash
sudo ./post_install.sh
```

Ce script :
- Vérifie l'état des conteneurs
- Demande l'URL du webhook N8N
- Déploie le script d'intégration dans Wazuh
- Crée l'utilisateur API `n8n` dans Wazuh
- Redémarre le conteneur Wazuh Manager

## 2. Déploiement des agents sur Windows

Pour chaque poste Windows à superviser, procédez comme suit :

1. **Copiez le dossier `scripts/windows_agent_install/` sur le poste Windows**
2. **Ouvrez un terminal PowerShell en mode administrateur**
3. **Lancez le script d'installation** :
   ```powershell
   .\install_wazuh_agent.ps1
   ```
4. **Suivez les instructions** :
   - Saisissez l'adresse IP ou le FQDN du serveur Wazuh Manager (récupérable lors de l'installation du serveur)
   - Le script télécharge et installe l'agent, configure les scripts de réponse active, et adapte le fichier `ossec.conf`

## 3. Accès à la plateforme

- **Wazuh Dashboard** : https://[IP_SERVICES]
  - Utilisateur : `admin`
  - Mot de passe : `SecretPassword`
- **N8N** : http://[IP_SERVICES]:5678
  - Utilisateur/mot de passe par défaut définis lors de l'installation

## 4. Notes complémentaires

- Les scripts d'installation sont interactifs et adaptent la configuration à votre environnement.
- Pour toute modification réseau ou intégration supplémentaire, relancez les scripts `install.sh` ou `post_install.sh`.
- Les scripts PowerShell pour les agents Windows déploient aussi les scripts de réponse active (antivirus, blocage IP).

## 5. Dépannage

- Vérifiez l'état des conteneurs avec :
  ```bash
  docker-compose ps
  docker-compose logs
  ```
- Pour relancer la stack :
  ```bash
  docker-compose up -d
  ```
- Pour toute question, consultez la documentation ou contactez l'équipe RUPA.

---

© 2025 RUPA System
