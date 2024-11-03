from flask import Flask, render_template, request, redirect, url_for, session
import requests
import os

app = Flask(__name__)
# Définir une clé secrète par défaut sécurisée
default_secret_key = 'uneCléTrèsSécureParDéfaut123!@#'

# Utiliser la variable d'environnement si elle est définie, sinon utiliser la clé par défaut
app.secret_key = os.environ.get('SECRET_KEY', default_secret_key)

# Fichier d'utilisateurs stockés en local
UTILISATEURS = {
    'admin': {
        'password': 'motdepasse123',
        'role': 'admin',
        'dashboards': ['wazuh', 'kibana']
    },
    'admin_systeme': {
        'password': 'password',
        'role': 'admin_systeme',
        'dashboards': ['wazuh']
    },
    'admin_reseau': {
        'password': 'password',
        'role': 'admin_reseau',
        'dashboards': ['kibana']
    }
}


# Informations de l'API Wazuh
WAZUH_API_URL = 'https://wazuh.manager:55000'
WAZUH_API_USER = 'wazuh-wui'
WAZUH_API_PASSWORD = 'MyS3cr37P450r.*-'

# Désactiver les warnings SSL pour les requêtes
requests.packages.urllib3.disable_warnings()

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vérification correcte du mot de passe
        if username in UTILISATEURS and UTILISATEURS[username]['password'] == password:
            session['username'] = username
            session['role'] = UTILISATEURS[username]['role']
            session['dashboards'] = UTILISATEURS[username]['dashboards']
            # Créer une session sur Wazuh
            token = create_wazuh_session(username, password)
            if token:
                session['wazuh_token'] = token
                return redirect(url_for('dashboard'))
            else:
                session.pop('username', None)
                return render_template('login.html', error='Échec de la connexion à Wazuh')
        else:
            return render_template('login.html', error='Nom d\'utilisateur ou mot de passe incorrect')
    return render_template('login.html')


def create_wazuh_session():
    """Crée une session sur Wazuh et retourne le jeton d'authentification."""
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    response = requests.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD), verify=False)
    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        print("Erreur lors de la connexion à Wazuh:", response.text)
        return None



@app.route('/dashboard')
def dashboard():
    # Vérifiez si 'username' et 'dashboards' sont présents dans la session
    if 'username' in session and 'dashboards' in session:
        return render_template('dashboard.html', username=session['username'], user_dashboards=session['dashboards'])
    else:
        # Supprimez la session et redirigez vers la page de login si les clés ne sont pas présentes
        session.clear()
        return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session.get('role') == 'admin':
        return render_template('manage_users.html', users=UTILISATEURS)
    else:
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Déconnecte l'utilisateur et supprime le jeton Wazuh de la session."""
    if 'wazuh_token' in session:
        delete_wazuh_session(session['wazuh_token'])
    session.clear()
    return redirect(url_for('login'))

def delete_wazuh_session(token):
    """Supprime le jeton de session dans Wazuh."""
    url = f"{WAZUH_API_URL}/security/user/logout"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 200:
        print("Déconnexion réussie de Wazuh")
    else:
        print("Erreur lors de la déconnexion de Wazuh:", response.text)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
