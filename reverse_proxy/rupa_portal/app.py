from flask import Flask, render_template, request, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète'  # À changer pour une clé secrète sécurisée

# Fichier d'utilisateurs stockés en local
UTILISATEURS = {
    'admin': 'motdepasse123',
    'user': 'password'
}

# URL de l'API Wazuh
WAZUH_API_URL = 'https://wazuh-dashboard:55000'

# Désactiver les warnings SSL pour les requêtes
requests.packages.urllib3.disable_warnings()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in UTILISATEURS and UTILISATEURS[username] == password:
            session['username'] = username
            # Créer une session sur Wazuh
            token = create_wazuh_session(username, password)
            session['wazuh_token'] = token
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Nom d\'utilisateur ou mot de passe incorrect')
    return render_template('login.html')

def create_wazuh_session(username, password):
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    response = requests.post(url, auth=(username, password), verify=False)
    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        return None

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
