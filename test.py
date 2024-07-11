# test.py

from flask import Flask
from flask_mail import Mail, Message
from config import Config  # Importez votre configuration depuis config.py

app = Flask(__name__)
app.config.from_object(Config)  # Utilisez la configuration définie dans Config

mail = Mail(app)  # Initialisez l'extension Flask-Mail

@app.route('/send_test_email')
def send_test_email():
    try:
        msg = Message('Test Email', recipients=['recipient@example.com'])
        msg.body = 'This is a test email sent from Flask-Mail.'
        mail.send(msg)
        return 'Email sent successfully!'
    except Exception as e:
        return str(e)
    

from werkzeug.security import generate_password_hash

# Hacher le mot de passe
password = 'admin1'
hashed_password = generate_password_hash(password)
print(hashed_password)

from app import db
from app import User

# Créer un utilisateur admin
admin_user = User(username='admin', email='admin@example.com', password=generate_password_hash('admin1'), is_admin=True)

# Ajouter et valider dans la base de données
db.session.add(admin_user)
db.session.commit()



from werkzeug.security import generate_password_hash
from app import db
from app import User

hashed_password = generate_password_hash('admin1')

admin_user = User(username='admin 1', email='admin1@example.com', password=hashed_password, is_admin=True)

db.session.add(admin_user)
db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, port=5002)
