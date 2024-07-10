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

if __name__ == '__main__':
    app.run(debug=True, port=5002)
