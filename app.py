from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
import secrets
from flask_login import LoginManager, login_user, logout_user, UserMixin, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config



app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)


login_manager = LoginManager()  #gestionnaire de sessions de connexion (LoginManager).
login_manager.init_app(app)
login_manager.login_view = 'login' #Cette ligne définit la vue de connexion par défaut


class User(UserMixin, db.Model): #UserMinin permet au modele d'herite de plusieurs methode importante necessaire pour de flask_login
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(500))
    tasks = db.relationship('Task', backref='author', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_echeance = db.Column(db.DateTime, nullable=True, default=db.func.current_timestamp())
    etat = db.Column(db.String(20), nullable=False, default='à faire')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#Elle assure que seuls les utilisateurs valides peuvent être récupérés et que les actions sensibles nécessitent une vérification de l'identité de l'utilisateur.
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, int(user_id))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required #Flask-Login vérifie si l'utilisateur actuel est authentifié sinon  Flask-Login redirige automatiquement l'utilisateur vers la vue spécifiée par login_manager.login_view = 'login'
def dashboard():
    if request.method == 'POST':
        filter_etat = request.form.get('filter_etat')
        if filter_etat:
            tasks = Task.query.filter_by(user_id=current_user.id, etat=filter_etat).all()
        else:
            tasks = Task.query.filter_by(user_id=current_user.id).all()
    else:
        tasks = Task.query.all()

    return render_template('dashboard.html', tasks=tasks)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Vous vous êtes connecté avec succes', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect !!!')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            flash('Ce nom d\'utilisateur est déjà pris. Veuillez en choisir un autre.')
            return redirect(url_for('login'))
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        etat = request.form['etat']
        new_task = Task(title=title, description=description, etat=etat, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash('Nouvelle tâche créée avec succès!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('/partials/_form.html')


@app.route('/update/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('Vous n\'ête pas autorisé a modifier cette tache !!!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        task.etat = request.form['etat']
        db.session.commit()
        flash('Tâche mise à jour avec succès!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('/partials/_form.html', task=task, user=current_user)


@app.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à supprimer cette tâche !!!', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(task)
    db.session.commit()
    flash('Tâche supprimer avec succès!', 'success')
    return redirect(url_for('dashboard'))



@app.route('/profil', methods=['GET', 'POST'])
@login_required
def profil():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('Veuillez remplir tous les champs', 'danger')
            return redirect(url_for('profil'))
        
        current_user.username = username
        current_user.email = email
        current_user.password = generate_password_hash(password)
        
        try:
            db.session.commit()
            flash('Le profil a été mis à jour avec succès!', 'success')
            return redirect(url_for('profil'))
        except Exception as e:
            flash(f'Erreur lors de la mise à jour du profil : {str(e)}', 'danger')
            return redirect(url_for('profil'))
    
    return render_template('/partials/_profil.html', user=current_user)




# # Fonction pour générer un token sécurisé
# def generate_reset_token():
#     return secrets.token_urlsafe(32)

# # Route pour la demande de réinitialisation de mot de passe
# @app.route('/reset_password_request', methods=['GET', 'POST'])
# def reset_password_request():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         # Recherchez l'utilisateur par son adresse e-mail dans la base de données
#         user = User.query.filter_by(email=email).first()
#         if user:
#             # Générer un token de réinitialisation
#             token = generate_reset_token()
#             user.reset_password_token = token
#             db.session.commit()

#             # Envoyer un e-mail de réinitialisation avec le lien
#             reset_url = url_for('reset_password', token=token, _external=True)
#             msg = Message('Réinitialisation de mot de passe', sender='votre_email@example.com', recipients=[email])
#             msg.body = f'Pour réinitialiser votre mot de passe, veuillez cliquer sur ce lien : {reset_url}'
#             mail.send(msg)

#             flash('Un e-mail a été envoyé avec les instructions pour réinitialiser votre mot de passe.', 'success')
#             return redirect(url_for('login'))
#         else:
#             flash('Aucun utilisateur trouvé avec cette adresse e-mail.', 'danger')
#     return render_template('reset_password_request.html')

# # Route pour la réinitialisation de mot de passe
# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     user = User.query.filter_by(reset_password_token=token).first()
#     if user:
#         if request.method == 'POST':
#             password = request.form.get('password')
#             # Mettre à jour le mot de passe de l'utilisateur
#             user.password = generate_password_hash(password)
#             user.reset_password_token = None  # Effacer le token après réinitialisation
#             db.session.commit()
#             flash('Votre mot de passe a été réinitialisé avec succès.', 'success')
#             return redirect(url_for('login'))
#         return render_template('reset_password.html', token=token)
#     else:
#         flash('Ce lien de réinitialisation de mot de passe est invalide ou a expiré.', 'danger')
#         return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
