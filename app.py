from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint
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
    reset_password_token = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
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



@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.is_admin:
                # Connexion réussie en tant qu'administrateur
                login_user(user)
                flash('Vous êtes maintenant connecté en tant qu\'administrateur.', 'success')
                return redirect(url_for('admin.admin_dashboard'))
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
        is_admin = request.form.get('is_admin') == 'on'
        
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            flash('Ce nom d\'utilisateur est déjà pris. Veuillez en choisir un autre.')
            return redirect(url_for('login'))
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password), is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')


def generate_reset_token():
    return secrets.token_urlsafe(32)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token()
            user.reset_password_token = token
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Réinitialisation de mot de passe', sender='you@example.com', recipients=[email])
            msg.body = f'Pour réinitialiser votre mot de passe, veuillez cliquer sur ce lien : {reset_url}'
            mail.send(msg)

            flash('Un email a été envoyé avec les instructions pour réinitialiser votre mot de passe.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Aucun utilisateur trouvé avec cette adresse email.', 'danger')
    return render_template('/partials/_reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_password_token=token).first()
    if user:
        if request.method == 'POST':
            password = request.form.get('password')
            user.password = generate_password_hash(password)
            user.reset_password_token = None
            db.session.commit()
            flash('Votre mot de passe a été réinitialisé avec succès.', 'success')
            return redirect(url_for('login'))
        return render_template('/partials/_reset_password.html', token=token)
    else:
        flash('Ce lien de réinitialisation de mot de passe est invalide ou a expiré.', 'danger')
        return redirect(url_for('login'))
    
    
@app.route('/send_test_email')
def send_test_email():
    try:
        msg = Message('Test Email', recipients=['daoudasoum14@gmail.com'])
        msg.body = 'Ce ci est un test de mail depuis Flask-Mail.'
        mail.send(msg)
        return 'Email envoyé avec succes!'
    except Exception as e:
        return str(e)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required  # Flask-Login vérifie si l'utilisateur actuel est authentifié sinon Flask-Login redirige automatiquement l'utilisateur vers la vue spécifiée par login_manager.login_view = 'login'
def dashboard():
    filter_etat = 'all'
    if request.method == 'POST':
        filter_etat = request.form.get('filter_etat')
        if filter_etat and filter_etat != 'all':
            tasks = Task.query.filter_by(user_id=current_user.id, etat=filter_etat).all()
        else:
            tasks = Task.query.filter_by(user_id=current_user.id).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id).all()

    return render_template('dashboard.html', tasks=tasks, filter_etat=filter_etat)



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
        is_admin = request.form.get('is_admin')
        
        if not username or not email or not password:
            flash('Veuillez remplir tous les champs', 'danger')
            return redirect(url_for('profil'))
        
        current_user.username = username
        current_user.email = email
        current_user.password = generate_password_hash(password)
        current_user.is_admin = True if is_admin else False
        
        try:
            db.session.commit()
            flash('Le profil a été mis à jour avec succès!', 'success')
            return redirect(url_for('profil'))
        except Exception as e:
            flash(f'Erreur lors de la mise à jour du profil : {str(e)}', 'danger')
            return redirect(url_for('profil'))
    
    return render_template('/partials/_profil.html', user=current_user)





admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les autorisations nécessaires pour accéder à cette page.', 'danger')
        return redirect(url_for('dashboard'))  # Redirige l'utilisateur non-admin vers le tableau de bord utilisateur normal
    
    users = User.query.all()  # Récupère tous les utilisateurs
    tasks = Task.query.all()  # Récupère toutes les tâches
    
    return render_template('/admin/dashboard.html', users=users, tasks=tasks)

@admin_bp.route('/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les autorisations nécessaires pour accéder à cette page.', 'danger')
        return redirect(url_for('dashboard'))  # Redirige l'utilisateur non-admin vers le tableau de bord utilisateur normal
    
    users = User.query.all()  # Récupère tous les utilisateurs
    
    return render_template('admin/users.html', users=users)

@admin_bp.route('/tasks')
@login_required
def manage_tasks():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les autorisations nécessaires pour accéder à cette page.', 'danger')
        return redirect(url_for('dashboard'))  # Redirige l'utilisateur non-admin vers le tableau de bord utilisateur normal
    
    tasks = Task.query.all()  # Récupère toutes les tâches
    
    return render_template('admin/tasks.html', tasks=tasks)

# Enregistrez le Blueprint de l'administration
app.register_blueprint(admin_bp)

if __name__ == '__main__':
    app.run(debug=True, port=5003)
