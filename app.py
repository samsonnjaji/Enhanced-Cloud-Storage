import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////tmp/cloud_storage.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', files=user_files)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        filename = request.form.get('filename')
        if filename:
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('No filename provided!', 'danger')
    return render_template('upload.html')

@app.route('/update/<int:file_id>', methods=['GET', 'POST'])
@login_required
def update(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        new_filename = request.form.get('new_filename')
        if new_filename:
            file.filename = new_filename
            db.session.commit()
            flash('File updated successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('No filename provided!', 'danger')
    return render_template('update.html', file=file)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('index'))
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
            else:
                new_user = User(username=username)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
