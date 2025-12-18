from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, \
    login_required, logout_user, current_user

from functools import wraps
import hashlib
import hmac
import os
import re
import uuid

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_hash: str, password: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_password(password))

def simple_secure_filename(filename: str) -> str:
    name, ext = os.path.splitext(filename)
    name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    if not name:
        name = uuid.uuid4().hex
    return name + ext.lower()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///biysk_districts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'districts')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = hash_password(password)

    def check_password(self, password):
        return verify_password(self.password_hash, password)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    district_id = db.Column(db.Integer, db.ForeignKey('district.id', ondelete='CASCADE'), nullable=False)

class District(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(255))
    reviews = db.relationship(
        'Review',
        backref='district',
        lazy=True,
        cascade='all, delete-orphan'
    )
    images = db.relationship(
        'DistrictImage',
        backref='district',
        lazy=True,
        cascade='all, delete-orphan'
    )

class DistrictImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    district_id = db.Column(db.Integer, db.ForeignKey('district.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    districts = District.query.all()
    return render_template('index.html', districts=districts)

@app.route('/district/<int:district_id>', methods=['GET', 'POST'])
def district_detail(district_id):
    district = District.query.get_or_404(district_id)

    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Чтобы оставить отзыв, войдите на сайт.', 'danger')
            return redirect(url_for('login', next=url_for('district_detail',
                                                          district_id=district.id)))

        rating = int(request.form.get('rating', 0))
        comment = request.form.get('comment', '')
        if 1 <= rating <= 5:
            review = Review(
                rating=rating,
                comment=comment,
                user_id=current_user.id,
                district_id=district.id
            )
            db.session.add(review)
            db.session.commit()
            flash('Отзыв добавлен.', 'success')
        else:
            flash('Оценка должна быть от 1 до 5.', 'danger')
        return redirect(url_for('district_detail', district_id=district.id))

    reviews = Review.query.filter_by(district_id=district.id).all()
    return render_template('district_detail.html',
                           district=district,
                           reviews=reviews)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        if not username or not email or not password:
            flash('Все поля обязательны.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Пользователь с таким логином или email уже существует.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна, войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Вы вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@admin_required
def admin_index():
    users = User.query.all()
    districts = District.query.all()
    reviews = Review.query.all()
    return render_template('admin/index.html',
                           users=users,
                           districts=districts,
                           reviews=reviews)

@app.route('/admin/districts/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_district():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '')
        if not name:
            flash('Название обязательно.', 'danger')
            return redirect(url_for('admin_add_district'))

        d = District(name=name, description=description)
        db.session.add(d)
        db.session.flush()

        files = request.files.getlist('images')
        for file in files:
            if file and file.filename:
                filename = simple_secure_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                img = DistrictImage(filename=filename, district_id=d.id)
                db.session.add(img)

        db.session.commit()
        flash('Район добавлен.', 'success')
        return redirect(url_for('admin_index'))

    return render_template('admin/add_district.html')

@app.route('/admin/districts/<int:district_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_district(district_id):
    district = District.query.get_or_404(district_id)

    db.session.delete(district)
    db.session.commit()
    flash('Район, его отзывы и изображения удалены.', 'info')
    return redirect(url_for('admin_index'))

@app.route('/admin/reviews/<int:review_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    district_id = review.district_id
    db.session.delete(review)
    db.session.commit()
    flash('Отзыв удалён.', 'info')
    return redirect(url_for('district_detail', district_id=district_id))

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

