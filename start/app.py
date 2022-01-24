import json
import os
from base64 import b64encode, b64decode
from time import time, sleep

import jwt
from Crypto.Cipher import AES
from flask_mail import Mail, Message
from flask import Flask, render_template, url_for, flash, request
from flask_bootstrap import Bootstrap
from Crypto.Util.Padding import pad, unpad
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import StringField, PasswordField, BooleanField, EmailField
from wtforms.validators import InputRequired, Email, Length, ValidationError, DataRequired, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

# import sqlite3
#
# con  = sqlite3.connect('database.db')
# con.cursor()

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = '362474070f155b'
app.config['MAIL_PASSWORD'] = '7a4e55493cbb61'
mail = Mail(app)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret'
pepper = 'JS8g7Biu87iu78b*O&bkYC$Y5cT KuuYFC'
encryption_method = 'pbkdf2:sha256:100000'
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\patri\\Desktop\\ochrona danych\\cohrona_flask_pycharm\\start\\database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def UniqueUsernameRequired(form, field):
    otheruser = User.query.filter_by(username=form.username.data).first()
    if otheruser:
        raise ValidationError("Username Taken")


def UniqueEmailRequired(form, field):
    otheruser = User.query.filter_by(email=form.email.data).first()
    if otheruser:
        raise ValidationError("Email already registered")


def send_email(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Password Reset"
    msg.sender = app.config['MAIL_USERNAME']
    msg.recipients = [user.email]
    msg.html = render_template('reset_email.html', user=user, token=token)

    mail.send(msg)


def encrypt_value(key, data_to_encrypt):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_to_encrypt.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    return result


def decrypt_value(key, data_to_decrypt):
    data_to_decrypt = json.loads(data_to_decrypt)
    iv = b64decode(data_to_decrypt['iv'])
    ct = b64decode(data_to_decrypt['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    key = db.Column(db.String(16))
    passwords = db.relationship('Passwords', backref='user', lazy=True)

    def __repr__(self):
        return f" Id: {self.id} \n Username: {self.username} \n Email: {self.email} \n Password: {self.password} \n"

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.username, 'exp': time() + expires}, key=app.config['SECRET_KEY'],
                          algorithm='HS256')

    @staticmethod
    def verify_reset_token(token):
        try:
            username = jwt.decode(token, key=app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(username=username).first()


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(30))
    login = db.Column(db.String(50))
    password = db.Column(db.String(80))

    def __init__(self, appName, login, password, userId):
        self.name = appName
        self.login = login
        self.password = password
        self.user_id = userId


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Current password', validators=[InputRequired(), Length(min=8, max=80)])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80),
                                                             EqualTo('confirm', message='New passwords must match')])
    confirm = PasswordField('Repeat New Password')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15), UniqueUsernameRequired])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50),
                                             UniqueEmailRequired])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80),
                                                     EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')


class ForgotForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(message='Invalid email'), Length(max=50)])


class PasswordResetForm(FlaskForm):
    new_password = PasswordField('New password', validators=[DataRequired(), Length(min=8, max=80)])
    confirm = PasswordField('Repeat Password')


class CheckPasswordForm(FlaskForm):
    password = PasswordField('Your password', validators=[DataRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()

    if form.validate_on_submit():
        sleep(3)
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(encryption_method + '$' + user.password, form.password.data + pepper):
                login_user(user, remember=form.remember.data)
                flash('You were successfully logged in!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password or username!')
                return render_template('login.html', form=form)
        else:
            flash('Invalid password or username!')
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()

    if form.validate_on_submit():
        method, salt, hash = generate_password_hash(form.password.data + pepper, method=encryption_method,
                                                    salt_length=24).split('$')
        hashed_password = salt + '$' + hash
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,
                        key=os.urandom(16))
        db.session.add(new_user)
        db.session.commit()
        flash('New user created succesfully!')
        return redirect(url_for('login'))
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/passwd_change', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if form.new_password.data == form.old_password.data:
            flash('New password must be different from old one.')
            return render_template('change_password.html', form=form)
        user_got = User.query.filter_by(username=current_user.username).first()
        if current_user:
            if check_password_hash(encryption_method + '$' + user_got.password, form.old_password.data + pepper):
                method, salt, hash = generate_password_hash(form.new_password.data + pepper,
                                                            method=encryption_method, salt_length=24).split('$')
                hashed_password = salt + '$' + hash
                user_got.password = hashed_password
                db.session.commit()
                flash('Password changed successfully!')
                return redirect(url_for('login'))
            else:
                flash('Current password input incorrect')

    return render_template('change_password.html', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = ForgotForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            send_email(user)

        flash('You will receive an email, if there is a user with such email address.')
        return redirect(url_for('index'))

    return render_template('forgot.html', form=form)


@app.route('/password_reset_verified/<token>', methods=['GET', 'POST'])
def reset_verified(token):
    form = PasswordResetForm()

    if form.validate_on_submit():
        user = User.verify_reset_token(token)
        if not user:
            return redirect(url_for('index'))

        method, salt, hash = generate_password_hash(form.new_password.data + pepper, method=encryption_method,
                                                    salt_length=24).split('$')
        hashed_password = salt + '$' + hash
        user.password = hashed_password
        db.session.commit()
        flash('Password changed successfully!')
        return redirect(url_for('login'))

    return render_template('reset_verified.html', form=form)


@app.route('/insert', methods=['POST'])
@login_required
def insert():
    if request.method == 'POST':
        webappFromDash = request.form['webapp']
        loginFromDash = encrypt_value(current_user.key, request.form['login'])
        passwordFromDash = encrypt_value(current_user.key, request.form['password'])
        userID = current_user.id

        my_data = Passwords(webappFromDash, loginFromDash, passwordFromDash, userID)
        db.session.add(my_data)
        db.session.commit()

        flash("Added new password")
        return redirect(url_for('dashboard'))


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    if request.method == 'POST':
        my_data = Passwords.query.get(request.form.get('id'))

        my_data.appName = request.form['webapp']
        my_data.login = encrypt_value(current_user.key, request.form['login'])
        my_data.password = encrypt_value(current_user.key, request.form['password'])

        db.session.commit()
        flash("Password Updated Successfully")

        return redirect(url_for('dashboard'))


@app.route('/delete/<id>/', methods=['GET', 'POST'])
@login_required
def delete(id):
    my_data = Passwords.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Password Deleted Successfully")

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=current_user.username).first()
    passwords_list = user.passwords
    visible_passwords_list = []
    for item in passwords_list:
        visible_passwords_list.append(
            {'id': item.id, 'name': item.name, 'login': decrypt_value(current_user.key, item.login),
             'password': decrypt_value(current_user.key, item.password)})
    return render_template('dashboard.html', password_list=visible_passwords_list)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, ssl_context=('pm.test.crt', 'pm.test.key'))
