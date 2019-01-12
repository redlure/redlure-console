from flask import request, render_template, flash, redirect, url_for, jsonify
from app import app, db
from app.forms import LoginForm
from app.models import User, UserSchema, Profile, ProfileSchema
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from flask_mail import Mail, Message
from app.functions import convert_to_bool
import json


# URL posted to for logins
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        print('User is already authenticated')
        return redirect(url_for('home'))

    username = request.form.get('Username')
    if username is not None:
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(request.form.get('Password')):
            print('invalid username or password')
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            print('redirecting to home')
            next_page = url_for('home')
        return redirect(next_page)
    return 'login page'


# URL called for session logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# URL directed to after successful login
@app.route('/home')
@login_required
def home():
    return 'home'


# URL accepting post data to add another user to the database
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('Username')
    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username)
        user.set_password(request.form.get('Password'))
        db.session.add(user)
        db.session.commit()
        print('User %s added to the database' % username)
        return 'success'
    else:
        print('That username already exists in the database')
        return 'failed to enter into database'


# URL returning JSON object of all users in the database
@app.route('/manage_users')
@login_required
def manage_users():
    all_users = User.query.all()
    schema = UserSchema(many=True, strict=True)
    users = schema.dump(all_users)
    return jsonify(users)


# URL returning JSON object of all sending profiles in the database
@app.route('/manage_profiles')
@login_required
def manage_profiles():
    all_profiles = Profile.query.all()
    schema = ProfileSchema(many=True, strict=True)
    profiles = schema.dump(all_profiles)
    return jsonify(profiles)


# URL accepting post data to add sending profile to the database
@app.route('/add_profile', methods=['POST'])
@login_required
def add_profile():
    name = request.form.get('Name')
    from_address = request.form.get('From_Address')
    host = request.form.get('SMTP_Host')
    port = request.form.get('SMTP_Port')
    username = request.form.get('Username')
    password = request.form.get('Password')
    tls = request.form.get('TLS')
    ssl = request.form.get('SSL')
   
    profile = Profile.query.filter_by(name=name).first()
    ssl_bool = convert_to_bool(ssl)
    tls_bool = convert_to_bool(tls)
    if profile is None and type(ssl_bool) == bool and type(tls_bool) == bool:
        profile = Profile(name=name, from_address=from_address, smtp_host=host, smtp_port=port, username=username, password=password, tls=tls_bool, ssl=ssl_bool)
        db.session.add(profile)
        db.session.commit()
        print('Profile %s added to the database' % name)
        return 'success'
    else:
        print('failed to enter into database')
        return 'failed to enter into database'


# URL accepting post data to send a test email from a specific sending profile
@app.route('/profile_test', methods=['POST'])
@login_required
def profile_test():
    address = request.form.get('Address')
    name = request.form.get('Profile_Name')
    profile = Profile.query.filter_by(name=name).first()
    if profile is not None:
        mail = Mail(app)
        app.config['MAIL_SERVER'] = profile.smtp_host
        app.config['MAIL_PORT'] = profile.smtp_port
        app.config['MAIL_USERNAME'] = profile.username
        app.config['MAIL_PASSWORD'] = profile.password
        app.config['MAIL_USE_TLS'] = profile.tls
        app.config['MAIL_USE_SSL'] = profile.ssl
        mail = Mail(app)
        msg = Message('Hello', sender = profile.from_address, recipients = [address])
        msg.html = "<text>Hello Flask message sent from Flask-Mail</text>"
        mail.send(msg)
        return 'Test email sent'
    else:
        return 'Profile does not exist'