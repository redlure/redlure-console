from flask import request, render_template, flash, redirect, url_for, jsonify
from app import app, db
from app.models import User, UserSchema, Profile, ProfileSchema, Role, RoleSchema, Client, ClientSchema
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from flask_mail import Mail, Message
from app.functions import convert_to_bool, admin_login_required, user_login_required
import json


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    For POST requests, login the current user
    '''
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


@app.route('/logout')
@login_required
def logout():
    '''
    Logout the current user
    '''
    logout_user()
    return redirect(url_for('login'))


@app.route('/home')
@login_required
@user_login_required
def home():
    '''
    home page
    '''
    return 'home'


# handles requests to add users or get all users
@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_login_required
def users():
    '''
    For GET requests, return all users
    For POST requests, add a new user
    '''
    if request.method == 'GET':
        all_users = User.query.all()
        schema = UserSchema(many=True, strict=True)
        users = schema.dump(all_users)
        return jsonify(users)
    # request is a POST
    else:
        username = request.form.get('Username')
        role = request.form.get('Role')
        role = Role.query.filter_by(name=role).first()
        user = User.query.filter_by(username=username).first()
        if user is not None:
            return 'Failed to enter into DB - username taken', 400
        elif role is None:
            return 'failed to enter into database - role doesnt exist', 400
        else:
            user = User(username=username, role_id=role.id)
            user.set_password(request.form.get('Password'))
            db.session.add(user)
            db.session.commit()
            print('User %s added to the database' % username)
            return 'success', 201


@app.route('/profiles', methods=['POST', 'GET'])
@login_required
@user_login_required
def profiles():
    '''
    For GET requests, return all profiles
    For POST requests, add a new profile
    '''
    if request.method == 'GET':
        all_profiles = Profile.query.all()
        schema = ProfileSchema(many=True, strict=True)
        profiles = schema.dump(all_profiles)
        return jsonify(profiles)
    # request is a POST
    else:
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
        if profile is not None:
            return 'profile already exists', 400
        elif type(ssl_bool) == bool and type(tls_bool) == bool:
            return 'ssl/tls must be either true or false', 400
        else:
            profile = Profile(name=name, from_address=from_address, smtp_host=host, smtp_port=port, username=username, password=password, tls=tls_bool, ssl=ssl_bool)
            db.session.add(profile)
            db.session.commit()
            print('Profile %s added to the database' % name)
            return 'success', 201


@app.route('/profiles/<profile_name>', methods=['GET', 'POST', 'DELETE'])
@login_required
@user_login_required
def profile(profile_name):
    '''
    For GET requests, return the profile with the given name
    For POST requests, use the given profile to send a test email
    For DELETE requests, delete the given profile
    '''

    # request is a GET
    if request.method == 'GET':
        print (profile_name)
        profile = Profile.query.filter_by(name=profile_name).first()
        schema = ProfileSchema(strict=True)
        profile_data = schema.dump(profile)
        return jsonify(profile_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        profile = Profile.query.filter_by(name=profile_name).first()
        if profile is None:
            return 'profile does not exist', 404
        else:
            db.session.delete(profile)
            db.session.commit()
            return 'profile deleted', 204

    # request is a POST
    else:
        address = request.form.get('Address')
        profile = Profile.query.filter_by(name=profile_name).first()
        if profile is None:
            return 'Profile does not exist', 404
        else:
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


@app.route('/clients', methods=['GET', 'POST'])
@login_required
@user_login_required
def clients():
    '''
    For GET requests, return all clients
    For POST requests, add a new client
    '''
    if request.method == 'GET':
        all_clients = Client.query.all()
        schema = ClientSchema(many=True, strict=True)
        clients = schema.dump(all_clients)
        return jsonify(clients)
    else:
        # request is a POST
        name = request.form.get('Name')
        client = Client.query.filter_by(name=name).first()
        if client is None:
            client = Client(name=name)
            admins = Role.query.filter_by(role_type='Administrator').all()
            for admin in admins:
                admin.clients.append(client)
            db.session.add(client)
            db.session.commit()
            return 'success', 201
        else:
            return 'client already exists', 400


@app.route('/roles', methods=['GET', 'POST'])
@login_required
@admin_login_required
def roles():
    '''
    For GET requests, return all clients
    For POST requests, add a new client
    '''
    if request.method == 'GET':
        all_roles = Role.query.all()
        schema = RoleSchema(many=True, strict=True)
        roles = schema.dump(all_roles)
        return jsonify(roles)
    else:
        name = request.form.get('Name')
        role_type = request.form.get('Role_Type')
        role = Role.query.filter_by(name=name).first()
        if role is not None:
            return 'role already exists with that name', 400
        elif role_type.lower() not in ['administrator', 'user', 'client']:
            return 'role type not admin, user, or client', 400
        else:
            role = Role(name=name, role_type=role_type)
            db.session.add(role)
            db.session.commit()       
            return 'success', 201
    