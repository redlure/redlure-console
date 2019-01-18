from flask import request, render_template, flash, redirect, url_for, jsonify
from app import app, db
from app.models import User, UserSchema, Profile, ProfileSchema, Role, RoleSchema, Workspace, WorkspaceSchema, List, ListSchema, Person, PersonSchema, Campaign, CampaignSchema, Domain, DomainSchema, Email, EmailSchema
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from flask_mail import Mail, Message
from app.functions import convert_to_bool, admin_login_required, user_login_required, validate_email_format
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


@app.route('/domains', methods=['GET', 'POST'])
@login_required
@user_login_required
def domains():
    '''
    For GET requests, return all domains
    For POST requests, add a new domain
    '''

    # request is a GET
    if request.method == 'GET':
        all_domains = Domain.query.all()
        schema = DomainSchema(many=True, strict=True)
        domain_data = schema.dump(all_domains)
        return jsonify(domain_data)

    # request is a POST
    elif request.method == 'POST':
        domain = request.form.get('Domain')
        cert_path = request.form.get('Cert_Path')
        key_path = request.form.get('Key_Path')

        domain_obj = Domain.query.filter_by(domain=domain).first()
        if domain_obj is not None:
            return 'domain already exists', 400
        
        domain_obj = Domain(domain=domain, cert_path=cert_path, key_path=key_path)
        domain_obj.update_ip()
        db.session.add(domain_obj)
        db.session.commit()
        return 'domain added', 201


@app.route('/domains/refresh', methods=['GET'])
@login_required
@user_login_required
def refresh_domains():
    all_domains = Domain.query.all()
    for domain in all_domains:
        domain.update_ip()
    db.session.commit()
    return redirect('/domains')


@app.route('/domains/<domain_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def domain(domain_id):
    '''
    For GET requests, return the given domain (and refresh the IP in case of update)
    For PUT requests, update the existing domain
    FOR DELETE requests, delete the given domain
    '''

    domain_obj = Domain.query.filter_by(id=domain_id).first()
    if domain_obj is None:
        return 'domain does not exist', 404

    # request is a GET
    if request.method == 'GET':
        domain_obj.update_ip()
        schema = DomainSchema(strict=True)
        domain_data = schema.dump(domain_obj)
        return jsonify(domain_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(domain_obj)
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        domain = request.form.get('Domain')
        cert_path = request.form.get('Cert_Path')
        key_path = request.form.get('Key_Path')

        domain_obj.domain = domain
        domain_obj.cert_path = cert_path
        domain_obj.key_path = key_path
        domain_obj.update_ip()
        db.session.commit()
        return 'domain updated'


@app.route('/workspaces/<workspace_id>/profiles', methods=['POST', 'GET'])
@login_required
@user_login_required
def profiles(workspace_id):
    '''
    For GET requests, return all profiles
    For POST requests, add a new profile
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    if request.method == 'GET':
        all_profiles = Profile.query.filter_by(workspace_id=workspace_id).all()
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
        elif type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400
        else:
            profile = Profile(name=name, from_address=from_address, smtp_host=host, smtp_port=port, \
                username=username, password=password, tls=tls_bool, ssl=ssl_bool, workspace_id=workspace_id)
            db.session.add(profile)
            db.session.commit()
            print('Profile %s added to the database' % name)
            return 'success', 201


@app.route('/workspaces/<workspace_id>/profiles/<profile_id>', methods=['GET', 'POST', 'DELETE', 'PUT'])
@login_required
@user_login_required
def profile(workspace_id, profile_id):
    '''
    For GET requests, return the profile with the given name
    For POST requests, use the given profile to send a test email
    For DELETE requests, delete the given profile
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    profile = Profile.query.filter_by(id=profile_id, workspace_id=workspace_id).first()
    if profile is None:
        return 'profile does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ProfileSchema(strict=True)
        profile_data = schema.dump(profile)
        return jsonify(profile_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(profile)
        db.session.commit()
        return 'profile deleted', 204

    # request is a POST
    elif request.method == 'POST':
        address = request.form.get('Address')
        if not validate_email_format(address):
            return 'Enter a valid email address', 400
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
            return 'Test email sent', 200
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        from_address = request.form.get('From_Address')
        host = request.form.get('SMTP_Host')
        port = request.form.get('SMTP_Port')
        username = request.form.get('Username')
        password = request.form.get('Password')
        tls = request.form.get('TLS')
        ssl = request.form.get('SSL')

        ssl_bool = convert_to_bool(ssl)
        tls_bool = convert_to_bool(tls)

        if type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400
        else:
            profile.name = name
            profile.from_address = from_address
            profile.smtp_host = host
            profile.smtp_port = port
            profile.username = username
            profile.password = password
            profile.tls = tls_bool
            profile.ssl = ssl_bool
            profile.workspace_id = workspace_id

            db.session.commit()
            return 'updated', 200


@app.route('/workspaces', methods=['GET', 'POST'])
@login_required
@user_login_required
def workspaces():
    '''
    For GET requests, return all workspaces
    For POST requests, add a new workspace
    '''
    if request.method == 'GET':
        all_workspaces = Workspace.query.all()
        schema = WorkspaceSchema(many=True, strict=True)
        workspaces = schema.dump(all_workspaces)
        return jsonify(workspaces)
    else:
        # request is a POST
        name = request.form.get('Name')
        workspace = Workspace.query.filter_by(name=name).first()
        if workspace is None:
            workspace = Workspace(name=name)
            admins = Role.query.filter_by(role_type='Administrator').all()
            for admin in admins:
                admin.workspaces.append(workspace)
            db.session.add(workspace)
            db.session.commit()
            return 'success', 201
        else:
            return 'workspace already exists', 400


@app.route('/workspaces/<workspace_id>', methods=['GET', 'PUT', 'DELETE'])
def workspace(workspace_id):
    '''
    For GET requests, return the given workspace's info
    For PUT requests, update given workspace's info
    For DELETE requets, delete the given workspace
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
            return 'workspace does not exist', 404
    # request is a GET
    if request.method == 'GET':
        schema = WorkspaceSchema(strict=True)
        workspace_data = schema.dump(workspace)
        return jsonify(workspace_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if workspace.name == 'General' and workspace.id == 1:
            return 'cannot delete General workspace', 400
        db.session.delete(workspace)
        db.session.commit()
        return 'workspace deleted', 204

    elif request.method == 'PUT':
        name = request.form.get('Name')
        workspace_name = Workspace.query.filter_by(name=name).first()
        if workspace_name is not None:
            return 'workspace with that name already exists', 400
        elif name is None or name == '':
            return 'provide a non-null name', 400
        else:
            workspace.name = name
            db.session.commit()
            return 'workspace updated', 200


@app.route('/roles', methods=['GET', 'POST'])
@login_required
@admin_login_required
def roles():
    '''
    For GET requests, return all workspaces
    For POST requests, add a new workspace
    '''

    # request is a GET
    if request.method == 'GET':
        all_roles = Role.query.all()
        schema = RoleSchema(many=True, strict=True)
        roles = schema.dump(all_roles)
        return jsonify(roles)

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        role_type = request.form.get('Role_Type')
        role = Role.query.filter_by(name=name).first()
        if role is not None:
            return 'role already exists with that name', 400
        elif role_type.lower() not in ['administrator', 'user', 'client']:
            return 'role type not admin, user, or client', 400
        else:
            role = Role(name=name, role_type=role_type)
            if role.role_type in ['administrator', 'user']:
                general_ws = Workspace.query.filter_by(id=1, name='General').first()
                if general_ws is not None:
                    role.workspaces.append(general_ws)
            db.session.add(role)
            db.session.commit()       
            return 'success', 201


@app.route('/workspaces/<workspace_id>/lists', methods = ['GET', 'POST'])
@login_required
@user_login_required
def targetlists(workspace_id):
    '''
    For GET requests, return all target lists associated with the given workspace
    For POST requests, add a new list to the given workspace
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        workspace_lists = List.query.filter_by(workspace_id=workspace_id).all()
        schema = ListSchema(many=True, strict=True)
        list_data = schema.dump(workspace_lists)
        return jsonify(list_data)
    
    # request is a POST
    elif request.method == 'POST':
        req_json = request.get_json()
        name = req_json['name']
        targets = req_json['targets']
        list_name = List.query.filter_by(workspace_id=workspace_id, name=name).first()
        if list_name is not None:
            return 'workspace already has a list with that name', 400
        else:
            new_list = List(name=name, workspace_id=workspace_id)
            for target in targets:
                person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
                new_list.targets.append(person)
            db.session.add(new_list)
            db.session.commit()
            return 'success', 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>', methods = ['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def targetlist(workspace_id, list_id):
    '''
    For GET requests, return the given list
    For PUT requests, udpate the given list
    For DELETE requests, delete the given list
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ListSchema(strict=True)
        list_data = schema.dump(targetlist)
        return jsonify(list_data)
    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(targetlist)
        db.session.commit()
        return '', 204

    # request is a PUT (update attributes of the List)
    elif request.method == 'PUT':
        req_json = request.get_json()
        name = req_json['name']
        targets = req_json['targets']
        for target in targets:
            person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
            targetlist.targets.append(person)
        targetlist.name = name
        db.session.commit()
        return 'updated', 200


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets', methods=['POST', 'GET'])
@login_required
@user_login_required
def targets(workspace_id, list_id):
    '''
    For GET requets, return all targets of the given list
    For POST requests, add a target to the given list
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    # request is a GET
    if request.method == 'GET':
        targets = Person.query.filter_by(list_id=list_id)
        schema = PersonSchema(many=True, strict=True)
        all_targets = schema.dump(targets)
        return jsonify(all_targets)

    # request is a POST
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        person = Person(first_name=first_name, last_name=last_name, email=email)
        targetlist.targets.append(person)
        db.session.commit()
    return 'added person', 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets/<target_id>', methods=['DELETE'])
@login_required
@user_login_required
def target(workspace_id, list_id, target_id):
    '''
    For DELETE requests, delete the given target from the given list
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    target = Person.query.filter_by(id=target_id, list_id=list_id).first()
    if target is None:
        return 'target does not exist'

    db.session.delete(target)
    db.session.commit()
    return 'deleted', 204