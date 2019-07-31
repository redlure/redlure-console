from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from app import app, db
from app.models import User, UserSchema, Profile, ProfileSchema, Role, RoleSchema, Workspace, WorkspaceSchema, List, ListSchema, Person, PersonSchema, Campaign, CampaignSchema, WorkerCampaignSchema, Domain, DomainSchema, Email, EmailSchema, Result, ResultSchema, Page, PageSchema, Server, ServerSchema, APIKey, APIKeySchema, Form, FormSchema, Campaignpages, ResultCampaignSchema
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from flask_mail import Mail, Message
from app.functions import convert_to_bool, admin_login_required, user_login_required, validate_email_format, validate_workspace, validate_campaign_makeup, require_api_key, clone_link, update_workspace_ts, convert_to_datetime
import json
import subprocess
from flask_cors import cross_origin  
from datetime import datetime


@app.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    '''
    For POST requests, login the current user.
    '''

    #if current_user.is_authenticated:
     #   return json.dumps({'success': True}), 200, {'ContentType':'application/json'}

    username = request.form.get('Username')
    if username is not None:
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(request.form.get('Password')):
            return json.dumps({'success': False}), 401, {'ContentType':'application/json'} 

        login_user(user)
        '''
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            print('redirecting to home')
            next_page = url_for('workspaces')
        #return redirect(next_page)
        '''
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'} 
    return json.dumps({'success': False}), 401, {'ContentType':'application/json'} 


@app.route('/logout')
@cross_origin(supports_credentials=True)
@login_required
def logout():
    '''
    Logout the current user.
    '''
    logout_user()
    return redirect(url_for('login'))


@app.route('/home')
@login_required
@user_login_required
def home():
    '''
    home page.
    '''
    return 'home'


@app.route('/api')
@login_required
@admin_login_required
def api():
    key = APIKey.query.first()
    
    if key is None:
        return 'no key yet', 404

    schema = APIKeySchema(strict=True)
    key_data = schema.dump(key)
    return jsonify(key_data[0])


@app.route('/api/generate')
@login_required
@admin_login_required
def generate_api():
    key = APIKey.query.first()
    # key has not been made, create one
    if key is None:
        key = APIKey()

    # else update existing record with a new key
    else:
        key.generate_key()
    
    schema = APIKeySchema(strict=True)
    key_data = schema.dump(key)
    return jsonify(key_data[0])


@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_login_required
def users():
    '''
    For GET requests, return all users.
    For POST requests, add a new user.
    '''
    if request.method == 'GET':
        all_users = User.query.all()
        schema = UserSchema(many=True, strict=True)
        users = schema.dump(all_users)
        return jsonify(users[0])
    # request is a POST
    else:
        username = request.form.get('Username')
        role = request.form.get('Role')
        role = Role.query.filter_by(name=role).first()
        user = User.query.filter_by(username=username).first()
        
        if user is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        elif role is None:
            return 'failed to enter into database - role doesnt exist', 400
    
        user = User(username=username, role_id=role.id)
        user.set_password(request.form.get('Password'))
        db.session.add(user)
        db.session.commit()
        schema = UserSchema(strict=True)
        user_data = schema.dump(user)
        return jsonify(user_data[0]), 201


@app.route('/users/<user_id>', methods=['GET', 'DELETE'])
@login_required
@admin_login_required
def user(user_id):
    '''
    For GET requests, return the given user.
    For DELETE requests, delete the given user.
    '''

    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return 'user does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = UserSchema(strict=True)
        user_data = schema.dump(user)
        return jsonify(user_data)
    
    # request is a DELETE
    elif request.method == 'DELETE':
        if current_user == user:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'} 
        db.session.delete(user)
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'} 


@app.route('/domains', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def domains():
    '''
    For GET requests, return all domains.
    For POST requests, add a new domain.
    '''

    # request is a GET
    if request.method == 'GET':
        all_domains = Domain.query.all()
        schema = DomainSchema(many=True, strict=True)
        domain_data = schema.dump(all_domains)
        return jsonify(domain_data[0])

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

        schema = DomainSchema(strict=True)
        domain_data = schema.dump(domain_obj)
        return jsonify(domain_data[0]), 201


@app.route('/domains/refresh', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def refresh_domains():
    all_domains = Domain.query.all()
    for domain in all_domains:
        domain.update_ip()
    db.session.commit()
    return redirect('/domains')


@app.route('/domains/<domain_id>', methods=['GET', 'PUT', 'DELETE'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def domain(domain_id):
    '''
    For GET requests, return the given domain (and refresh the IP in case of update).
    For PUT requests, update the existing domain.
    FOR DELETE requests, delete the given domain.
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

        same_domain = Domain.query.filter_by(domain=domain).first()

        if same_domain is not None and str(same_domain.id) != domain_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        domain_obj.domain = domain
        domain_obj.cert_path = cert_path
        domain_obj.key_path = key_path
        domain_obj.update_ip()
        db.session.commit()
        return 'domain updated'


@app.route('/domains/<domain_id>/certificates/generate')
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def generate_cert(domain_id):
    '''
    For GET requests, generate certificates on the server the domain is pointed at.
    '''

    domain_obj = Domain.query.filter_by(id=domain_id).first()
    if domain_obj is None:
        return 'domain does not exist', 404

    server = Server.query.filter_by(ip=domain_obj.ip).first()
    if server is None:
        return json.dumps({'success': False, 'msg': 'Failed to generate cert. The domain does not resolve to the IP of a redlure worker'}), 200, {'ContentType':'application/json'}
    
    domain_obj.generate_cert(server)
    return 'certs generated'



@app.route('/servers', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def servers():
    '''
    For GET requests, return all servers.
    For POST requests, add a new servers.
    '''
    # request is a GET
    if request.method == 'GET':
        all_servers = Server.query.all()
        schema = ServerSchema(many=True, strict=True)
        server_data = schema.dump(all_servers)
        return jsonify(server_data[0])

    # request is a POST
    elif request.method == 'POST':
        ip = request.form.get('IP')
        alias = request.form.get('Alias')
        port = request.form.get('Port')

        server_obj = Server.query.filter_by(ip=ip).first()
        if server_obj is not None:
            return 'server already exists', 400
        
        server_obj = Server(ip=ip, alias=alias, port=port)
        schema = ServerSchema(strict=True)
        server_data = schema.dump(server_obj)
        return jsonify(server_data[0]), 201


@app.route('/servers/<server_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@admin_login_required
def server(server_id):
    '''
    For GET requests, return the given server (and refresh the IP in case of update).
    For PUT requests, update the existing server.
    FOR DELETE requests, delete the given server.
    '''

    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ServerSchema(strict=True)
        server_data = schema.dump(server_obj)
        return jsonify(server_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(server_obj)
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        ip = request.form.get('IP')
        alias= request.form.get('Alias')
        port = request.form.get('Port')

        same_server = Server.query.filter_by(alias=alias).first()

        if same_server is not None and str(same_server.id) != server_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        server_obj.ip = ip
        server_obj.alias = alias
        server_obj.port = port
        db.session.commit()
        return 'server updated'


@app.route('/servers/<server_id>/status')
@login_required
@user_login_required
def server_status(server_id):
    '''
    For GET requests, return check if the given redlure-worker server is online and responsive.
    '''

    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    status = server_obj.check_status()
    return json.dumps({'status': status}), 200, {'ContentType':'application/json'} 


@app.route('/workspaces/<workspace_id>/profiles', methods=['POST', 'GET'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def profiles(workspace_id):
    '''
    For GET requests, return all profiles.
    For POST requests, add a new profile.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    if request.method == 'GET':
        all_profiles = Profile.query.filter_by(workspace_id=workspace_id).order_by(Profile.updated_at.desc()).all()
        schema = ProfileSchema(many=True, strict=True)
        profiles = schema.dump(all_profiles)
        return jsonify(profiles[0])
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
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        elif type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400

        profile = Profile(name=name, from_address=from_address, smtp_host=host, smtp_port=port, \
            username=username, password=password, tls=tls_bool, ssl=ssl_bool, workspace_id=workspace_id)
        db.session.add(profile)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()

        schema = ProfileSchema(strict=True)
        profile_data = schema.dump(profile)
        return jsonify(profile_data[0]), 201


@app.route('/workspaces/<workspace_id>/profiles/<profile_id>', methods=['GET', 'POST', 'DELETE', 'PUT'])
@login_required
@user_login_required
def profile(workspace_id, profile_id):
    '''
    For GET requests, return the profile with the given name.
    For POST requests, use the given profile to send a test email.
    For DELETE requests, delete the given profile.
    '''
    if not validate_workspace(workspace_id):
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
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'profile deleted', 204

    # request is a POST
    elif request.method == 'POST':
        address = request.form.get('Address')
        
        if not validate_email_format(address):
            return 'Enter a valid email address', 400
    
        success = profile.send_test_mail(address)
        return json.dumps({'success': success}), 200, {'ContentType':'application/json'} 
            
    
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


        same_profile = Profile.query.filter_by(name=name).first()

        if same_profile is not None and str(same_profile.id) != profile_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        ssl_bool = convert_to_bool(ssl)
        tls_bool = convert_to_bool(tls)

        if type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400
        
        profile.name = name
        profile.from_address = from_address
        profile.smtp_host = host
        profile.smtp_port = port
        profile.username = username
        profile.password = password
        profile.tls = tls_bool
        profile.ssl = ssl_bool
        profile.workspace_id = workspace_id
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()

        schema = ProfileSchema(strict=True)
        profile_data = schema.dump(profile)
        return jsonify(profile_data[0]), 200


@app.route('/workspaces', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
@login_required
@user_login_required
def workspaces():
    '''
    For GET requests, return all workspaces.
    For POST requests, add a new workspace.
    '''
    if request.method == 'GET':
        all_workspaces = Workspace.query.filter(Workspace.roles.contains(current_user.role)).order_by(Workspace.updated_at.desc()).all()
        schema = WorkspaceSchema(many=True, strict=True)
        workspaces = schema.dump(all_workspaces)
        return jsonify(workspaces[0])
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
            schema = WorkspaceSchema(strict=True)
            workspace_data = schema.dump(workspace)
            return jsonify(workspace_data[0]), 201
        else:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}


@app.route('/workspaces/<workspace_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def workspace(workspace_id):
    '''
    For GET requests, return the given workspace's info.
    For PUT requests, update given workspace's info.
    For DELETE requets, delete the given workspace.
    '''
    workspace = Workspace.query.filter(Workspace.roles.contains(current_user.role)).filter_by(id=workspace_id).first()
    if workspace is None:
            return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = WorkspaceSchema(strict=True)
        workspace_data = schema.dump(workspace)
        return jsonify(workspace_data[0])

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
    For GET requests, return all roles.
    For POST requests, add a new role.
    '''

    # request is a GET
    if request.method == 'GET':
        all_roles = Role.query.all()
        schema = RoleSchema(many=True, strict=True)
        roles = schema.dump(all_roles)
        return jsonify(roles[0])

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        role_type = request.form.get('Role_Type')
        role = Role.query.filter_by(name=name).first()

        if role is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        elif role_type.lower() not in ['administrator', 'user', 'client']:
            return 'role type not admin, user, or client', 400
        
        role = Role(name=name, role_type=role_type)
        if role.role_type.lower() in ['administrator', 'user']:
            general_ws = Workspace.query.filter_by(id=1, name='General').first()
            role.workspaces.append(general_ws)
        db.session.add(role)
        db.session.commit()       
        schema = RoleSchema(strict=True)
        role_data = schema.dump(role)
        return jsonify(role_data[0]), 201


@app.route('/roles/<role_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
@admin_login_required
def role(role_id):
    '''
    For GET requests, return the given role.
    For DELETE requests, delete the given role.
    For PUT requests, update the current role.
    '''

    role = Role.query.filter_by(id=role_id).first()
    if role is None:
        return 'role does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = RoleSchema(strict=True)
        role_data = schema.dump(role)
        return jsonify(role_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if current_user.role_id == role.id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        db.session.delete(role)
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}

    # request is a PUT
    elif request.method == 'PUT':
        workspace_ids = request.form.getlist('Workspace_ID[]')
        workspaces = Workspace.query.filter(Workspace.id.in_(workspace_ids)).all()

        role.workspaces = workspaces
        db.session.commit()
        schema = RoleSchema(strict=True)
        role_data = schema.dump(role)
        return jsonify(role_data[0]), 201


@app.route('/workspaces/<workspace_id>/lists', methods = ['GET', 'POST'])
@login_required
@user_login_required
def targetlists(workspace_id):
    '''
    For GET requests, return all target lists associated with the given workspace.
    For POST requests, add a new list to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        workspace_lists = List.query.filter_by(workspace_id=workspace_id).all()
        schema = ListSchema(many=True, strict=True)
        list_data = schema.dump(workspace_lists)
        return jsonify(list_data[0])
    
    # request is a POST
    elif request.method == 'POST':
        req_json = request.get_json()
        print(req_json)
        name = req_json['name']
        targets = req_json['targets']
        
        list_name = List.query.filter_by(workspace_id=workspace_id, name=name).first()
        if list_name is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        
        new_list = List(name=name, workspace_id=workspace_id)
        for target in targets:
            person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
            new_list.targets.append(person)
        db.session.add(new_list)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = ListSchema(strict=True)
        list_data = schema.dump(new_list)
        return jsonify(list_data[0]), 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>', methods = ['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def targetlist(workspace_id, list_id):
    '''
    For GET requests, return the given list.
    For PUT requests, udpate the given list.
    For DELETE requests, delete the given list.
    '''
    if not validate_workspace(workspace_id):
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
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return '', 204

    # request is a PUT (update attributes of the List)
    elif request.method == 'PUT':
        req_json = request.get_json()
        name = req_json['name']
        targets = req_json['targets']

        same_list = List.query.filter_by(name=name).first()

        if same_list is not None and str(same_list.id) != list_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        targetlist.targets = []
        for target in targets:
            person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
            targetlist.targets.append(person)
        targetlist.name = name
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = ListSchema(strict=True)
        list_data = schema.dump(targetlist)
        return jsonify(list_data[0]), 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets', methods=['POST', 'GET'])
@login_required
@user_login_required
def targets(workspace_id, list_id):
    '''
    For GET requets, return all targets of the given list.
    For POST requests, add a target to the given list.
    '''
    if not validate_workspace(workspace_id):
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
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
    return 'added person', 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets/<target_id>', methods=['DELETE'])
@login_required
@user_login_required
def target(workspace_id, list_id, target_id):
    '''
    For DELETE requests, delete the given target from the given list.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    target = Person.query.filter_by(id=target_id, list_id=list_id).first()
    if target is None:
        return 'target does not exist'

    db.session.delete(target)
    update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
    db.session.commit()
    return 'deleted', 204


@app.route('/workspaces/<workspace_id>/emails', methods=['GET', 'POST'])
@login_required
@user_login_required
def emails(workspace_id):
    '''
    For GET requests, return all emails for the given workspace.
    For POST requests, add a new email to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_emails = Email.query.filter_by(workspace_id=workspace_id).order_by(Email.updated_at.desc()).all()
        schema = EmailSchema(many=True, strict=True)
        email_data = schema.dump(all_emails)
        return jsonify(email_data[0])

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        subject = request.form.get('Subject')
        track = request.form.get('Track')

        track_bool = convert_to_bool(track)
        if type(track_bool) != bool:
            return 'Track must be either true or false', 400

        email = Email(name=name, html=html, subject=subject, workspace_id=workspace_id, track=track_bool)
        db.session.add(email)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = EmailSchema(strict=True)
        email_data = schema.dump(email)
        return jsonify(email_data[0]), 200


@app.route('/workspaces/<workspace_id>/emails/<email_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def email(workspace_id, email_id):
    '''
    For GET requests, return the given email.
    For DELETE requests, delete the given email.
    For PUT requests, update the given email.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    email = Email.query.filter_by(id=email_id, workspace_id=workspace_id).first()
    if email is None:
        return 'email does not exist', 404

    #request is a GET
    if request.method == 'GET':
        schema = EmailSchema(strict=True)
        email_data = schema.dump(email)
        return jsonify(email_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(email)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        subject = request.form.get('Subject')
        html = request.form.get('HTML').encode()
        track = request.form.get('Track')

        same_email = Email.query.filter_by(name=name).first()

        if same_email is not None and str(same_email.id) != email_id:
            print(same_email.name, same_email.id)
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        track_bool = convert_to_bool(track)
        if type(track_bool) != bool:
            return 'Track must be either true or false', 400

        email.name = name
        email.subject = subject
        email.html = html
        email.track = track_bool
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/clone', methods=['POST'])
@login_required
@user_login_required
def clone():
    '''
    For POST requests, return the source HTML of a given URL
    '''
    link = request.form.get('Link')
    return clone_link(link)

    


@app.route('/workspaces/<workspace_id>/pages', methods=['GET', 'POST'])
@login_required
@user_login_required
def pages(workspace_id):
    '''
    For GET requests, return all pages for the given workspace.
    For POST requests, add a new pages to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_pages = Page.query.filter_by(workspace_id=workspace_id).order_by(Page.updated_at.desc()).all()
        schema = PageSchema(many=True, strict=True)
        page_data = schema.dump(all_pages)
        return jsonify(page_data[0])

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        url = request.form.get('URL')

        page = Page.query.filter_by(name=name).first()

        if page is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        page = Page(name=name, html=html, workspace_id=workspace_id, url=url)
        db.session.add(page)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = PageSchema(strict=True)
        page_data = schema.dump(page)
        return jsonify(page_data[0]), 201


@app.route('/workspaces/<workspace_id>/pages/<page_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def page(workspace_id, page_id):
    '''
    For GET requests, return the given page.
    For DELETE requests, delete the given page.
    For PUT requests, update the given page.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    page = Page.query.filter_by(id=page_id, workspace_id=workspace_id).first()
    if page is None:
        return 'page does not exist', 404

    #request is a GET
    if request.method == 'GET':
        page.find_form_fields()
        schema = PageSchema(strict=True)
        page_data = schema.dump(page)
        return jsonify(page_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        db.session.delete(page)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        url = request.form.get('URL')

        same_page = Page.query.filter_by(name=name).first()

        if same_page is not None and str(same_page.id) != page_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        page.name = name
        page.html = html
        page.url = url
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/workspaces/<workspace_id>/campaigns', methods=['GET', 'POST'])
@login_required
@user_login_required
def campaigns(workspace_id):
    '''
    For GET requests, return all campaigns for the given workspace.
    For POST requests, all a campaign to the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_campaigns = Campaign.query.filter_by(workspace_id=workspace_id).order_by(Campaign.updated_at.desc()).all()
        
        # sort the pages associated with the campaign by index
        for campaign in all_campaigns:
            campaign.pages.sort(key=lambda camp: camp.index)
        
        schema = CampaignSchema(many=True, strict=True)
        campaign_data = schema.dump(all_campaigns)
        return jsonify(campaign_data[0])

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        email_name = request.form.get('Email_Name')
        page_names = request.form.getlist('Page_Names[]') # page names is a list of page names # page names is a list of page names
        profile_name = request.form.get('Profile_Name')
        list_name = request.form.get('List_Name')
        domain_name = request.form.get('Domain_Name')
        server_alias = request.form.get('Server_Alias')
        port = request.form.get('Port')
        ssl = request.form.get('SSL')
        redirect_url = request.form.get('Redirect_URL')
        start_time = request.form.get('Start_Time')
        interval = request.form.get('Interval')
        batch_size =request.form.get('Batch_Size')
        payload_url = request.form.get('Payload_URL')
        
        print(start_time)
        if start_time:
            start_time = convert_to_datetime(start_time)
        else:
            start_time = datetime.now()
        print(type(start_time))
        print(start_time)


        ssl_bool = convert_to_bool(ssl)
        if type(ssl_bool) != bool:
            return 'ssl must be either true or false', 400

        pages = []

        for page_name in page_names:
            page = Page.query.with_entities(Page).filter((Page.name == page_name) & ((Page.workspace_id == 2) | (Page.workspace_id == 1))).first()
            pages.append(page)

        email = Email.query.with_entities(Email).filter((Email.name == email_name) & ((Email.workspace_id == 2) | (Email.workspace_id == 1))).first()
        profile = Profile.query.with_entities(Profile).filter((Profile.name == profile_name) & ((Profile.workspace_id == 2) | (Profile.workspace_id == 1))).first()
        targetlist = List.query.with_entities(List).filter((List.name == list_name) & ((List.workspace_id == 2) | (List.workspace_id == 1))).first()
        domain = Domain.query.filter_by(domain=domain_name).first()
        server = Server.query.filter_by(alias=server_alias).first()

        # make sure all given modules exist before continuing
        makeup = validate_campaign_makeup(email, pages, profile, targetlist, domain, server)
        if makeup:
            return makeup
        
        campaign = Campaign(name=name, workspace_id=workspace_id, email_id=email.id, profile_id=profile.id, \
                start_time=start_time, send_interval=interval, batch_size=batch_size, \
                list_id=targetlist.id, domain_id=domain.id, server_id=server.id, port=port, ssl=ssl_bool, redirect_url=redirect_url, \
                payload_url=payload_url)
        
        #for page in pages:
            #print(campaign.id)
        print('pages ',  pages)
        print(f'campaign: {campaign}')

        db.session.add(campaign)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        for idx, page in enumerate(pages):
            #Todo: fix somethingn in hbere
            page_association = Campaignpages(campaign_id=campaign.id, page_id=page.id, index=idx)
            db.session.add(page_association)
            db.session.commit()
        print('down here')
        return json.dumps({'success': True, 'id': campaign.id}), 200, {'ContentType':'application/json'}


@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
@user_login_required
def campaign(workspace_id, campaign_id):
    '''
    For GET requests, return the given campaign.
    For DELETE requests, delete the given campaign.
    For PUT requests, update the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = CampaignSchema(strict=True)
        campaign_data = schema.dump(campaign)
        return jsonify(campaign_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if campaign.status == 'Active':
            kill(workspace_id, campaign_id)
        db.session.delete(campaign)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'campaign deleted', 204

    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        email_name = request.form.get('Email_Name')
        profile_name = request.form.get('Profile_Name')
        list_name = request.form.get('List_Name')
        domain_name = request.form.get('Domain_Name')
        server_alias = request.form.get('Server_Alias')
        port = request.form.get('Port')
        ssl = request.form.get('SSL')
        redirect_url = request.form.get('Redirect_URL')

        same_campaign = Campaign.query.filter_by(name=name).first()

        if same_campaign is not None and str(same_campaign.id) != campaign_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        ssl_bool = convert_to_bool(ssl)
        if type(ssl_bool) != bool:
            return 'ssl must be either true or false', 400

        email = Email.query.filter_by(name=email_name, workspace_id=workspace_id).first()
        profile = Profile.query.filter_by(name=profile_name, workspace_id=workspace_id).first()
        targetlist = List.query.filter_by(name=list_name, workspace_id=workspace_id).first()
        domain = Domain.query.filter_by(domain=domain_name).first()
        server = Server.query.filter_by(alias=server_alias).first()

        # make sure all given modules exist before continuing
        makeup = validate_campaign_makeup(email, page, profile, targetlist, domain, server)
        if makeup:
            return makeup

        campaign.name = name
        campaign.email_id = email.id
        campaign.profile_id = profile.id
        campaign.list_id = targetlist.id
        campaign.domain_id = domain.id
        campaign.server_id = server.id
        campaign.port = port
        campaign.ssl = ssl_bool
        campaign.redirect_url = redirect_url
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'campaign updated'


@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/cast', methods=['GET'])
@login_required
@user_login_required
def cast(workspace_id, campaign_id):
    '''
    For GET requests, kick off the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return json.dumps({'success': False, 'reasonCode': 1}), 200, {'ContentType':'application/json'}

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return json.dumps({'success': False, 'reasonCode': 2}), 200, {'ContentType':'application/json'}

    if campaign.status != 'Inactive':
        return json.dumps({'success': False, 'reasonCode': 3}), 200, {'ContentType':'application/json'}

    if campaign.server.check_status() != 'Online':
        return json.dumps({'success': False, 'reasonCode': 4}), 200, {'ContentType':'application/json'}

    schema = WorkerCampaignSchema(strict=True)
    campaign_data = schema.dump(campaign)
    
    campaign.prep_tracking()
    campaign.cast(campaign_data)
    
    return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/kill', methods=['GET'])
@login_required
@user_login_required
def kill(workspace_id, campaign_id):
    '''
    For GET requests, kill the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    if campaign.status != 'Active':
        return 'campaign is not active', 400

    if campaign.server.check_status() != 'Online':
        campaign.status = 'Complete'
        db.session.commit()
        return 'could not stop campaign: %s. - campaign changed to completed' % campaign.server.status, 400

    campaign.kill()
    
    return 'campaign killed', 200


@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/results')
@login_required
@user_login_required
def campaign_results(workspace_id, campaign_id):
    '''
    For GET requests, return results for the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    schema = ResultSchema(many=True, strict=True)
    results = schema.dump(campaign.results)
    return jsonify(results[0])


@app.route('/workspaces/<workspace_id>/results')
@login_required
@user_login_required
def workspace_results(workspace_id):
    '''
    For GET requests, return results for all campaigns in the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    workspace_results = Result.query.join(Campaign).join(Workspace).filter(Workspace.id == workspace_id).all()
    campaigns = Campaign.query.filter_by(workspace_id=workspace_id).all()

    schema = ResultCampaignSchema(many=True, strict=True)
    c_results = schema.dump(campaigns)

    schema = ResultSchema(many=True, strict=True)
    results = schema.dump(workspace_results)
   
    return jsonify(c_results[0], results[0])


@app.route('/workspaces/<workspace_id>/campaigns/modules')
@login_required
@user_login_required
def campaign_modules(workspace_id):
    '''
    For GET requests, return possible campaign modules in the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404


    page_names = Page.query.with_entities(Page.name).filter((Page.workspace_id == workspace_id) | (Page.workspace_id == 1)).all()
    list_names = List.query.with_entities(List.name).filter((List.workspace_id == workspace_id) | (List.workspace_id == 1)).all()
    email_names = Email.query.with_entities(Email.name).filter((Email.workspace_id == workspace_id) | (Email.workspace_id == 1)).all()
    profile_names = Profile.query.with_entities(Profile.name).filter((Profile.workspace_id == workspace_id) | (Profile.workspace_id == 1)).all()
    domain_names = Domain.query.with_entities(Domain.domain).all()
    server_names = Server.query.with_entities(Server.alias).all()

    all_info = {
        "pages": [item for sublist in page_names for item in sublist], # make list of lists a flat list
        "lists": [item for sublist in list_names for item in sublist],
        "emails": [item for sublist in email_names for item in sublist],
        "profiles": [item for sublist in profile_names for item in sublist],
        "domains": [item for sublist in domain_names for item in sublist],
        "servers": [item for sublist in server_names for item in sublist],
    }

    return jsonify(all_info), 200


# Overview/Dasboard/Home routes (pull data to be shown on the page)

@app.route('/campaigns/active')
@user_login_required
def active_campaigns():
    '''
    For GET requests, pull data on active campaigns
    '''
    active_campaigns = Campaign.query.filter_by(status='Active').order_by(Campaign.workspace_id).all()
    schema = CampaignSchema(many=True, strict=True)
    campaign_data = schema.dump(active_campaigns)
    return jsonify(campaign_data)


@app.route('/workspaces/recent')
@user_login_required
def recent_workspaces():
    '''
    For GET requests, return recently used workspaces
    '''
    recent_workspaces = Workspace.query.order_by(Workspace.updated_at.desc()).limit(5).all()
    schema = WorkspaceSchema(many=True, strict=True)
    workspaces = schema.dump(recent_workspaces)
    return jsonify(workspaces)


# API routes below accept data from redlure-worker servers

@app.route('/results/update', methods=['POST'])
@require_api_key
def record_action():
    '''
    Requires matching API key. For POST requests, check the database for a result with
    a matching identifier and update the result's status.
    '''
    tracker = request.form.get('tracker')
    action = request.form.get('action')
    
    result = Result.query.filter_by(tracker=tracker).first()
    
    # tracker string is not in db
    if result is None:
        return 'no tracker', 404

    if action == 'Clicked' and result.status != 'Submitted':
        result.status = action
    elif action == 'Opened' and result not in ['Clicked', 'Submitted']:
        result.status = action

    db.session.commit()
    return 'updated'


@app.route('/results/form', methods=['POST'])
@require_api_key
def record_form():
    '''
    Requires matching API key. For POST requests, check the database for a result with
    a matching identifier and record the submiited form values.
    '''
    tracker = request.form.get('tracker')
    form_data = request.form.get('data')

    result = Result.query.filter_by(tracker=tracker).first()
    # tracker string is not in db
    if result is None:
        return 'no tracker', 404

    form = Form(data=form_data)

    result.forms.append(form)
    result.status = 'Submitted'
    db.session.commit()
    return 'updated'
