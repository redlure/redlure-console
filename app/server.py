from app import app, db
from marshmallow import Schema, fields
from flask import request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
import requests
import json
from app.apikey import APIKey
from app.functions import admin_login_required, user_login_required


####################
#  Server Classes
#####################
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True)
    port = db.Column(db.Integer, nullable=False)
    alias = db.Column(db.String(64), unique=True)
    status = db.Column(db.String(64))
    campaigns = db.relationship('Campaign', backref='server', lazy=True)


    def __init__(self, **kwargs):
        db.session.add(self)
        self.__dict__.update(kwargs)
        db.session.commit()


    def check_status(self):
        params = {'key': APIKey.query.first().key}
        try:
            r = requests.post(f'https://{self.ip}:{self.port}/status', params=params, verify=False, timeout=5)
            if r.status_code == 200:
                self.status = 'Online'
            elif r.status_code == 401:
                self.status = 'Mismatching API Key'
            else:
                self.status = 'Offline'
        except:
            self.status = 'Offline'
        db.session.commit()
        return self.status


    def check_processes(self):
        self.check_status()
        if self.status == 'Online':
            params = {'key': APIKey.query.first().key}
            r = requests.post(f'https://{self.ip}:{self.port}/processes/check', params=params, verify=False)
            return r


    def kill_process(self, port):
        self.check_status()
        if self.status == 'Online':
            params = {'key': APIKey.query.first().key}
            payload = {'port': port}
            r = requests.post(f'https://{self.ip}:{self.port}/processes/kill', params=params, data=payload, verify=False)
            if r.status_code == 200:
                return 'process killed'
            else:
                return 'error killing process'


    def check_certs(self, cert_path, key_path):
        params = {'key': APIKey.query.first().key}
        payload = {'cert_path': cert_path, 'key_path': key_path}
        r = requests.post(f'https://{self.ip}:{self.port}/certificates/check', params=params, data=payload, verify=False)
        return r


    def list_files(self):
        params = {'key': APIKey.query.first().key}
        r = requests.post(f'https://{self.ip}:{self.port}/files', params=params, verify=False)
        return r


    def upload_file(self, files):
        params = {'key': APIKey.query.first().key}
        payload = {'Filename': files['file'].filename}
        r = requests.post(f'https://{self.ip}:{self.port}/files/upload', params=params, files=files, data=payload, verify=False)
        return r


    def delete_file(self, filename):
        params = {'key': APIKey.query.first().key}
        payload = {'Filename': filename}
        r = requests.post(f'https://{self.ip}:{self.port}/files/delete', params=params, data=payload, verify=False)
        return r


    def delete_allfiles(self):
        params = {'key': APIKey.query.first().key}
        r = requests.post(f'https://{self.ip}:{self.port}/files/deleteall', params=params, verify=False)
        return r


class ServerSchema(Schema):
    id = fields.Number()
    ip = fields.Str()
    alias = fields.Str()
    port = fields.Number()
    status = fields.Str()


####################
#  Server Routes
#####################
@app.route('/servers', methods=['GET', 'POST'])
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
        schema = ServerSchema(many=True)
        server_data = schema.dump(all_servers)
        return jsonify(server_data)

    # request is a POST
    elif request.method == 'POST':
        ip = request.form.get('IP')
        alias = request.form.get('Alias')
        port = request.form.get('Port')

        server_obj = Server.query.filter_by(ip=ip).first()
        if server_obj is not None:
            return 'server already exists', 400
        
        server_obj = Server(ip=ip, alias=alias, port=port)
        schema = ServerSchema()
        server_data = schema.dump(server_obj)
        app.logger.info(f'Added server {alias} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(server_data), 201


@app.route('/servers/<server_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@admin_login_required
def server(server_id):
    '''
    For GET requests, return the given server 
    For PUT requests, update the existing server.
    FOR DELETE requests, delete the given server.
    '''

    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ServerSchema()
        server_data = schema.dump(server_obj)
        return jsonify(server_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted server {server_obj.alias} ({server_obj.ip}) - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
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
            return json.dumps({'success': False, 'msg': f'Server with alias {alias} already exists'}), 200, {'ContentType':'application/json'}

        server_obj.ip = ip
        server_obj.alias = alias
        server_obj.port = port
        db.session.commit()
        app.logger.info(f'Updated server {server_obj.alias} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


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


@app.route('/servers/<server_id>/processes')
@login_required
@user_login_required
def server_procs(server_id):
    '''
    For GET requests, query the server for ports already listening.
    '''

    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    data = server_obj.check_processes()
    return json.dumps(data.json()), 200, {'ContentType':'application/json'}


@app.route('/servers/<server_id>/files', methods=['GET', 'POST'])
@login_required
@user_login_required
def server_file_upload(server_id):
    '''
    For GET requests, list all files on the server.
    For POST requests, upload a new file to the server
    '''

    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    if request.method == 'GET':
        data = server_obj.list_files()
        return json.dumps(data.json()), 200, {'ContentType':'application/json'}
    elif request.method == 'POST':
        data = server_obj.upload_file(request.files)
        filename = request.files['file'].filename
        app.logger.info(f'Uploaded {filename} to {server_obj.alias} ({server_obj.ip}) - Uploaded by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps(data.json()), 200, {'ContentType':'application/json'}


@app.route('/servers/<server_id>/files/delete', methods=['GET', 'POST'])
@login_required
@user_login_required
def server_file_delete(server_id):
    '''
    For GET requests delete all uploads off the server
    For POST requests delete a specified file off the server
    '''
    server_obj = Server.query.filter_by(id=server_id).first()
    if server_obj is None:
        return 'server does not exist', 404

    if request.method == 'GET':
       data = server_obj.delete_allfiles()
       app.logger.info(f'Deleted all uploaded files from {server_obj.alias} ({server_obj.ip}) - Uploaded by {current_user.username} - Client IP address {request.remote_addr}')
    elif request.method == 'POST':
        filename = request.form.get('Filename')
        data = server_obj.delete_file(filename)
        app.logger.info(f'Deleted {filename} from {server_obj.alias} ({server_obj.ip}) - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
    return json.dumps(data.json()), 200, {'ContentType':'application/json'}
