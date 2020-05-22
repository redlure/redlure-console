from app import app, db
from marshmallow import Schema, fields
from flask import request, jsonify
from flask_login import login_required, current_user
from socket import gethostbyname
import requests
import json
from app.server import Server
from app.apikey import APIKey
from app.functions import admin_login_required, user_login_required


####################
#  Domain Classes
#####################
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64))
    cert_path = db.Column(db.String(128))
    key_path = db.Column(db.String(128))
    campaigns = db.relationship('Campaign', backref='domain', lazy=True)


    def update_ip(self):
        '''
        Get the IP address that the domain name is pointed at
        '''
        try:
            self.ip = gethostbyname(self.domain)
        except:
            self.ip = 'Domain not found'


    def generate_cert(self, server):
        payload = {'domain': self.domain}
        params = {'key': APIKey.query.first().key}
        r = requests.post(f'https://{server.ip}:{server.port}/certificates/generate', params=params, data=payload, verify=False)
        if r.json()['success']:
            self.cert_path = r.json()['cert_path']
            self.key_path = r.json()['key_path']
            db.session.commit()
        return r


class DomainSchema(Schema):
    id = fields.Number()
    domain = fields.Str()
    ip = fields.Str()
    cert_path = fields.Str()
    key_path = fields.Str()


####################
#  Domain Routes
#####################
@app.route('/domains', methods=['GET', 'POST'])
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
        schema = DomainSchema(many=True)
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

        schema = DomainSchema()
        domain_data = schema.dump(domain_obj)
        app.logger.info(f'Added domain {domain} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(domain_data), 201


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
        db.session.commit()
        schema = DomainSchema()
        domain_data = schema.dump(domain_obj)
        return jsonify(domain_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted domain {domain_obj.domain} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
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

        schema = DomainSchema()
        domain_data = schema.dump(domain_obj)
        app.logger.info(f'Updated domain {domain_obj.domain} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(domain_data), 200


@app.route('/domains/<domain_id>/certificates/generate')
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
    
    data = domain_obj.generate_cert(server)
    app.logger.info(f'Generated certificates for {domain_obj.domain} on {server.alias} ({server.ip}) - Generated by {current_user.username} - Client IP address {request.remote_addr}')
    return json.dumps(data.json()), 200, {'ContentType':'application/json'}
