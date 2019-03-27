from app import app, db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from marshmallow import Schema, fields, post_dump, pre_dump
from flask_mail import Mail, Message
from app import app
from flask import jsonify
from socket import gethostbyname
import string
import random
from datetime import datetime
import os
import subprocess
import shutil
from binascii import hexlify
import requests
from bs4 import BeautifulSoup
import json


role_access = db.Table('role access',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspace.id'), primary_key=True)
)

campaign_pages = db.Table('campaign_pages',
    db.Column('campaign_id', db.Integer, db.ForeignKey('campaign.id'), primary_key=True),
    db.Column('page_id', db.Integer, db.ForeignKey('page.id'), primary_key=True)
)


# Workspace Classes
class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    lists = db.relationship('List', backref='workspace', lazy=True, cascade='all,delete')
    profiles = db.relationship('Profile', backref='workspace', lazy=True, cascade='all,delete')
    emails = db.relationship('Email', backref='workspace', lazy=True, cascade='all,delete')
    pages = db.relationship('Page', backref='workspace', lazy=True, cascade='all,delete')
    campaigns = db.relationship('Campaign', backref='workspace', lazy=True, cascade='all,delete')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Workspace {}>'.format(self.name)


class WorkspaceSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Role Classes
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    role_type = db.Column(db.String(64), nullable=False)
    workspaces = db.relationship('Workspace', secondary=role_access, lazy=True, backref=db.backref('roles', lazy=True))
    users = db.relationship('User', backref='role', lazy=True)


    def __repr__(self):
        return '<Role {}>'.format(self.name)


class RoleSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    role_type = fields.Str()
    workspaces = fields.Nested(WorkspaceSchema, many=True, strict=True)


# User Classes
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)


    def set_password(self, password):
        '''
        Hash the given string and store as the user's password
        '''
        self.password_hash = generate_password_hash(password)


    def check_password(self, password):
        '''
        Hash the given string and check it against the stored password hash 
        '''
        return check_password_hash(self.password_hash, password)


    def __repr__(self):
        return '<User {}>'.format(self.username)


class UserSchema(Schema):
    id = fields.Number()
    username = fields.Str()
    role = fields.Nested(RoleSchema, strict=True)
    

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


# Sending Profile Classes
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    from_address = db.Column(db.String(64), nullable=False)
    smtp_host = db.Column(db.String(64), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    tls = db.Column(db.Boolean, default=False, nullable=False)
    ssl = db.Column(db.Boolean, default=True, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='profile', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Sending Profile {}>'.format(self.name)


    def set_mail_configs(self):
        app.config['MAIL_SERVER'] = self.smtp_host
        app.config['MAIL_PORT'] = self.smtp_port
        app.config['MAIL_USERNAME'] = self.username
        app.config['MAIL_PASSWORD'] = self.password
        app.config['MAIL_USE_TLS'] = self.tls
        app.config['MAIL_USE_SSL'] = self.ssl

    
    def send_test_mail(self, address):
        self.set_mail_configs()
        mail = Mail(app)
        msg = Message('redlure test', sender=self.from_address, recipients=[address])
        msg.html = "<text>This a test email sent from your redlure profile using Flask Mail</text>"
        try:
            mail.send(msg)
            return True
        except:
           return False
        
    
    def send_mail(self, email, targets, campaign_id, base_url):
        try:
            self.set_mail_configs()
            mail = Mail(app)
            for target in targets:
                msg = Message(subject=email.subject, sender=self.from_address, recipients=[target.email])
                msg.html = email.prep_html(base_url, target)
                mail.send(msg)
                
                result = Result.query.filter_by(campaign_id=campaign_id, person_id=target.id).first()
                result.status = 'Sent'
                db.session.commit()
        except Exception as error:
            print(error)


class ProfileSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    from_address = fields.Str()
    smtp_host = fields.Str()
    smtp_port = fields.Number()
    username = fields.Str()
    password = fields.Str()
    tls = fields.Boolean()
    ssl = fields.Boolean()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Person Classes (Targets)
class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)
    result = db.relationship('Result', backref='person', lazy=True, cascade='all,delete', uselist=False)


    def __repr__(self):
        return '<Person {}>'.format(self.email)


class PersonSchema(Schema):
    id = fields.Number()
    first_name = fields.Str()
    last_name = fields.Str()
    email = fields.Str()


# Target List Classes
class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    targets = db.relationship('Person', backref='list', lazy=True, cascade='all,delete')
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='list', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Target List {}>'.format(self.name)


class ListSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    targets = fields.Nested(PersonSchema, many=True, strict=True)
    workspace_id = fields.Number()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Email Classes
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    subject = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    track = db.Column(db.Boolean, default=True, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='email', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Email {}>'.format(self.name)

    
    def prep_html(self, base_url, target):
        '''
        Replace variables in the email HTML with proper values and insert the tracking image URL if needed.
        '''
        base_url = 'http://10.1.5.64:8080/'
        html = self.html
        html = html.replace(b'{{ fname }}', str.encode(target.first_name))
        html = html.replace(b'{{ lname }}', str.encode(target.last_name))
        html = html.replace(b'{{ name }}', str.encode('%s %s' % (target.first_name, target.last_name)))
        html = html.replace(b'{{ url }}', str.encode('%s' % target.result.tracker))
        html = html.replace(b'{{ id }}', str.encode(target.result.tracker))
        
        soup = BeautifulSoup(html, features='lxml')
        base = soup.new_tag('base', href=base_url)
        soup.find('head').insert_before(base)

        if self.track:
            tracker = soup.new_tag('img', alt='', src='%s/pixel.png' % (target.result.tracker))
            soup.find('body').insert_after(tracker)
        html = str(soup).encode()

        return html


class EmailSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    subject = fields.Str()
    html = fields.Str()
    track = fields.Boolean()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Page Classes
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    url = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Page {}>'.format(self.name)


    def find_form_fields(self):
        fields = []
        forms = BeautifulSoup(self.html, features="lxml").find_all('form')
        inputs = forms[0].find_all('input')
        for input in inputs:
            fields.append(input['name'])


class PageSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    html = fields.Str()
    url = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Domain Classes
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64))
    cert_path = db.Column(db.String(128))
    key_path = db.Column(db.String(128))
    campaigns = db.relationship('Campaign', backref='domain', lazy=True)


    def __repr__(self):
        return '<Domain {}>'.format(self.domain)


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
        try:
            r = requests.post('https://%s:%d/certificates/generate' % (server.ip, server.port), params=params, data=payload, verify=False)
        except:
            pass


class DomainSchema(Schema):
    id = fields.Number()
    domain = fields.Str()
    ip = fields.Str()
    cert_path = fields.Str()
    key_path = fields.Str()


# Form Classes (HTML form data submitted by victims)
class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('result.id'))
    data = db.Column(db.String(128))


class FormSchema(Schema):
    id = fields.Number()
    result_id = fields.Number()
    data = fields.Dict()


    @post_dump
    def serialize_form(self, data):
        '''
        Convert the submitted form data from type String back to Dict
        '''
        data['data'] = json.loads(data['data'])
        return data
    


# Result Classes
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'))
    tracker = db.Column(db.String(32), nullable=False, unique=True)
    status = db.Column(db.String(32))
    forms = db.relationship('Form', backref='result', lazy=True, cascade='all,delete')


    def __init__(self, **kwargs):
        self.status = 'Scheduled'
        self.__dict__.update(kwargs)

    
    def get_json_forms(self):
        for form in self.forms:
            print(json.loads(form.data))


class ResultSchema(Schema):
    id = fields.Number()
    campaign_id = fields.Number()
    person = fields.Nested(PersonSchema, strict=True)
    tracker = fields.Str()
    status = fields.Str()
    forms = fields.Nested(FormSchema, strict=True, many=True)


# Server classes
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
        self.check_status()
        

    def check_status(self):
        params = {'key': APIKey.query.first().key}
        try:
            r = requests.get('https://%s:%d/status' % (self.ip, self.port), params=params, verify=False, timeout=5)
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


    def kill_process(self, port):
        self.check_status()
        if self.status == 'Online':
            params = {'key': APIKey.query.first().key}
            payload = {'port': port}
            r = requests.get('https://%s:%d/processes/kill' % (self.ip, self.port), params=params, data=payload, verify=False)
            if r.status_code == 200:
                return 'process killed'
            else:
                return 'error killing process'


    def __repr__(self):
        return '<Server {}>'.format(self.alias)


class ServerSchema(Schema):
    id = fields.Number()
    ip = fields.Str()
    alias = fields.Str()
    port = fields.Number()
    status = fields.Str()


# API Key Class
class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64))


    def __init__(self):
        db.session.add(self)
        self.generate_key()


    def __repr__(self):
        return '<APIKey {}>'.format(self.key)

    
    def generate_key(self):
        self.key = hexlify(os.urandom(24)).decode()
        db.session.commit()


class APIKeySchema(Schema):
    key = fields.Str()


# Campaign Classes
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    pages = db.relationship('Page', secondary=campaign_pages, lazy=True, backref=db.backref('campaigns', lazy=True))
    redirect_url = db.Column(db.String(64), nullable=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    ssl = db.Column(db.Boolean, nullable=False)
    results = db.relationship('Result', backref='campaign', lazy=True, cascade='all,delete')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(32), nullable=False)
    

    def __init__(self, **kwargs):
        self.status = 'Inactive'
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Campaign {}>'.format(self.name)

    
    def prep_tracking(self):
        for target in self.list.targets:
            tracker = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
            result = Result(campaign_id=self.id, person_id=target.id, tracker=tracker)
            db.session.add(result)
        db.session.commit()


    def cast(self, data):
        # tell worker to start hosting
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/campaigns/start' % (self.server.ip, self.server.port), json=data, params=params, verify=False)
        if r.status_code == 400:
            # TODO - handle case where port is already in use
            pass

        # start sending emails
        base_url = 'https://%s' % self.domain.domain if self.ssl else 'http://%s' % self.domain.domain
        self.profile.send_mail(self.email, self.list.targets, self.id, base_url)
        self.status = 'Active'
        db.session.commit()


    def kill(self):
        payload = {'id': self.id, 'port': self.port}
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/campaigns/kill' % (self.server.ip, self.server.port), data=payload, params=params, verify=False)
        self.status = 'Complete'
        db.session.commit()


class CampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    workspace_id = fields.Number()
    email = fields.Nested(EmailSchema, strict=True)
    pages = fields.Nested(PageSchema, strict=True, many=True)
    redirect_url = fields.Str()
    profile = fields.Nested(ProfileSchema, strict=True)
    targetlist = fields.Nested(ListSchema, strict=True)
    domain = fields.Nested(DomainSchema, strict=True)
    server = fields.Nested(ServerSchema, strict=True)
    port = fields.Number()
    ssl = fields.Boolean()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    status = fields.Str()


class WorkerCampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    pages = fields.Nested(PageSchema, strict=True, many=True)
    redirect_url = fields.Str()
    domain = fields.Nested(DomainSchema, strict=True)
    server = fields.Nested(ServerSchema, strict=True)
    port = fields.Number()
    ssl = fields.Boolean()
