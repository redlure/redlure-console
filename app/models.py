from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from marshmallow import Schema, fields
from flask_mail import Mail, Message
from app import app
from flask import jsonify
from socket import gethostbyname
import string
import random
from datetime import datetime


role_access = db.Table('role access',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspace.id'), primary_key=True)
)


# Workspace Classes
class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    lists = db.relationship('List', backref='workspace', lazy=True, cascade='all,delete')
    profiles = db.relationship('Profile', backref='workspace', lazy=True, cascade='all,delete')
    emails = db.relationship('Email', backref='workspace', lazy=True, cascade='all,delete')
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
    name = db.Column(db.String(64), unique=True, nullable=False)
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
        mail.send(msg)
        
    
    def send_mail(self, subject, html, targets, campaign_id):
        try:
            self.set_mail_configs()
            mail = Mail(app)
            for target in targets:
                msg = Message(subject=subject, sender=self.from_address, recipients=[target.email])
                msg.html = html
                mail.send(msg)
                
                result = Result.query.filter_by(campaign_id=campaign_id, person_id=target.id).first()
                result.status = 'Email Sent'
                print(result)
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
    results = db.relationship('Result', backref='person', lazy=True)


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
    targets = fields.Nested(PersonSchema, many=True)
    workspace_id = fields.Number()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Email Classes
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    subject = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='email', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Email {}>'.format(self.name)


class EmailSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    subject = fields.Str()
    html = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Page Classes
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='page', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Page {}>'.format(self.name)


class PageSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    html = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Campaign Classes
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    results = db.relationship('Result', backref='campaign', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __repr__(self):
        return '<Campaign {}>'.format(self.name)

    
    def prep_tracking(self):
        for target in self.list.targets:
            tracker = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
            result = Result(campaign_id=self.id, person_id=target.id, tracker=tracker)
            db.session.add(result)
        db.session.commit()
    

    def cast(self):
        self.profile.send_mail(self.email.subject, self.email.html, self.list.targets, self.id)


class CampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    workspace_id = fields.Number()
    email_id = fields.Number()
    profile_id = fields.Number()
    list_id = fields.Number()
    domain_id = fields.Number()
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


class DomainSchema(Schema):
    id = fields.Number()
    domain = fields.Str()
    ip = fields.Str()
    cert_path = fields.Str()
    key_path = fields.Str()


# Result Classes
class Result(db.Model):
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), primary_key=True)
    tracker = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32))


class ResultSchema(Schema):
    campaign_id = fields.Number()
    person_id = fields.Nested(PersonSchema, strict=True)
    tracker = fields.Str()
    status = fields.Str()