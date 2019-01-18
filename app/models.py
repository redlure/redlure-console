from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from marshmallow import Schema, fields
from flask_mail import Mail, Message
import app
from flask import jsonify
from socket import gethostbyname


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

    def __repr__(self):
        return '<Workspace {}>'.format(self.name)


class WorkspaceSchema(Schema):
    id = fields.Number()
    name = fields.Str()


# Role Classes
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    role_type = db.Column(db.String(64), nullable=False)
    workspaces = db.relationship('Workspace', secondary=role_access, lazy=True, backref=db.backref('workspaces', lazy=True))
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


    def __repr__(self):
        return '<Sending Profile {}>'.format(self.name)


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


# Person Classes (Targets)
class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)

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

    def __repr__(self):
        return '<Target List {}>'.format(self.name)



class ListSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    targets = fields.Nested(PersonSchema, many=True)
    workspace_id = fields.Number()


# Email Classes
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='email', lazy=True)

    def __repr__(self):
        return '<Email {}>'.format(self.name)


class EmailSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    html = fields.Str()


# Campaign Classes
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)

    def __repr__(self):
        return '<Campaign {}>'.format(self.name)


class CampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    workspace_id = fields.Number()
    email_id = fields.Number()
    profile_id = fields.Number()
    list_id = fields.Number()
    domain_id = fields.Number()


# Domain Classes
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64))
    cert_path = db.Column(db.String(128))
    key_path = db.Column(db.String(128))
    campaigns = db.relationship('Campaign', backref='domain', lazy=True)

    def __repr__(self):
        print('hit')
        return '<Domain {}>'.format(self.name)

    def update_ip(self):
        '''
        Get the IP address that the domain name is pointed at
        '''
        try:
            new_ip = gethostbyname(self.domain)
            if new_ip != self.ip:
                self.ip = new_ip
        except:
            self.ip = 'Domain not found'


class DomainSchema(Schema):
    id = fields.Number()
    domain = fields.Str()
    ip = fields.Str()
    cert_path = fields.Str()
    key_path = fields.Str()