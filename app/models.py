from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from marshmallow import Schema, fields
from flask_mail import Mail, Message
import app
from flask import jsonify


# User Classes

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    # set the user's password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # evalute a given string against the user's stored password hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class UserSchema(Schema):
    id = fields.Number()
    username = fields.Str()
    

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

'''
# Role Classes
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    admin = db.Column(db.String(64))
    user = db.Column(db.Boolean)
    client = db.Column(db.Boolean)

    def __repr__(self):
        return '<Role {}>'.format(self.name)


# Client Classes
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))

    def __repr__(self):
        return '<Client {}>'.format(self.name)
'''

# Sending Profile Classes
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    from_address = db.Column(db.String(64))
    smtp_host = db.Column(db.String(64))
    smtp_port = db.Column(db.Integer)
    username = db.Column(db.String(64))
    password = db.Column(db.String(64))
    tls = db.Column(db.Boolean, default=False, nullable=False)
    ssl = db.Column(db.Boolean, default=True, nullable=False)

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