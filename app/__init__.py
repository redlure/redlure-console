#!/usr/bin/env python3
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os
import logging
from logging.handlers import RotatingFileHandler


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models
from app.models import User, Role, Workspace, Profile, List, Person


if not app.debug:

    # create logs dir if it does not exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # log using rotatingfilehandler, capping log files at 10240 bytes and storing up to 10 logfiles
    file_handler = RotatingFileHandler('logs/redure-server.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('redlure-server startup')

# initialize the database if it does not already exist
try:
    db.session.query(User).count()
except:
    db.create_all()

# add general workspace
if db.session.query(Workspace).count() == 0:
    general_ws = Workspace(name='General')
    db.session.add(general_ws)
    db.session.commit()

# if no roles exist in database, add base roles
if db.session.query(Role).count() == 0:
    print('No roles found in database - initializing default roles')
    administrator = Role(name='Defualt Administrator', role_type='Administrator')
    user = Role(name='Defualt User', role_type='User') 
    client = Role(name='Defualt Client', role_type='Client')
    general_ws = Workspace.query.filter_by(id=1, name='General').first()
    if general_ws is not None:
            administrator.workspaces.append(general_ws)
            user.workspaces.append(general_ws)
    db.session.add(administrator)
    db.session.add(user)
    db.session.add(client)
    db.session.commit()

# if no users exist in database, add default admin
if db.session.query(User).count() == 0:
    print('No users found in database - initializing default admin user')
    admin = User(username='admin', role_id=1)
    admin.set_password('redlure')
    db.session.add(admin)
    db.session.commit()
