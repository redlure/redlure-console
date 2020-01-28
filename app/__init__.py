#!/usr/bin/env python3
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os
import logging
from flask_cors import CORS
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.debug = True
CORS(app, supports_credentials=True)
app.config.from_object(Config)
db = SQLAlchemy(app, session_options={"autoflush": False, "expire_on_commit": False})
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models


# create logs dir if it does not exist
if not os.path.exists('logs'):
    os.mkdir('logs')

# log using rotatingfilehandler, capping log files at 10240 bytes and storing up to 10 logfiles
file_handler = RotatingFileHandler('logs/redure-console.log', maxBytes=10240, backupCount=10)

# Set the format and level for the log messages
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]', datefmt='%m-%d-%y %H:%M')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

# Add the handler and set the required level
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)
