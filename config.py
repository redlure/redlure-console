import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = 'secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'redlure.db' + '?check_same_thread=False')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #TESTING = True