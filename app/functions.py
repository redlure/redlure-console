# file of miscellaneous functions for the backend application
from functools import wraps
from flask_login import current_user
import re
from app.models import Workspace, Email, Profile, List, Domain
from flask_mail import Mail, Message
from app import app


def send_mail(profile, subject, html, addresses):
    if type(addresses) != list:
        addresses = [addresses]
    try:
        app.config['MAIL_SERVER'] = profile.smtp_host
        app.config['MAIL_PORT'] = profile.smtp_port
        app.config['MAIL_USERNAME'] = profile.username
        app.config['MAIL_PASSWORD'] = profile.password
        app.config['MAIL_USE_TLS'] = profile.tls
        app.config['MAIL_USE_SSL'] = True #profile.ssl
        mail = Mail(app)
        msg = Message(subject=subject, sender=profile.from_address, recipients=addresses)
        msg.html = "<text>Hello Flask message sent from Flask-Mail</text>"
        mail.send(msg)
        return 'test email sent', 200
    except Exception as error:
        return error
    


def validate_campaign_makeup(email, profile, targetlist, domain):
    '''
    Return a message and HTTP error code if a given campaign module does not exist.
    '''
    if email is None:
        return 'email invalid', 404
    
    if profile is None:
        return 'profile invalid', 404

    if targetlist is None:
        return 'list invalid', 404

    if domain is None:
        return 'domain invalid', 404


def validate_workspace(workspace_id):
    '''
    Returns True if the given Workspace ID exists in the database
    '''
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if workspace is None:
        return False
    return True


def validate_email_format(email):
    '''
    Returns True if a given email address has an '@' with a '.' for a later character
    '''
    email_reg = re.compile(r'[^@]+@[^@]+\.[^@]+')
    if email_reg.match(email):
        return True
    else:
        return False


def admin_login_required(f):
    '''
    Require that the current user has admin privs
    '''
    @wraps(f)
    def wrap(*args, **kwargs):
        role_type = current_user.role.role_type
        if role_type.lower() != 'administrator':
            return 'you need admin', 401
        return f(*args, **kwargs)
    return wrap


def user_login_required(f):
    '''
    Require that the current user has at least user privs
    '''
    @wraps(f)
    def wrap(*args, **kwargs):
        role_type = current_user.role.role_type
        if role_type.lower() not in ['administrator', 'user']:
            return 'you need to be user or admin', 401
        return f(*args, **kwargs)
    return wrap


def convert_to_bool(value):
    '''
    Evaluate if a string is True or False
    '''
    if value.strip().lower() == 'true':
        return True
    elif value.strip().lower() == 'false':
        return False
    else:
        return -1