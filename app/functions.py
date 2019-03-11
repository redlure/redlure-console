# file of miscellaneous functions for the backend application
from functools import wraps
from flask_login import current_user
import re
from app.models import Workspace, Email, Profile, List, Domain, APIKey
from flask_mail import Mail, Message
from app import app
from flask import request, abort
import requests
from bs4 import BeautifulSoup
from datetime import datetime


def update_workspace_ts(workspace):
    '''
    Set the updated_at attribute of the given workspace to the current datetime
    '''
    workspace.updated_at = datetime.utcnow()


def clone_link(link):
    r = requests.get(link, verify=False)
    if r.status_code == 200:
        soup = BeautifulSoup(r.content, features='lxml')
        base = soup.new_tag('base', href=link)
        soup.find('head').insert_before(base)
        return str(soup), 200
    else:
        return 'error with link', 404


def require_api_key(f):
    '''
    Require an API key be provided to a function
    '''
    @wraps(f)
    def wrap(*args, **kwargs):
        api_key = APIKey.query.first().key
        if request.args.get('key') and request.args.get('key') == api_key:
            return f(*args, **kwargs)
        else:
            abort(401)
    return wrap 


def validate_campaign_makeup(email, pages, profile, targetlist, domain, server):
    '''
    Return a message and HTTP error code if a given campaign module does not exist.
    '''
    if email is None:
        return 'email invalid', 404

    for page in pages:
        if page is None:
            return 'at least 1 page is invalid', 404
    
    if profile is None:
        return 'profile invalid', 404

    if targetlist is None:
        return 'list invalid', 404

    if domain is None:
        return 'domain invalid', 404

    if server is None:
        return 'server invalid', 404


def validate_workspace(workspace_id):
    '''
    Returns True if the given Workspace ID exists in the database
    '''
    workspace = Workspace.query.filter(Workspace.roles.contains(current_user.role)).filter_by(id=workspace_id).first()
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