# file of miscellaneous functions for the backend application
from functools import wraps
from flask_login import current_user
import re


def init_roles():
    print('hi')

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