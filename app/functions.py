# file of miscellaneous functions for the backend application
from functools import wraps
from flask_login import current_user

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