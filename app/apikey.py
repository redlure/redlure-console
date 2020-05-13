from app import app, db
from flask import jsonify, request, abort
from flask_login import login_required
from marshmallow import Schema, fields
from os import urandom
from binascii import hexlify
from functools import wraps
from app.functions import admin_login_required, user_login_required


####################
#  API Key Classes
#####################
class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64))


    def __init__(self):
        db.session.add(self)
        self.generate_key()


    def generate_key(self):
        app.logger.info('New API key generated')
        self.key = hexlify(urandom(24)).decode()
        db.session.commit()


class APIKeySchema(Schema):
    key = fields.Str()


####################
#  API Key Routes
#####################
@app.route('/api')
@login_required
@user_login_required
def api():
    key = APIKey.query.first()
    
    if key is None:
        return 'no key yet', 404

    schema = APIKeySchema()
    key_data = schema.dump(key)
    return jsonify(key_data)


@app.route('/api/generate')
@login_required
@admin_login_required
def generate_api():
    key = APIKey.query.first()
    # key has not been made, create one
    if key is None:
        key = APIKey()

    # else update existing record with a new key
    else:
        key.generate_key()
    
    schema = APIKeySchema()
    key_data = schema.dump(key)
    return jsonify(key_data)


###############################
#  Wrapper for non-api routes
###############################
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