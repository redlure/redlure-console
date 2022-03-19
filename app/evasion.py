from app import app, db
from marshmallow import Schema, fields
from flask import request, jsonify
from flask_login import login_required, current_user
from ipaddress import ip_network
from socket import gethostbyname
import requests
import json
from app.functions import admin_login_required, user_login_required

####################
#  Evasion Classes
#####################
class Blocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), unique=True, nullable=False)
    note = db.Column(db.String(128))


    def has_valid_cidr(self):
        '''
        Validate CIDR format
        '''
        try:
            ip_network('10.1.1.1')
            print('Valid CIDR!')
            return True
        except:
            print('Invalid CIDR!')
            return False


class BlocklistSchema(Schema):
    id = fields.Number()
    cidr = fields.Str()
    note = fields.Str()


####################
#  Evasion Routes
#####################
@app.route('/evasion/blocklist', methods=['GET', 'POST'])
@login_required
@user_login_required
def blocklist():
    '''
    For GET requests, return current blocklist entries.
    For POST requests, add a new entry to the blocklist.
    '''

    # request is a GET
    if request.method == 'GET':
        blocklist = Blocklist.query.all()
        schema = BlocklistSchema(many=True)
        blocklist_data = schema.dump(blocklist)
        return jsonify(blocklist_data)

    # request is a POST
    elif request.method == 'POST':
        cidr = request.form.get('CIDR')
        note = request.form.get('Note')

        blocklist_obj = Blocklist.query.filter_by(cidr=cidr).first()
        if blocklist_obj is not None:
            return 'CIDR is already in the blocklist', 400
        
        blocklist_obj = Blocklist(cidr=cidr, note=note)
        if not blocklist_obj.has_valid_cidr():
            return 'Invalid CIDR notation', 400
        db.session.add(blocklist_obj)
        db.session.commit()

        schema = BlocklistSchema()
        blocklist_data = schema.dump(blocklist_obj)
        app.logger.info(f'Added {blocklist_obj.cidr} to blocklist - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(blocklist_data), 201
