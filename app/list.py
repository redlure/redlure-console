from app import app, db
from marshmallow import Schema, fields
from datetime import datetime
from flask import request, jsonify
from flask_login import login_required, current_user
import json
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.functions import user_login_required


####################
#  List Classes
#####################
class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=True)
    results = db.relationship('Result', backref='person', lazy=False, cascade='all,delete')


class PersonSchema(Schema):
    id = fields.Number()
    first_name = fields.Str()
    last_name = fields.Str()
    email = fields.Str()


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    targets = db.relationship('Person', backref='list', lazy=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='list', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return '<Target List {}>'.format(self.name)


class ListSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    targets = fields.Nested(PersonSchema, many=True, strict=True)
    workspace_id = fields.Number()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


####################
#  List Routes
#####################
@app.route('/workspaces/<workspace_id>/lists', methods = ['GET', 'POST'])
@login_required
@user_login_required
def targetlists(workspace_id):
    '''
    For GET requests, return all target lists associated with the given workspace.
    For POST requests, add a new list to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        workspace_lists = List.query.filter_by(workspace_id=workspace_id).order_by(List.updated_at.desc()).all()
        schema = ListSchema(many=True)
        list_data = schema.dump(workspace_lists)
        return jsonify(list_data)
    
    # request is a POST
    elif request.method == 'POST':
        req_json = request.get_json()
        name = req_json['name']
        targets = req_json['targets']
        
        list_name = List.query.filter_by(workspace_id=workspace_id, name=name).first()
        if list_name is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        
        new_list = List(name=name, workspace_id=workspace_id)
        for target in targets:
            person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
            new_list.targets.append(person)
        db.session.add(new_list)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = ListSchema()
        list_data = schema.dump(new_list)
        app.logger.info(f'Added list {name} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(list_data), 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>', methods = ['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def targetlist(workspace_id, list_id):
    '''
    For GET requests, return the given list.
    For PUT requests, udpate the given list.
    For DELETE requests, delete the given list.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ListSchema()
        list_data = schema.dump(targetlist)
        return jsonify(list_data)
    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted list {targetlist.name} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(targetlist)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return '', 204

    # request is a PUT (update attributes of the List)
    elif request.method == 'PUT':
        req_json = request.get_json()
        name = req_json['name']
        targets = req_json['targets']

        same_list = List.query.filter_by(name=name).first()

        if same_list is not None and str(same_list.id) != list_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        targetlist.targets = []
        for target in targets:
            person = Person(first_name=target['first_name'], last_name=target['last_name'], email=target['email'])
            targetlist.targets.append(person)
        targetlist.name = name
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = ListSchema()
        list_data = schema.dump(targetlist)
        app.logger.info(f'Updated list {targetlist.name} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(list_data), 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets', methods=['POST', 'GET'])
@login_required
@user_login_required
def targets(workspace_id, list_id):
    '''
    For GET requets, return all targets of the given list.
    For POST requests, add a target to the given list.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    # request is a GET
    if request.method == 'GET':
        targets = Person.query.filter_by(list_id=list_id)
        schema = PersonSchema(many=True)
        all_targets = schema.dump(targets)
        return jsonify(all_targets)

    # request is a POST
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        person = Person(first_name=first_name, last_name=last_name, email=email)
        targetlist.targets.append(person)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
    return 'added person', 201


@app.route('/workspaces/<workspace_id>/lists/<list_id>/targets/<target_id>', methods=['DELETE'])
@login_required
@user_login_required
def target(workspace_id, list_id, target_id):
    '''
    For DELETE requests, delete the given target from the given list.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    targetlist = List.query.filter_by(id=list_id, workspace_id=workspace_id).first()
    if targetlist is None:
        return 'list does not exist', 404

    target = Person.query.filter_by(id=target_id, list_id=list_id).first()
    if target is None:
        return 'target does not exist'

    db.session.delete(target)
    update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
    db.session.commit()
    return 'deleted', 204