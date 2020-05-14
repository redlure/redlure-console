from app import app, db
from marshmallow import Schema, fields
from flask import request, jsonify
from flask_login import login_required, current_user
import json
from app.workspace import Workspace, WorkspaceSchema
from app.functions import admin_login_required, user_login_required


############################
#  Role Classes
############################

# Association table for roles and workspaces
role_access = db.Table('role access',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspace.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    role_type = db.Column(db.String(64), nullable=False)
    workspaces = db.relationship('Workspace', secondary=role_access, lazy=True, backref=db.backref('roles', lazy=True))
    users = db.relationship('User', backref='role', lazy=True, cascade='all,delete')


class RoleSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    role_type = fields.Str()
    workspaces = fields.Nested(WorkspaceSchema, many=True, strict=True)


############################
#  Role Routes
############################
@app.route('/roles', methods=['GET', 'POST'])
@login_required
@admin_login_required
def roles():
    '''
    For GET requests, return all roles.
    For POST requests, add a new role.
    '''

    # request is a GET
    if request.method == 'GET':
        all_roles = Role.query.all()
        schema = RoleSchema(many=True)
        roles = schema.dump(all_roles)
        return jsonify(roles)

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        role_type = request.form.get('Role_Type')
        role = Role.query.filter_by(name=name).first()

        if role is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        elif role_type.lower() not in ['administrator', 'user', 'client']:
            return 'role type not admin, user, or client', 400
        
        role = Role(name=name, role_type=role_type)
        if role.role_type.lower() in ['administrator', 'user']:
            general_ws = Workspace.query.filter_by(id=1, name='General').first()
            role.workspaces.append(general_ws)
        db.session.add(role)
        db.session.commit()       
        schema = RoleSchema()
        role_data = schema.dump(role)
        app.logger.info(f'Added role {name} ({role_type}) - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(role_data), 201


@app.route('/roles/<role_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
@admin_login_required
def role(role_id):
    '''
    For GET requests, return the given role.
    For DELETE requests, delete the given role.
    For PUT requests, update the current role.
    '''

    role = Role.query.filter_by(id=role_id).first()
    if role is None:
        return 'role does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = RoleSchema()
        role_data = schema.dump(role)
        return jsonify(role_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if current_user.role_id == role.id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        app.logger.info(f'Deleted role {role.name} ({role.role_type}) - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(role)
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}

    # request is a PUT
    elif request.method == 'PUT':
        workspace_ids = request.form.getlist('Workspace_ID[]')
        workspaces = Workspace.query.filter(Workspace.id.in_(workspace_ids)).all()

        role.workspaces = workspaces
        db.session.commit()
        schema = RoleSchema()
        role_data = schema.dump(role)
        app.logger.info(f'Updated role permissions for {role.name} ({role.role_type}) - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(role_data), 201


#########################################################
# !!
# Workspaces route
# wImported to avoid circular dependency
###########################################################
@app.route('/workspaces', methods=['GET', 'POST'])
@login_required
@user_login_required
def workspaces():
    '''
    For GET requests, return all workspaces.
    For POST requests, add a new workspace.
    '''
    if request.method == 'GET':
        all_workspaces = Workspace.query.filter(Workspace.roles.contains(current_user.role)).order_by(Workspace.updated_at.desc()).all()
        schema = WorkspaceSchema(many=True)
        workspaces = schema.dump(all_workspaces)
        return jsonify(workspaces)
    else:
        # request is a POST
        name = request.form.get('Name')
        workspace = Workspace.query.filter_by(name=name).first()
        if workspace is None:
            workspace = Workspace(name=name)

            # give all admin roles permissions to the new workspace
            admins = Role.query.filter_by(role_type='Administrator').all()
            for admin in admins:
                admin.workspaces.append(workspace)

            # if the user posting the workspace is not an admin, give their role permissions
            if current_user.role.role_type == 'User':
                current_user.role.workspaces.append(workspace)

            db.session.add(workspace)
            db.session.commit()
            schema = WorkspaceSchema()
            workspace_data = schema.dump(workspace)
            app.logger.info(f'Added workspace {name} - Added by {current_user.username} - Client IP address {request.remote_addr}')
            return jsonify(workspace_data), 201
        else:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
