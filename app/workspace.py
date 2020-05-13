from app import app, db
from flask import request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from marshmallow import Schema, fields
from app.functions import user_login_required


############################
#  Workspace Classes
############################
class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    lists = db.relationship('List', backref='workspace', lazy=True, cascade='all,delete')
    profiles = db.relationship('Profile', backref='workspace', lazy=True, cascade='all,delete')
    emails = db.relationship('Email', backref='workspace', lazy=True, cascade='all,delete')
    pages = db.relationship('Page', backref='workspace', lazy=True, cascade='all,delete')
    campaigns = db.relationship('Campaign', backref='workspace', lazy=True, cascade='all,delete')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


class WorkspaceSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


############################
#  Workspace Routes
############################

#########################################################
# !!
# Main Workspace route @app.route('/workspaces') lives
# in roles.py to avoid circular dependency that occurs
# when adding access to a new workspace to all admin roles
###########################################################

@app.route('/workspaces/<workspace_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def workspace(workspace_id):
    '''
    For GET requests, return the given workspace's info.
    For PUT requests, update given workspace's info.
    For DELETE requets, delete the given workspace.
    '''
    workspace = Workspace.query.filter(Workspace.roles.contains(current_user.role)).filter_by(id=workspace_id).first()
    if workspace is None:
            return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = WorkspaceSchema()
        workspace_data = schema.dump(workspace)
        return jsonify(workspace_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if workspace.id == 1:
            return 'cannot delete General workspace', 400
        app.logger.info(f'Deleted workspace {workspace.name} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(workspace)
        db.session.commit()
        return 'workspace deleted', 204

    elif request.method == 'PUT':
        name = request.form.get('Name')
        workspace_name = Workspace.query.filter_by(name=name).first()
        if workspace_name is not None:
            return 'workspace with that name already exists', 400
        elif name is None or name == '':
            return 'provide a non-null name', 400
        else:
            workspace.name = name
            db.session.commit()
            return 'workspace updated', 200


############################
#  Class Specific Helpers
############################
def validate_workspace(workspace_id):
    '''
    Returns True if the given Workspace ID exists in the database
    '''
    workspace = Workspace.query.filter(Workspace.roles.contains(current_user.role)).filter_by(id=workspace_id).first()
    if workspace is None:
        return False
    return True


def update_workspace_ts(workspace):
    '''
    Set the updated_at attribute of the given workspace to the current datetime
    '''
    workspace.updated_at = datetime.utcnow()