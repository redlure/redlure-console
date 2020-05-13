from app import app, db, login
from flask_login import UserMixin
from flask import request, jsonify
import json
from flask_login import current_user, login_user, logout_user, login_required
from marshmallow import Schema, fields
from werkzeug.security import generate_password_hash, check_password_hash
from app.role import Role, RoleSchema
from app.functions import admin_login_required, user_login_required


####################
#  User Classes
#####################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)


    def set_password(self, password):
        '''
        Hash the given string and store as the user's password
        '''
        self.password_hash = generate_password_hash(password)


    def check_password(self, password):
        '''
        Hash the given string and check it against the stored password hash 
        '''
        return check_password_hash(self.password_hash, password)


class UserSchema(Schema):
    id = fields.Number()
    username = fields.Str()
    role = fields.Nested(RoleSchema, strict=True)
    

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


########################################
#  User Routes and Login/Logout Routes
########################################
@app.route('/login', methods=['POST'])
def login():
    '''
    For POST requests, login the current user.
    '''
    username = request.form.get('Username')

    if username is not None:
        user = User.query.filter_by(username=username).first()
        if user is None:
            app.logger.warning(f'Failed login attempt for user {username} - Invalid username - Client IP address: {request.remote_addr}')
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        if not user.check_password(request.form.get('Password')):
            app.logger.warning(f'Failed login attempt for user {username} - Invalid password - Client IP address: {request.remote_addr}')
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        login_user(user)
        app.logger.info(f'Successful login for user {username} - Client IP address: {request.remote_addr}')

        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}
    return json.dumps({'success': False}), 200, {'ContentType':'application/json'}


@app.route('/logout')
@login_required
def logout():
    '''
    Logout the current user.
    '''
    app.logger.info(f'Successful logout for user {current_user.username} - Client IP address {request.remote_addr}')
    logout_user()
    return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_login_required
def users():
    '''
    For GET requests, return all users.
    For POST requests, add a new user.
    '''
    if request.method == 'GET':
        all_users = User.query.all()
        schema = UserSchema(many=True)
        users = schema.dump(all_users)
        return jsonify(users)
    # request is a POST
    else:
        username = request.form.get('Username')
        role = request.form.get('Role')
        role = Role.query.filter_by(name=role).first()
        user = User.query.filter_by(username=username).first()
        
        if user is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}
        elif role is None:
            return 'failed to enter into database - role doesnt exist', 400
    
        user = User(username=username, role_id=role.id)
        user.set_password(request.form.get('Password'))
        db.session.add(user)
        db.session.commit()
        schema = UserSchema()
        user_data = schema.dump(user)
        app.logger.info(f'New user {username} created as a {role} - Created by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(user_data), 201


@app.route('/users/<user_id>/reset', methods=['POST'])
@login_required
def reset_password(user_id):
    '''
    For POST requests, reset password of given user
    '''
    user = User.query.filter_by(id=user_id).first()
    
    if user is None:
        return json.dumps({'success': False, 'message': 'User does not exist'}), 200, {'ContentType':'application/json'}

    password = request.form.get('Password')
    user.set_password(password)
    
    db.session.commit()
    app.logger.info(f'Password reset for {user.username} - Reset by {current_user.username} - Client IP address {request.remote_addr}')
    return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/users/<user_id>', methods=['GET', 'DELETE'])
@login_required
@admin_login_required
def user(user_id):
    '''
    For GET requests, return the given user.
    For DELETE requests, delete the given user.
    '''

    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return 'user does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = UserSchema()
        user_data = schema.dump(user)
        return jsonify(user_data)
    
    # request is a DELETE
    elif request.method == 'DELETE':
        if current_user == user:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'} 
        db.session.delete(user)
        db.session.commit()
        app.logger.info(f'Deleted user {user.username} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'} 


@app.route('/users/current')
@login_required
def currentUser():
    '''
    For GET requests, return the current user
    '''
    schema = UserSchema()
    user_data = schema.dump(current_user)
    return jsonify(user_data)