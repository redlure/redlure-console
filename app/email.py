from app import app, db
from marshmallow import Schema, fields
from datetime import datetime
from bs4 import BeautifulSoup
from flask import request, jsonify
from flask_login import login_required, current_user
import json
from app.workspace import Workspace, validate_workspace, update_workspace_ts
#from app.result import Result
from app.functions import convert_to_bool, user_login_required


####################
#  Email Classes
#####################
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    subject = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    track = db.Column(db.Boolean, default=True, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='email', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


    def prep_html(self, base_url, target, result, url):
        '''
        Replace variables in the email HTML with proper values and insert the tracking image URL if needed.
        '''
        # get result for this target in this campaign
        #result = next((x for x in target.results if x.campaign_id == campaign_id), None)
        #result = Result.query.filter_by(campaign_id=int(campaign_id), person_id=target.id).first()
        # get if campaign is using SSL
        ssl = result.campaign.ssl
        # get port the worker will host on
        port = result.campaign.port
        # get the domain name the campaign is using
        domain = result.campaign.domain.domain

        payload_url_path = result.campaign.payload_url

        # determine if base URLs are using HTTP/HTTPS and include port number in URLs for non-standard ports
        if ssl:
            if port != 443:
                base_url = f'https://{domain}:{port}'
                payload_url = f'https://{domain}:{port}{payload_url_path}?id={result.tracker}'
            else:
                base_url = f'https://{domain}'
                payload_url = f'https://{domain}{payload_url_path}?id={result.tracker}'
        else:
            if port!= 80:
                base_url = f'http://{domain}:{port}'
                payload_url = f'http://{domain}:{port}{payload_url_path}?id={result.tracker}'
            else:
                base_url = f'http://{domain}'
                payload_url = f'http://{domain}{payload_url_path}?id={result.tracker}'
        
        if url[0] != '/': url = '/' + url

        html = self.html
        if target.first_name: html = html.replace(b'{{ fname }}', str.encode(target.first_name))
        if target.last_name: html = html.replace(b'{{ lname }}', str.encode(target.last_name))
        if target.first_name and target.last_name: html = html.replace(b'{{ name }}', str.encode('%s %s' % (target.first_name, target.last_name)))
        html = html.replace(b'{{ email }}', str.encode(target.email))
        html = html.replace(b'{{ url }}', str.encode('%s%s?id=%s' % (base_url, url, result.tracker)))
        html = html.replace(b'{{ id }}', str.encode(result.tracker))
        html = html.replace(b'{{ payload_url }}', str.encode(payload_url))

        soup = BeautifulSoup(html, features='lxml')
        base = soup.new_tag('base', href=base_url)
        soup.insert(1, base)

        if self.track:
            tracker = soup.new_tag('img', alt='', src=f'{base_url}/{result.tracker}/pixel.png')
            soup.find('body').insert_after(tracker)
        html = str(soup).encode()

        return html


class EmailSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    subject = fields.Str()
    html = fields.Str()
    track = fields.Boolean()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


####################
#  Email Routes
#####################
@app.route('/workspaces/<workspace_id>/emails', methods=['GET', 'POST'])
@login_required
@user_login_required
def emails(workspace_id):
    '''
    For GET requests, return all emails for the given workspace.
    For POST requests, add a new email to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_emails = Email.query.filter_by(workspace_id=workspace_id).order_by(Email.updated_at.desc()).all()
        schema = EmailSchema(many=True)
        email_data = schema.dump(all_emails)
        return jsonify(email_data)

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        subject = request.form.get('Subject')
        track = request.form.get('Track')

        track_bool = convert_to_bool(track)
        if type(track_bool) != bool:
            return 'Track must be either true or false', 400

        email = Email(name=name, html=html, subject=subject, workspace_id=workspace_id, track=track_bool)
        db.session.add(email)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = EmailSchema()
        email_data = schema.dump(email)
        app.logger.info(f'Added email {name} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(email_data), 200


@app.route('/workspaces/<workspace_id>/emails/<email_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def email(workspace_id, email_id):
    '''
    For GET requests, return the given email.
    For DELETE requests, delete the given email.
    For PUT requests, update the given email.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    email = Email.query.filter_by(id=email_id, workspace_id=workspace_id).first()
    if email is None:
        return 'email does not exist', 404

    #request is a GET
    if request.method == 'GET':
        schema = EmailSchema()
        email_data = schema.dump(email)
        return jsonify(email_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted email {email.name} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(email)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        subject = request.form.get('Subject')
        html = request.form.get('HTML').encode()
        track = request.form.get('Track')

        same_email = Email.query.filter_by(name=name).first()

        if same_email is not None and str(same_email.id) != email_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        track_bool = convert_to_bool(track)
        if type(track_bool) != bool:
            return 'Track must be either true or false', 400

        email.name = name
        email.subject = subject
        email.html = html
        email.track = track_bool
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        app.logger.info(f'Updated email {name} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}
