from app import app, db, sched
from marshmallow import Schema, fields, post_dump
from flask import request, jsonify
from flask_mail import Mail, Message
from flask_login import login_required
from datetime import datetime, timedelta
import html2text
import json
import re
from app.role import RoleSchema
from app.cipher import encrypt, decrypt
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.functions import admin_login_required, user_login_required


############################
#  Sending Profile Classes
############################
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    from_address = db.Column(db.String(64), nullable=False)
    smtp_host = db.Column(db.String(64), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    tls = db.Column(db.Boolean, default=False, nullable=False)
    ssl = db.Column(db.Boolean, default=True, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    campaigns = db.relationship('Campaign', backref='profile', cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return '<Sending Profile {}>'.format(self.name)

    def set_mail_configs(self):
        app.config['MAIL_SERVER'] = self.smtp_host
        app.config['MAIL_PORT'] = self.smtp_port
        app.config['MAIL_USERNAME'] = decrypt(self.username).decode()
        app.config['MAIL_PASSWORD'] = decrypt(self.password).decode()
        app.config['MAIL_USE_TLS'] = self.tls
        app.config['MAIL_USE_SSL'] = self.ssl


    def send_test_mail(self, address):
        """
        Sends a test email to ensure everything is configured properly
        @param address: str - recipient of the email
        """
        self.set_mail_configs()
        mail = Mail(app)
        msg = Message('redlure test', sender=self.from_address, recipients=[address])
        msg.html = "<text>This a test email sent from your redlure profile using Flask Mail</text>"
        msg.body = html2text.html2text(msg.html)
        try:
            mail.send(msg)
            return True
        except Exception:
           return False


    def schedule_campaign(self, email, targets, campaign_id, base_url, interval, batch_size, start_time, data, ip, port, url):
        """
        Schedules a campaign to execute in a separate thread. The user decides when it will run, how many emails to send at a time, and how long to wait between batches.
        @param email:
        @param targets:
        @param campaign_id: int - Unique identifier for the campaign to execute
        @param base_url: 
        @param interval: int - 
        @param batch_size: int - Number of emails to send at once
        @param start_time: datetime - Time in which to kickoff the campaign
        """
        # Configurations
        self.set_mail_configs()
        mail = Mail(app)
        #sched = BackgroundScheduler()
        job_id = str(campaign_id)
        targets = list(targets)

        # Ensures that batch_size and interval are set
        #batch_size = len(targets) if not batch_size else batch_size
        #interval = 0 if not interval else interval

        # Schedule the campaign and intialize it
        current_jobs = sched.get_jobs()
        # In case the batch size or interval are blank, set them appropriately 
        if not batch_size: batch_size = len(targets)
        if not interval: interval = 0

        interval = int(interval)
        batch_size = int(batch_size)

        campaign = Campaign.query.filter_by(id=campaign_id).first()

        # Schedule the campaign and intialize it
        try:
            if start_time < datetime.now():
                # schedule campaign to be run in 8 seconds from current timme - anything less and the campaign will wait 1 interval before sending the first batch of emails. Does not affect sending without batches or future start times
                start_time = datetime.now() + timedelta(0,8)
                sched.add_job(func=self.send_emails, trigger='interval', minutes=interval, id=job_id, start_date=datetime.now() + timedelta(0,8), replace_existing=True, args=[targets, email, mail, base_url, job_id, batch_size, sched, data, len(targets), ip, port, url])
            else:
                sched.add_job(func=self.send_emails, trigger='interval', minutes=interval, id=job_id, start_date=start_time, replace_existing=True, args=[targets, email, mail, base_url, job_id, batch_size, sched, data, len(targets), ip, port, url])
        except Exception:
            app.logger.exception(f'Error scheduling campaign {campaign.name} (ID: {campaign_id})')
        else:
            app.logger.info(f'Scheduled campaign {campaign.name} (ID: {campaign_id}) to start at {start_time} - Sending {len(targets)} emails in batches of {batch_size} every {interval} minutes')
            #sched.start()

        return


    def send_emails(self, recipients, email, mail, base_url, job_id, batch_size, sched, data, total_recipients, ip, port, url):
        """
        Sends emails to the targets in batches.  This function alwasy runs on a separate thread.
        @param recipients: list - all remaining targets to send an email to for the specified campaign
        @param email:
        @param mail: Flask Mail Instance
        @param base_url: 
        @param job_id: int - Unique identifier for the scheduled job (it is identical to campaign_id)
        @param batch_size: int - Number of emails to send at once
        @param sched: Schedule Instance - this is necessary to kill of the job 
        """

        campaign = Campaign.query.filter_by(id=job_id).first()
        if campaign is None:
            sched.remove_job(job_id)
            app.logger.info(f'Campaign ID {job_id} does not exist - Campaign will not start, scheduled job will be removed')
            return

        # Before sending emails, ensure the web server starts on the worker 
        if len(recipients) == total_recipients:
            # If the worker gives an issue, kill off the campaign and log the error
            worker_response = self.start_worker(data, ip, port)

            if not worker_response['success']:
                msg = worker_response['msg']
                campaign.status = msg
                db.session.commit()
                app.logger.error(f'Failed to start campaign {campaign.name} (ID: {campaign.id}) - Worker web server failed to start on server {campaign.server.alias} (IP: {campaign.server.ip}) - Reason: {msg}')
                sched.remove_job(job_id)
                return
            else:
                app.logger.info(f'Campaign {campaign.name} (ID: {campaign.id}) successfully started web server on {campaign.server.alias} (IP: {campaign.server.ip})')
                campaign.status = 'Active'
                db.session.commit()

        for _ in range(batch_size):
            if recipients:
                recipient = recipients.pop()

                msg = Message(subject=email.subject, sender=self.from_address, recipients=[recipient.email])
                msg.html = email.prep_html(base_url=base_url, target=recipient, campaign_id=job_id, url=url)
                msg.body = html2text.html2text(msg.html.decode())

                status = ''

                # Since this function is in a different thread, it doesn't have the app's context by default
                with app.app_context():
                    try:
                        mail.send(msg)
                    except Exception as e:
                        status = 'Error'
                        app.logger.exception(f'Error sending email to {recipient.email} for {campaign.name} (ID: {campaign.id}) - {e}')
                    else:
                        status = 'Sent'
                        app.logger.info(f'Email succesflly sent to {recipient.email} for campaign {campaign.name} (ID: {campaign.id})')

                # Updates email's status in database
                result = Result.query.filter_by(campaign_id=int(job_id), person_id=recipient.id).first()
                result.status = status
                event = Event(action=status, time=datetime.now(), ip_address='N/A')
                result.events.append(event)
                db.session.commit()

            # When all targets have been emailed, the job has to be explicitly removed
            else:
                sched.remove_job(job_id=job_id)
                #with app.app_context():
                app.logger.info(f'Finished sending emails for campaign {campaign.name} (ID: {campaign.id})')
                return

        return

    @staticmethod
    def start_worker(data, ip, port):
        # tell worker to start hosting
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/campaigns/start' % (ip, port), json=data, params=params, verify=False)
        return r.json()


class ProfileSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    from_address = fields.Str()
    smtp_host = fields.Str()
    smtp_port = fields.Number()
    username = fields.Str()
    password = fields.Str()
    tls = fields.Boolean()
    ssl = fields.Boolean()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


    @post_dump
    def decrypt(self, data, **kwargs):
        '''
        Decrypt SMTP username and password
        '''
        data['username'] = decrypt(data['username'].encode()).decode()
        data['password'] = decrypt(data['password'].encode()).decode()
        return data


############################
#  Sending Profile Routes
############################
@app.route('/workspaces/<workspace_id>/profiles', methods=['POST', 'GET'])
@login_required
@user_login_required
def profiles(workspace_id):
    '''
    For GET requests, return all profiles.
    For POST requests, add a new profile.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    if request.method == 'GET':
        all_profiles = Profile.query.filter_by(workspace_id=workspace_id).order_by(Profile.updated_at.desc()).all()
        schema = ProfileSchema(many=True)
        profiles = schema.dump(all_profiles)
        return jsonify(profiles)
    # request is a POST
    else:
        name = request.form.get('Name')
        from_address = request.form.get('From_Address')
        host = request.form.get('SMTP_Host')
        port = request.form.get('SMTP_Port')
        username = request.form.get('Username')
        password = request.form.get('Password')
        tls = request.form.get('TLS')
        ssl = request.form.get('SSL')
    
        profile = Profile.query.filter_by(name=name).first()
        ssl_bool = convert_to_bool(ssl)
        tls_bool = convert_to_bool(tls)

        if profile is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        elif type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400


        profile = Profile(name=name, from_address=from_address, smtp_host=host, smtp_port=port, \
            username=encrypt(username.encode()), password=encrypt(password.encode()), tls=tls_bool, ssl=ssl_bool, workspace_id=workspace_id)
        db.session.add(profile)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()

        schema = ProfileSchema()
        profile_data = schema.dump(profile)
        app.logger.info(f'Added profile {name} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(profile_data), 201


@app.route('/workspaces/<workspace_id>/profiles/<profile_id>', methods=['GET', 'POST', 'DELETE', 'PUT'])
@login_required
@user_login_required
def profile(workspace_id, profile_id):
    '''
    For GET requests, return the profile with the given name.
    For POST requests, use the given profile to send a test email.
    For DELETE requests, delete the given profile.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    profile = Profile.query.filter_by(id=profile_id, workspace_id=workspace_id).first()
    if profile is None:
        return 'profile does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = ProfileSchema()
        profile_data = schema.dump(profile)
        return jsonify(profile_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted profile {profile.name} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(profile)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'profile deleted', 204

    # request is a POST
    elif request.method == 'POST':
        address = request.form.get('Address')
        
        if not validate_email_format(address):
            return 'Enter a valid email address', 400
    
        success = profile.send_test_mail(address)
        if success:
            app.logger.info(f'Test email successfully email to {address} using profile {profile.name} - Sent by {current_user.username} - Client IP address {request.remote_addr}')
        else:
            app.logger.warning(f'Test email failed to {address} using profile {profile.name} - Sent by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': success}), 200, {'ContentType':'application/json'} 
            
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        from_address = request.form.get('From_Address')
        host = request.form.get('SMTP_Host')
        port = request.form.get('SMTP_Port')
        username = request.form.get('Username')
        password = request.form.get('Password')
        tls = request.form.get('TLS')
        ssl = request.form.get('SSL')


        same_profile = Profile.query.filter_by(name=name).first()

        if same_profile is not None and str(same_profile.id) != profile_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        ssl_bool = convert_to_bool(ssl)
        tls_bool = convert_to_bool(tls)

        if type(ssl_bool) != bool or type(tls_bool) != bool:
            return 'ssl/tls must be either true or false', 400
        
        profile.name = name
        profile.from_address = from_address
        profile.smtp_host = host
        profile.smtp_port = port
        profile.username = encrypt(username.encode())
        profile.password = encrypt(password.encode())
        profile.tls = tls_bool
        profile.ssl = ssl_bool
        profile.workspace_id = workspace_id
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()

        schema = ProfileSchema()
        profile_data = schema.dump(profile)
        app.logger.info(f'Updated profile {name} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(profile_data), 200


############################
#  Class Specific Helpers
############################
def validate_email_format(email):
    '''
    Returns True if a given email address has an '@' with a '.' for a later character
    '''
    email_reg = re.compile(r'[^@]+@[^@]+\.[^@]+')
    if email_reg.match(email):
        return True
    else:
        return False