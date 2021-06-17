from app import app, db, sched
from marshmallow import Schema, fields, post_dump
from datetime import datetime, timedelta
from flask import request, jsonify
from flask_mail import Message
from flask_login import login_required, current_user
import json
import html2text
import requests
import string
from magic import Magic
from app.cipher import decrypt
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.email import Email, EmailSchema
from app.domain import Domain, DomainSchema
from app.server import Server, ServerSchema
from app.list import List, ListSchema
from app.page import Page, PageSchema
from app.profile import Profile, ProfileSchema
from app.apikey import APIKey
from app.functions import user_login_required, convert_to_bool 

##############################################
# !!
# Event and Form classes imported from result.py
# Avoids circular dependency that arises when
# adding an email sent event to a result
##############################################

# Form Classes (HTML form data submitted by victims)
class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    data = db.Column(db.String(128))


class FormSchema(Schema):
    id = fields.Number()
    event_id = fields.Number()
    data = fields.Dict()


    @post_dump
    def serialize_form(self, data, **kwargs):
        '''
        Decrypt and convert the submitted form data from type String back to Dict
        '''
        decrypted_data = decrypt(data['data']).decode()
        data['data'] = json.loads(decrypted_data)
        return data

# Event class (tracks each open,click,download,submission in the database with timestamps and IPs)
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('result.id'), nullable=True)
    ip_address = db.Column(db.String(32))
    user_agent = db.Column(db.String(128))
    action = db.Column(db.String(32))
    time = db.Column(db.DateTime)
    form = db.relationship('Form', backref='event', uselist=False, lazy=True, cascade='all,delete')


class EventSchema(Schema):
    id = fields.Number()
    result_id = fields.Number()
    ip_address = fields.Str()
    user_agent = fields.Str()
    action = fields.Str()
    time = fields.DateTime(format='%m-%d-%y %H:%M:%S')
    form = fields.Nested(FormSchema, strict=True)


############################
#  Campaign Classes
############################

# Association Object for campaigns and pages
class Campaignpages(db.Model):
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), primary_key=True)
    index = db.Column(db.Integer)


class CampaignpagesSchema(Schema):
    index = fields.Number()
    page = fields.Nested(PageSchema, strict=True)


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=True)
    redirect_url = db.Column(db.String(64), nullable=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=True)
    port = db.Column(db.Integer, nullable=False)
    ssl = db.Column(db.Boolean, nullable=False)
    results = db.relationship('Result', backref='campaign', lazy=True, cascade='all,delete')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    status = db.Column(db.String(32), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True, default='')
    end_time = db.Column(db.DateTime, nullable=True, default=datetime(1, 1, 1, 0, 0, 0)) # For some reason the real end date does not get stored unless the attribute is initialized with a datetime
    send_interval = db.Column(db.Integer, default=0)  # Number of minutes to wait between sending batch of emails
    batch_size = db.Column(db.Integer)
    payload_url = db.Column(db.String(64))
    payload_file = db.Column(db.String(64))
    attachment = db.Column(db.LargeBinary, nullable=True)
    attachment_name = db.Column(db.String(64), nullable=True)
    pages = db.relationship('Campaignpages', backref='campaign', cascade='all, delete-orphan')


    def __init__(self, **kwargs):
        self.status = 'Inactive'
        self.__dict__.update(kwargs)


    def start_worker(self):
        # tell worker to start hosting
        schema = WorkerCampaignSchema()
        data = schema.dump(self)
        params = {'key': APIKey.query.first().key}
        r = requests.post(f'https://{self.server.ip}:{self.server.port}/campaigns/start', json=data, params=params, verify=False)
        return r.json()


    def cast(self):
        #schedule the campaign
        url = Campaignpages.query.filter_by(campaign_id=self.id, index=0).first().page.url
        base_url = 'https://%s' % self.domain.domain if self.ssl else 'http://%s' % self.domain.domain
        mail = self.profile.get_mailer()
        #self.profile.schedule_campaign(email=self.email, targets=self.list.targets, campaign_id=self.id, base_url=base_url, interval=self.send_interval, batch_size=self.batch_size, start_time=self.start_time, data=data, ip=self.server.ip, port=self.server.port, url=url)

        job_id = str(self.id)

        # Schedule the campaign and intialize it
        current_jobs = sched.get_jobs()

        # In case the batch size or interval are blank, set them appropriately 
        if not self.batch_size: self.batch_size = len(self.list.targets)
        if not self.send_interval: self.send_interval = 0
        db.session.commit()

        # Schedule the campaign and intialize it
        try:
            if self.start_time < datetime.now():
                # schedule campaign to be run in 8 seconds from current timme - anything less and the campaign will wait 1 interval before sending the first batch of emails. Does not affect sending without batches or future start times
                sched.add_job(func=self.run_campaign, trigger='interval', minutes=int(self.send_interval), id=job_id, start_date=datetime.now() + timedelta(0,8), replace_existing=True, args=[mail, base_url, url])
            else:
                sched.add_job(func=self.run_campaign, trigger='interval', minutes=int(self.send_interval), id=job_id, start_date=self.start_time, replace_existing=True, args=[mail, base_url, url])
        except Exception:
            app.logger.exception(f'Error scheduling campaign {self.name} (ID: {self.id})')
        else:
            app.logger.info(f'Scheduled campaign {self.name} (ID: {self.id}) to start at {self.start_time} - Sending {len(self.list.targets)} emails in batches of {self.batch_size} every {self.send_interval} minutes')

        self.status = 'Scheduled'
        db.session.commit()


    def run_campaign(self, mail, base_url, url):
        # Since this function is in a different thread, it doesn't have the app's context by default
        with app.app_context():
            unsent_results = [x for x in Campaign.query.filter_by(id=self.id).first().results if x.status == 'Scheduled']
            campaign = Campaign.query.filter_by(id=self.id).first() # since in diff thread, references to self will not update the database

            # start the worker and send emails
            job_id = str(self.id)

            if self is None:
                sched.remove_job(job_id)
                app.logger.info(f'Campaign ID {job_id} does not exist - Campaign will not start, scheduled job will be removed')
                return

            # Before sending emails, ensure the web server starts on the worker 
            # If the worker gives an issue, kill off the campaign and log the error
            if campaign.status == 'Scheduled':
                worker_response = self.start_worker()

                if not worker_response['success']:
                    msg = worker_response['msg']
                    campaign.status = msg
                    db.session.commit()
                    app.logger.error(f'Failed to start campaign {self.name} (ID: {self.id}) - Worker web server failed to start on server {self.server.alias} (IP: {self.server.ip}) - Reason: {msg}')
                    sched.remove_job(job_id)
                    return
                else:
                    app.logger.info(f'Campaign {self.name} (ID: {self.id}) successfully started web server on {self.server.alias} (IP: {self.server.ip})')
                    campaign.status = 'Active'
                    db.session.commit()


            for _ in range(int(self.batch_size)):
                if unsent_results:
                    result = unsent_results.pop()
                    recipient = result.person

                    msg = Message(subject=self.email.subject, sender=self.profile.from_address, recipients=[recipient.email])
                    msg.html = self.email.prep_html(base_url=base_url, target=recipient, result=result, url=url)
                    msg.body = html2text.html2text(msg.html.decode())

                    if self.attachment:
                        # Determine mimetype of attachment from bytes
                        mime = Magic(mime=True)
                        mimetype = mime.from_buffer(self.attachment)
                        # attach the file
                        msg.attach(self.attachment_name, mimetype, self.attachment)

                    status = ''

                    ts = datetime.now().strftime('%y%m%d.%H%M%S')
                    domain = app.config['MAIL_USERNAME'].split('@')[1]
                    msg.msgId = f'<{ts}@{domain}>'

                    try:
                        mail.send(msg)
                    except Exception as e:
                        status = 'Error'
                        app.logger.exception(f'Error sending email to {recipient.email} for {self.name} (ID: {self.id}) - {e}')
                    else:
                        status = 'Sent'
                        app.logger.info(f'Email succesflly sent to {recipient.email} for campaign {self.name} (ID: {self.id})')

                    # Updates email's status in database
                    result.status = status
                    event = Event(action=status, time=datetime.now(), ip_address='N/A')
                    result.events.append(event)
                    db.session.commit()

                # When all targets have been emailed, the job has to be explicitly removed
                else:
                    sched.remove_job(job_id=job_id)
                    app.logger.info(f'Finished sending emails for campaign {self.name} (ID: {self.id})')
                    return
        return


    def kill(self):
        payload = {'id': self.id, 'port': self.port}
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/campaigns/kill' % (self.server.ip, self.server.port), data=payload, params=params, verify=False)
        if r.status_code == 200:
            # remove from job scheduler
            self.remove_job()
            self.end_time = datetime.now()
            self.status = 'Complete'
            db.session.commit()
        return r.status_code


    def remove_job(self):
        try:
            sched.remove_job(str(self.id))
        except:
            pass
        return


class CampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    workspace_id = fields.Number()
    email = fields.Nested(EmailSchema, strict=True)
    pages = fields.Nested(CampaignpagesSchema, strict=True, many=True)
    redirect_url = fields.Str()
    profile = fields.Nested(ProfileSchema, strict=True)
    list = fields.Nested(ListSchema, strict=True)
    domain = fields.Nested(DomainSchema, strict=True)
    server = fields.Nested(ServerSchema, strict=True)
    port = fields.Number()
    ssl = fields.Boolean()
    created_at = fields.DateTime(format='%m-%d-%y %H:%M')
    updated_at = fields.DateTime(format='%m-%d-%y %H:%M')
    status = fields.Str()
    payload_url = fields.Str()
    start_time = fields.DateTime(format='%m-%d-%y %H:%M')
    payload_file = fields.Str()
    attachment_name = fields.Str()


class WorkerCampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    pages = fields.Nested(CampaignpagesSchema, strict=True, many=True)
    redirect_url = fields.Str()
    domain = fields.Nested(DomainSchema, strict=True)
    server = fields.Nested(ServerSchema, strict=True)
    port = fields.Number()
    ssl = fields.Boolean()
    payload_url = fields.Str()
    payload_file = fields.Str()


    @post_dump
    def order_pages(self, data, **kwargs):
        '''
        Order html pages by index attribute
        '''
        data['pages'].sort(key=lambda x: x['index'])
        return data


############################
#  Campaign Routes
############################

###################################################################################
# !!
# Main Campaigns route @app.route('/workspaces/<workspace_id>/campaigns') lives
# in result.py to avoid circular dependency that occurs when checking Result objects
# for duplicate tracking IDs, during creation of new campaign
#####################################################################################

@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
@user_login_required
def campaign(workspace_id, campaign_id):
    '''
    For GET requests, return the given campaign.
    For DELETE requests, delete the given campaign.
    For PUT requests, update the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    # request is a GET
    if request.method == 'GET':
        schema = CampaignSchema()
        campaign_data = schema.dump(campaign)
        return jsonify(campaign_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        if campaign.status == 'Active':
            campaign.kill()
        if campaign.status == 'Scheduled':
            campaign.remove_job()
        app.logger.info(f'Deleted campaign {campaign.name} (ID: {campaign.id}) - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(campaign)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'campaign deleted', 204

    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        email_name = request.form.get('Email_Name')
        profile_name = request.form.get('Profile_Name')
        list_name = request.form.get('List_Name')
        domain_name = request.form.get('Domain_Name')
        server_alias = request.form.get('Server_Alias')
        port = request.form.get('Port')
        ssl = request.form.get('SSL')
        redirect_url = request.form.get('Redirect_URL')

        same_campaign = Campaign.query.filter_by(name=name).first()

        if same_campaign is not None and str(same_campaign.id) != campaign_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        ssl_bool = convert_to_bool(ssl)
        if type(ssl_bool) != bool:
            return 'ssl must be either true or false', 400

        email = Email.query.filter_by(name=email_name, workspace_id=workspace_id).first()
        profile = Profile.query.filter_by(name=profile_name, workspace_id=workspace_id).first()
        targetlist = List.query.filter_by(name=list_name, workspace_id=workspace_id).first()
        domain = Domain.query.filter_by(domain=domain_name).first()
        server = Server.query.filter_by(alias=server_alias).first()

        # make sure all given modules exist before continuing
        makeup = validate_campaign_makeup(email, page, profile, targetlist, domain, server)
        if makeup:
            return makeup

        campaign.name = name
        campaign.email_id = email.id
        campaign.profile_id = profile.id
        campaign.list_id = targetlist.id
        campaign.domain_id = domain.id
        campaign.server_id = server.id
        campaign.port = port
        campaign.ssl = ssl_bool
        campaign.redirect_url = redirect_url
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'campaign updated'


@app.route('/workspaces/<workspace_id>/campaigns/validateips', methods=['POST'])
@login_required
@user_login_required
def validate_ips(workspace_id):
    '''
    For POST requests, validate that the IP address of a given server and domain match
    '''
    domain_id = request.form.get('Domain')
    server_id = request.form.get('Server')
    print(domain_id)
    domain_obj = Domain.query.filter_by(id=domain_id).first()
    if domain_obj is None:
        return 'domain does not exist', 404

    server = Server.query.filter_by(id=server_id).first()
    if server is None:
        return 'server does not exist', 404

    if server.ip != domain_obj.ip:
        return json.dumps({'success': False, 'msg': 'Chosen domain does not resolve to the IP address of the chosen server'}), 200, {'ContentType':'application/json'}
    return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


@app.route('/workspaces/<workspace_id>/campaigns/validatecerts', methods=['POST'])
@login_required
@user_login_required
def validate_certs(workspace_id):
    '''
    For POST requests, check that the provided domain has certs on the provided server
    '''
    domain_id = request.form.get('Domain')
    server_id = request.form.get('Server')

    domain_obj = Domain.query.filter_by(id=domain_id).first()
    if domain_obj is None:
        return 'domain does not exist', 404

    server = Server.query.filter_by(id=server_id).first()
    if server is None:
        return 'server does not exist', 404

    data = server.check_certs(domain_obj.cert_path, domain_obj.key_path)
    return json.dumps(data.json()), 200, {'ContentType':'application/json'}


###################################################################################
# !!
# Campaigns kill route @app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/kill')
# lives in result.py to avoid circular dependency that occurs when deleting Result
# objects tied to unsent emails when a campaign is killed before all emails send
#####################################################################################


@app.route('/workspaces/<workspace_id>/campaigns/modules')
@login_required
@user_login_required
def campaign_modules(workspace_id):
    '''
    For GET requests, return possible campaign modules in the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404


    page_names = Page.query.with_entities(Page.id, Page.name).filter((Page.workspace_id == workspace_id) | (Page.workspace_id == 1)).all()
    list_names = List.query.with_entities(List.id, List.name).filter((List.workspace_id == workspace_id) | (List.workspace_id == 1)).all()
    email_names = Email.query.with_entities(Email.id, Email.name).filter((Email.workspace_id == workspace_id) | (Email.workspace_id == 1)).all()
    profile_names = Profile.query.with_entities(Profile.id, Profile.name).filter((Profile.workspace_id == workspace_id) | (Profile.workspace_id == 1)).all()
    domain_names = Domain.query.with_entities(Domain.id, Domain.domain, Domain.ip).all()
    server_names = Server.query.with_entities(Server.id, Server.alias, Server.ip).all()

    all_info = {
        "pages": [dict(zip(['id','name'],p)) for p in page_names],
        "lists": [dict(zip(['id', 'name'],l)) for l in list_names],
        "emails": [dict(zip(['id', 'name'],e)) for e in email_names],
        "profiles": [dict(zip(['id', 'name'],p)) for p in profile_names],
        "domains": [dict(zip(['id', 'domain', 'ip'],d)) for d in domain_names],
        "servers": [dict(zip(['id','alias','ip'],s)) for s in server_names],
        "console_time": datetime.now()
    }

    return jsonify(all_info), 200

############################
#  Class Specific Helpers
############################
def validate_campaign_makeup(email, pages, profile, targetlist, domain, server):
    '''
    Return a message and HTTP error code if a given campaign module does not exist.
    '''
    if email is None:
        return json.dumps({'success': False, 'msg': 'Selected email is invalid'}), 200, {'ContentType':'application/json'}

    for page in pages:
        if page is None:
            return json.dumps({'success': False, 'msg': 'At least 1 selected page is invalid'}), 200, {'ContentType':'application/json'}
    
    if profile is None:
        return json.dumps({'success': False, 'msg': 'Selected profile is invalid'}), 200, {'ContentType':'application/json'}

    if targetlist is None:
        return json.dumps({'success': False, 'msg': 'Selected list is invalid'}), 200, {'ContentType':'application/json'}

    if domain is None:
        return json.dumps({'success': False, 'msg': 'Selected domain is invalid'}), 200, {'ContentType':'application/json'}

    if server is None:
        return json.dumps({'success': False, 'msg': 'Selected server is invalid'}), 200, {'ContentType':'application/json'}


def convert_to_datetime(dt_string):
    '''
    Converts a string to a datetime object
    
    Example 
    Input: '2019-07-31T10:30:30-04:00' (str)
    Output: 2019-07-31 10:30:30 (datetime)
    '''
    try:
        send_date, send_time = dt_string.split('T')
        send_time = send_time.split('-')[0]
        send_datetime = f'{send_date} {send_time}'
        send_datetime = datetime.strptime(send_datetime, '%Y-%m-%d %H:%M:%S')
    except:
        send_date, send_time = dt_string.split(' ')
        send_time = send_time.split('-')[0]
        send_datetime = f'{send_date} {send_time}'
        send_datetime = datetime.strptime(send_datetime, '%m/%d/%Y %H:%M:%S')

    return send_datetime
