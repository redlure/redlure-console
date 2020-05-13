from app import app, db
from marshmallow import Schema, fields, post_dump
from datetime import datetime
from flask import request, jsonify
from flask_login import login_required, current_user
import json
#import random
import requests
import string
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.email import Email, EmailSchema
from app.domain import Domain, DomainSchema
from app.server import Server, ServerSchema
from app.list import List, ListSchema
from app.page import Page, PageSchema
from app.profile import Profile, ProfileSchema
from app.functions import user_login_required, convert_to_bool 


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
    pages = db.relationship('Campaignpages', backref='campaign', cascade='all, delete-orphan')


    def __init__(self, **kwargs):
        self.status = 'Inactive'
        self.__dict__.update(kwargs)

    '''
    def prep_tracking(self, targets):
        for target in targets:
            tracker = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

            # make sure the tracker is not a repeat
            result = Result.query.filter_by(tracker=tracker).first()

            if result is None:
                result = Result(campaign_id=self.id, person_id=target.id, tracker=tracker)
                db.session.add(result)
                db.session.commit()
            else:
                self.prep_tracking(self,targets=[target])
    '''

    def cast(self, data):
        # schedule the campaign
        url = Campaignpages.query.filter_by(campaign_id=self.id, index=0).first().page.url
        base_url = 'https://%s' % self.domain.domain if self.ssl else 'http://%s' % self.domain.domain
        self.profile.schedule_campaign(email=self.email, targets=self.list.targets, campaign_id=self.id, base_url=base_url, interval=self.send_interval, batch_size=self.batch_size, start_time=self.start_time, data=data, ip=self.server.ip, port=self.server.port, url=url)
        self.status = 'Scheduled'
        db.session.commit()


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
            kill(workspace_id, campaign_id)
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
    send_date, send_time = dt_string.split('T')
    send_time = send_time.split('-')[0]
    send_datetime = f'{send_date} {send_time}'
    send_datetime = datetime.strptime(send_datetime, '%Y-%m-%d %H:%M:%S')

    return send_datetime
