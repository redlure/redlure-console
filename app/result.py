from app import app, db
from marshmallow import Schema, fields, post_dump
from flask import request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
import random
import json
import string
from app.cipher import decrypt
from app.list import List, PersonSchema
from app.campaign import Campaign, CampaignSchema, Campaignpages, WorkerCampaignSchema, convert_to_datetime, validate_campaign_makeup
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.server import Server, ServerSchema
from app.domain import Domain, DomainSchema
from app.page import Page
from app.email import Email
from app.profile import Profile
from app.apikey import require_api_key
from app.functions import user_login_required, convert_to_bool


####################
#  Result Classes
####################

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
    action = db.Column(db.String(32))
    time = db.Column(db.DateTime)
    form = db.relationship('Form', backref='event', uselist=False, lazy=True, cascade='all,delete')


class EventSchema(Schema):
    id = fields.Number()
    result_id = fields.Number()
    ip_address = fields.Str()
    action = fields.Str()
    time = fields.DateTime(format='%m-%d-%y %H:%M:%S')
    form = fields.Nested(FormSchema, strict=True)


# Result Classes
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'))
    tracker = db.Column(db.String(32), nullable=False, unique=True)
    status = db.Column(db.String(32))
    #forms = db.relationship('Form', backref='result', lazy=True, cascade='all,delete')
    events = db.relationship('Event', backref='result', lazy=True, cascade='all,delete')


    def __init__(self, **kwargs):
        self.status = 'Scheduled'
        self.__dict__.update(kwargs)


class ResultSchema(Schema):
    id = fields.Number()
    campaign_id = fields.Number()
    person = fields.Nested(PersonSchema, strict=True)
    tracker = fields.Str()
    status = fields.Str()
    #forms = fields.Nested(FormSchema, strict=True, many=True)
    events = fields.Nested(EventSchema, strict=True, many=True)


# Schema for dumping Campain objects for result routes
class ResultCampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    status = fields.Str()
    server = fields.Nested(ServerSchema, strict=True)
    domain = fields.Nested(DomainSchema, strict=True)
    start_time = fields.DateTime(format='%m-%d-%y %H:%M')
    end_time = fields.DateTime(format='%m-%d-%y %H:%M')


####################
#  Result Routes
####################
@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/results')
@login_required
@user_login_required
def campaign_results(workspace_id, campaign_id):
    '''
    For GET requests, return results for the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    schema = ResultSchema(many=True)
    results = schema.dump(campaign.results)
    return jsonify(results)


@app.route('/workspaces/<workspace_id>/results')
@login_required
@user_login_required
def workspace_results(workspace_id):
    '''
    For GET requests, return results for all campaigns in the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    workspace_results = Result.query.join(Campaign).join(Workspace).filter(Workspace.id == workspace_id).all()
    campaigns = Campaign.query.filter_by(workspace_id=workspace_id).all()

    schema = ResultCampaignSchema(many=True)
    c_results = schema.dump(campaigns)

    schema = ResultSchema(many=True)
    results = schema.dump(workspace_results)

    return jsonify(c_results, results)


@app.route('/results/generic', methods=['GET', 'DELETE'])
@login_required
@user_login_required
def generic_results():
    '''
    For GET requests, return submitted events without a result ID
    For DELETE requests, delete all submitted events without a result ID
    '''

    if request.method == 'GET':
        generic_submits = Event.query.filter_by(result_id=None).all()
        schema = EventSchema(many=True)
        data = schema.dump(generic_submits)
        return jsonify(data)
    elif request.method == 'DELETE':
        Event.query.filter_by(result_id=None).delete()
        db.session.commit()
        return 'results deleted', 204


@app.route('/results/generic/<event_id>', methods=['DELETE'])
@login_required
@user_login_required
def generic_result(event_id):
    '''
    For DELETE requests, delete the specified event, if event has no result ID
    '''
    event = Event.query.filter_by(id=event_id).first()
    if event.result_id != None:
        return 'event has a result ID', 404

    db.session.delete(event)
    db.session.commit()
    return 'event deleted', 204


#########################################################
# !!
# Campaigns route
# Imported to result.py to avoid circular dependency
###########################################################
@app.route('/workspaces/<workspace_id>/campaigns', methods=['GET', 'POST'])
@login_required
@user_login_required
def campaigns(workspace_id):
    '''
    For GET requests, return all campaigns for the given workspace.
    For POST requests, all a campaign to the given workspace.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_campaigns = Campaign.query.filter_by(workspace_id=workspace_id).order_by(Campaign.updated_at.desc()).all()

        # sort the pages associated with the campaign by index
        # for campaign in all_campaigns:
        #     campaign.pages.sort(key=lambda camp: camp.index)

        schema = CampaignSchema(many=True)
        campaign_data = schema.dump(all_campaigns)
        return jsonify(campaign_data)

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        email_id = request.form.get('Email')
        page_ids = request.form.getlist('Pages[]') # page names is a list of page names # page names is a list of page names
        profile_id = request.form.get('Profile')
        list_id = request.form.get('List')
        domain_id = request.form.get('Domain')
        server_id = request.form.get('Server')
        port = request.form.get('Port')
        ssl = request.form.get('SSL')
        redirect_url = request.form.get('Redirect_URL')
        start_time = request.form.get('Start_Time')
        interval = request.form.get('Interval')
        batch_size =request.form.get('Batch_Size')
        payload_url = request.form.get('Payload_URL')
        payload_file = request.form.get('Payload_File')

        #print(start_time)
        if start_time:
            start_time = convert_to_datetime(start_time)
        else:
            start_time = datetime.now()
        #print(type(start_time))
        #print(start_time)


        ssl_bool = convert_to_bool(ssl)
        if type(ssl_bool) != bool:
            return 'ssl must be either true or false', 400

        pages = []

        for page_id in page_ids:
            page = Page.query.with_entities(Page).filter((Page.id == page_id) & ((Page.workspace_id == workspace_id) | (Page.workspace_id == 1))).first()
            pages.append(page)
        print(email_id)
        email = Email.query.with_entities(Email).filter((Email.id == email_id) & ((Email.workspace_id == workspace_id) | (Email.workspace_id == 1))).first()
        profile = Profile.query.with_entities(Profile).filter((Profile.id == profile_id) & ((Profile.workspace_id == workspace_id) | (Profile.workspace_id == 1))).first()
        targetlist = List.query.with_entities(List).filter((List.id == list_id) & ((List.workspace_id == workspace_id) | (List.workspace_id == 1))).first()
        domain = Domain.query.filter_by(id=domain_id).first()
        server = Server.query.filter_by(id=server_id).first()

        # make sure all given modules exist before continuing
        makeup = validate_campaign_makeup(email, pages, profile, targetlist, domain, server)
        if makeup:
            return makeup
        
        campaign = Campaign(name=name, workspace_id=workspace_id, email_id=email.id, profile_id=profile.id, \
                start_time=start_time, send_interval=interval, batch_size=batch_size, \
                list_id=targetlist.id, domain_id=domain.id, server_id=server.id, port=port, ssl=ssl_bool, redirect_url=redirect_url, \
                payload_url=payload_url, payload_file=payload_file)

        db.session.add(campaign)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        for idx, page in enumerate(pages):
            #page_association = Campaignpages(index=idx)
            #campaign.pages.append(page_association)
            page_association = Campaignpages(campaign_id=campaign.id, page_id=page.id, index=idx)
            db.session.add(page_association)
            db.session.commit()

        schema = WorkerCampaignSchema()
        campaign_data = schema.dump(campaign)
        app.logger.info(f'Added campaign {name} (ID: {campaign.id}) (Start time: {start_time}) - Added by {current_user.username} - Client IP address {request.remote_addr}')

        prep_tracking(campaign.list.targets, campaign.id)
        campaign.cast(campaign_data)

        schema = CampaignSchema()
        data = schema.dump(campaign)

        return json.dumps({'success': True, 'campaign': data}), 200, {'ContentType':'application/json'}


#########################################################
# !!
# Campaigns route
# Imported to result.py to avoid circular dependency
###########################################################
@app.route('/workspaces/<workspace_id>/campaigns/<campaign_id>/kill', methods=['GET'])
@login_required
@user_login_required
def kill(workspace_id, campaign_id):
    '''
    For GET requests, kill the given campaign.
    '''

    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    campaign = Campaign.query.filter_by(id=campaign_id, workspace_id=workspace_id).first()
    if campaign is None:
        return 'campaign does not exist', 404

    if campaign.status != 'Active':
        return 'campaign is not active', 400

    if campaign.server.check_status() != 'Online':
        return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

    http_code = campaign.kill()

    if http_code != 200:
        app.logger.warning(f'Error stopping campaign {campaign.name} (ID: {campaign.id}) - Stop attempted by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

    app.logger.info(f'Stopped campaign {campaign.name} (ID: {campaign.id}) - Stopped by {current_user.username} - Client IP address {request.remote_addr}')
    sch = Result.query.filter_by(campaign_id=campaign.id, status='Scheduled').all()
    for x in sch:
        app.logger.warning(f'Campaign killed before email was scheduled to send to {x.person.email} - result (ID: {x.id}) deleted')
        db.session.delete(x)
    db.session.commit()
    return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


############################################################
# API routes to accept data from redlure-workers (servers)
# ##########################################################
@app.route('/results/update', methods=['POST'])
@require_api_key
def record_action():
    '''
    Requires matching API key. For POST requests, check the database for a result with
    a matching identifier and update the result's status.
    '''
    tracker = request.form.get('tracker')
    action = request.form.get('action')
    ip = request.form.get('ip')

    result = Result.query.filter_by(tracker=tracker).first()

    # tracker string is not in db
    if result is None:
        return 'no tracker', 404

    app.logger.info(f'Received {action} status from worker for result ID {result.id} in campaign {result.campaign.name} ({result.campaign.id})')
    event = Event(ip_address=ip, action=action, time=datetime.now())
    result.events.append(event)
    db.session.commit()

    # update result status in the database
    if result.status != 'Submitted':
        if action == 'Downloaded':
            result.status = action
            db.session.commit()
        elif action == 'Clicked' and result.status != 'Downloaded':
            result.status = action
            db.session.commit()
        elif action == 'Opened' and result.status not in ['Clicked', 'Downloaded']:
            result.status = action
            db.session.commit()

    return 'updated'


@app.route('/results/form', methods=['POST'])
@require_api_key
def record_form():
    '''
    Requires matching API key. For POST requests, check the database for a result with
    a matching identifier and record the submiited form values.
    '''
    tracker = request.form.get('tracker')
    form_data = request.form.get('data')
    ip = request.form.get('ip')

    result = Result.query.filter_by(tracker=tracker).first()

    # create event
    event = Event(ip_address=ip, action='Submitted', time=datetime.now())

    # create form
    enc_form_data = encrypt(form_data.encode())
    form = Form(data=enc_form_data)

    # add form to event object
    event.form = form

    # tracker string is not in db, add event + form will null result ID
    if result is None:
        db.session.add(event)
        db.session.commit()

    # else add event + form to our result
    else:
        app.logger.info(f'Received form data from worker for result ID {result.id} in campaign {result.campaign.name} ({result.campaign.id})')

        # add event to result object
        result.events.append(event)
        #result.forms.append(form)
        result.status = 'Submitted'
        db.session.commit()
    return 'updated'


############################
#  Class Specific Helpers
############################
def prep_tracking(targets, campaign_id):
    for target in targets:
        tracker = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

        # make sure the tracker is not a repeat
        result = Result.query.filter_by(tracker=tracker).first()

        if result is None:
            result = Result(campaign_id=campaign_id, person_id=target.id, tracker=tracker)
            db.session.add(result)
            db.session.commit()
        else:
            prep_tracking(targets=[target], campaign_id=campaign_id)
