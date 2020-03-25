from app import app, db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from marshmallow import Schema, fields, post_dump
from app.cipher import decrypt
from flask_mail import Mail, Message
from app import app
from flask import jsonify
from socket import gethostbyname
import string
import random
from datetime import datetime
import os
import subprocess
import shutil
from binascii import hexlify
import requests
from bs4 import BeautifulSoup
import json
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import html2text


# table to hold 1 encrypted value to test if cipher passphrase is correct
class CipherTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(64))


role_access = db.Table('role access',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspace.id'), primary_key=True)
)

# Workspace Classes
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


    def __repr__(self):
        return '<Workspace {}>'.format(self.name)


class WorkspaceSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Role Classes
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    role_type = db.Column(db.String(64), nullable=False)
    workspaces = db.relationship('Workspace', secondary=role_access, lazy=True, backref=db.backref('roles', lazy=True))
    users = db.relationship('User', backref='role', lazy=True, cascade='all,delete')

    def __repr__(self):
        return '<Role {}>'.format(self.name)


class RoleSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    role_type = fields.Str()
    workspaces = fields.Nested(WorkspaceSchema, many=True, strict=True)


# User Classes
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


    def __repr__(self):
        return '<User {}>'.format(self.username)


class UserSchema(Schema):
    id = fields.Number()
    username = fields.Str()
    role = fields.Nested(RoleSchema, strict=True)
    

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


# Sending Profile Classes
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
        sched = BackgroundScheduler()
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
            sched.add_job(func=self.send_emails, trigger='interval', minutes=interval, id=job_id, start_date=start_time, replace_existing=True, args=[targets, email, mail, base_url, job_id, batch_size, sched, data, len(targets), ip, port, url])
        except Exception:
            app.logger.exception(f'Error scheduling campaign {campaign.name} (ID: {campaign_id})')
        else:
            app.logger.info(f'Scheduled campaign {campaign.name} (ID: {campaign_id}) to start at {start_time} - Sending {len(targets)} emails in batches of {batch_size} every {interval} minutes')
            sched.start()

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

        # Before sending emails, ensure the web server starts on the worker
        campaign = Campaign.query.filter_by(id=job_id).first() 
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

                # Since this function is in a different thread, it doesn't have the app's context by default
                with app.app_context():
                    try:
                        mail.send(msg)
                    except Exception:
                        app.logger.exception(f'Error sending email to {recipient.email} for {campaign.name} (ID: {campaign.id})')
                    else:
                        app.logger.info(f'Email succesflly sent to {recipient.email} for campaign {campaign.name} (ID: {campaign.id})')

                # Updates email's status in database
                result = Result.query.filter_by(campaign_id=int(job_id), person_id=recipient.id).first()
                result.status = 'Sent'
                event = Event(action='Sent', time=datetime.now(), ip_address='N/A')
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


# Person Classes (Targets)
class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=True)
    results = db.relationship('Result', backref='person', lazy=False, cascade='all,delete')

    def __repr__(self):
        return '<Person {}>'.format(self.email)


class PersonSchema(Schema):
    id = fields.Number()
    first_name = fields.Str()
    last_name = fields.Str()
    email = fields.Str()


# Target List Classes
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


# Email Classes
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

    def __repr__(self):
        return '<Email {}>'.format(self.name)

    def prep_html(self, base_url, target, campaign_id, url):
        '''
        Replace variables in the email HTML with proper values and insert the tracking image URL if needed.
        '''
        # get result for this target in this campaign
        result = Result.query.filter_by(campaign_id=int(campaign_id), person_id=target.id).first()
        # get if campaign is using SSL
        ssl = result.campaign.ssl
        # get port the worker will host on
        port = result.campaign.port
        # get the domain name the campaign is using
        domain = result.campaign.domain.domain

        payload_url_path = result.campaign.payload_url

        if ssl:
            base_url = f'https://{domain}:{port}'
            payload_url = f'https://{domain}:{port}{payload_url_path}?id={result.tracker}'
        else:
            base_url = f'http://{domain}:{port}'
            payload_url = f'http://{domain}:{port}{payload_url_path}?id={result.tracker}'

        if url[0] != '/': url = '/' + url

        html = self.html
        if target.first_name: html = html.replace(b'{{ fname }}', str.encode(target.first_name))
        if target.last_name: html = html.replace(b'{{ lname }}', str.encode(target.last_name))
        if target.first_name and target.last_name: html = html.replace(b'{{ name }}', str.encode('%s %s' % (target.first_name, target.last_name)))
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


# Page Classes
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    url = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    campaigns = db.relationship('Campaignpages', backref='page', cascade='all, delete-orphan')


    def __repr__(self):
        return '<Page {}>'.format(self.name)


    def find_form_fields(self):
        fields = []
        forms = BeautifulSoup(self.html, features="lxml").find_all('form')
        inputs = forms[0].find_all('input')
        for input in inputs:
            fields.append(input['name'])


class PageSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    html = fields.Str()
    url = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


# Domain Classes
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64))
    cert_path = db.Column(db.String(128))
    key_path = db.Column(db.String(128))
    campaigns = db.relationship('Campaign', backref='domain', lazy=True)


    def __repr__(self):
        return '<Domain {}>'.format(self.domain)


    def update_ip(self):
        '''
        Get the IP address that the domain name is pointed at
        '''
        try:
            self.ip = gethostbyname(self.domain)
        except:
            self.ip = 'Domain not found'


    def generate_cert(self, server):
        payload = {'domain': self.domain}
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/certificates/generate' % (server.ip, server.port), params=params, data=payload, verify=False)
        if r.json()['success']:
            self.cert_path = r.json()['cert_path']
            self.key_path = r.json()['key_path']
            db.session.commit()
        return r


class DomainSchema(Schema):
    id = fields.Number()
    domain = fields.Str()
    ip = fields.Str()
    cert_path = fields.Str()
    key_path = fields.Str()


# Form Classes (HTML form data submitted by victims)
class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #result_id = db.Column(db.Integer, db.ForeignKey('result.id'), nullable=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    data = db.Column(db.String(128))


class FormSchema(Schema):
    id = fields.Number()
    #result_id = fields.Number()
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


# Server classes
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True)
    port = db.Column(db.Integer, nullable=False)
    alias = db.Column(db.String(64), unique=True)
    status = db.Column(db.String(64))
    campaigns = db.relationship('Campaign', backref='server', lazy=True)


    def __init__(self, **kwargs):
        db.session.add(self)
        self.__dict__.update(kwargs)
        db.session.commit()


    def check_status(self):
        params = {'key': APIKey.query.first().key}
        try:
            r = requests.post('https://%s:%d/status' % (self.ip, self.port), params=params, verify=False, timeout=5)
            if r.status_code == 200:
                self.status = 'Online'
            elif r.status_code == 401:
                self.status = 'Mismatching API Key'
            else:
                self.status = 'Offline'
        except:
            self.status = 'Offline'
        db.session.commit()
        return self.status


    def check_processes(self):
        self.check_status()
        if self.status == 'Online':
            params = {'key': APIKey.query.first().key}
            r = requests.post('https://%s:%d/processes/check' % (self.ip, self.port), params=params, verify=False)
            return r


    def kill_process(self, port):
        self.check_status()
        if self.status == 'Online':
            params = {'key': APIKey.query.first().key}
            payload = {'port': port}
            r = requests.post('https://%s:%d/processes/kill' % (self.ip, self.port), params=params, data=payload, verify=False)
            if r.status_code == 200:
                return 'process killed'
            else:
                return 'error killing process'


    def check_certs(self, cert_path, key_path):
        params = {'key': APIKey.query.first().key}
        payload = {'cert_path': cert_path, 'key_path': key_path}
        r = requests.post('https://%s:%s/certificates/check' % (self.ip, self.port), params=params, data=payload, verify=False)
        return r


    def list_files(self):
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/files' % (self.ip, self.port), params=params, verify=False)
        return r


    def upload_file(self, files):
        params = {'key': APIKey.query.first().key}
        payload = {'Filename': files['file'].filename}
        r = requests.post('https://%s:%d/files/upload' % (self.ip, self.port), params=params, files=files, data=payload, verify=False)
        return r


    def delete_file(self, filename):
        params = {'key': APIKey.query.first().key}
        payload = {'Filename': filename}
        r = requests.post('https://%s:%d/files/delete' % (self.ip, self.port), params=params, data=payload, verify=False)
        return r


    def delete_allfiles(self):
        params = {'key': APIKey.query.first().key}
        r = requests.post('https://%s:%d/files/deleteall' % (self.ip, self.port), params=params, verify=False)
        return r


    def __repr__(self):
        return '<Server {}>'.format(self.alias)


class ServerSchema(Schema):
    id = fields.Number()
    ip = fields.Str()
    alias = fields.Str()
    port = fields.Number()
    status = fields.Str()


# API Key Class
class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64))


    def __init__(self):
        db.session.add(self)
        self.generate_key()


    def __repr__(self):
        return '<APIKey {}>'.format(self.key)

    
    def generate_key(self):
        app.logger.info('New API key generated')
        self.key = hexlify(os.urandom(24)).decode()
        db.session.commit()


class APIKeySchema(Schema):
    key = fields.Str()


# Association Object for campaigns and pages
class Campaignpages(db.Model):
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), primary_key=True)
    index = db.Column(db.Integer)


class CampaignpagesSchema(Schema):
    index = fields.Number()
    page = fields.Nested(PageSchema, strict=True)


# Campaign Classes
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


    def __repr__(self):
        return '<Campaign {}>'.format(self.name)


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
            self.end_time = datetime.now()
            self.status = 'Complete'
            db.session.commit()
        return r.status_code


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


class ResultCampaignSchema(Schema):
    id = fields.Number()
    name = fields.Str()
    status = fields.Str()
    server = fields.Nested(ServerSchema, strict=True)
    domain = fields.Nested(DomainSchema, strict=True)
    start_time = fields.DateTime(format='%m-%d-%y %H:%M')
    end_time = fields.DateTime(format='%m-%d-%y %H:%M')
