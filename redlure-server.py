#!/usr/bin/env python3
from app import app, db
from app.models import User, Profile, Role, Workspace, List, Person, Email, Page, Domain, Campaign, Result, Server, APIKey, Form, Campaignpages, WorkerCampaignSchema
import subprocess
import os
import shlex
import shutil
from config import Config
from datetime import datetime

# objects to initialize 'flask shell' with
@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Profile': Profile,
        'Role': Role,
        'Workspace': Workspace,
        'List': List,
        'Person': Person,
        'Email': Email,
        'Page': Page,
        'Domain': Domain,
        'Campaign': Campaign,
        'Result': Result,
        'Server': Server,
        'APIKey': APIKey,
        'Form': Form,
        'Campaignpages': Campaignpages
    }


def init_db():
    if os.path.isdir('migrations'):
        shutil.rmtree('migrations')

    print('\n[*] Creating database\n')

    proc = subprocess.Popen(shlex.split('flask db init'))
    proc.wait()
    proc = subprocess.Popen(shlex.split('flask db migrate'))
    proc.wait()
    proc = subprocess.Popen(shlex.split('flask db upgrade'))
    proc.wait()

    print('\n[*] Initializing database values\n')

    general_ws = Workspace(name='General')
    db.session.add(general_ws)
    db.session.commit()

    administrator = Role(name='Defualt Administrator', role_type='Administrator')
    user = Role(name='Defualt User', role_type='User')
    client = Role(name='Defualt Client', role_type='Client')
    general_ws = Workspace.query.filter_by(id=1, name='General').first()
    if general_ws is not None:
        administrator.workspaces.append(general_ws)
        user.workspaces.append(general_ws)

    db.session.add(administrator)
    db.session.add(user)
    db.session.add(client)
    db.session.commit()

    admin = User(username='admin', role_id=1)
    admin.set_password('redlure')
    db.session.add(admin)
    db.session.commit()

    key = APIKey()

# check for scheduled campaigns that need to be rentered into the queue
def check_campaigns():
    campaigns = Campaign.query.filter_by(status='Scheduled').all()
    for campaign in campaigns:
        if datetime.now() < campaign.start_time:
            schema = WorkerCampaignSchema()
            campaign_data = schema.dump(campaign)
            campaign.cast(campaign_data)

        else:
            campaign.status = 'Start time missed (server outage)'
            db.session.commit()

def gen_certs():
    proc = subprocess.Popen(shlex.split('openssl req -x509 -newkey rsa:4096 -nodes -subj "/" -out redlure-cert.pem -keyout redlure-key.pem -days 365'))
    proc.wait()


if __name__ == '__main__':
    # SECRET_KEY is required
    if Config.SECRET_KEY == '':
        print('\n[!] A secret key is required - set the SECRET_KEY attribute in config.py')
        print(f'[!] New random secret key: {os.urandom(24)}')
        exit()

    # check if db exists yet
    if not os.path.isfile('redlure.db'):
        init_db()
    else:
        check_campaigns()

    # generate certs if they dont exist
    if Config.CERT_PATH == 'redlure-cert.pem' and Config.KEY_PATH == 'redlure-key.pem':
        if not os.path.isfile('redlure-cert.pem') or not os.path.isfile('redlure-key.pem'):
            gen_certs()

    # start the server
    #subprocess.Popen(['gunicorn', 'redlure-server:app', '-b 0.0.0.0:5000', '--certfile', 'redlure-cert.pem', '--keyfile', 'redlure-key.pem'])
    app.run(host='0.0.0.0', ssl_context=(Config.CERT_PATH, Config.KEY_PATH))
