#!/usr/bin/env python3
from app import app, db, functions
from app.functions import Color
import subprocess
import os
import shlex
import shutil
from config import Config
from datetime import datetime
from cryptography.fernet import InvalidToken
from app.cipher import CipherTest, Cipher, new_cipher_key, encrypt, decrypt
from app.workspace import Workspace
from app.role import Role
from app.user import User
from app.profile import Profile
from app.list import List, Person
from app.email import Email
from app.page import Page
from app.domain import Domain
from app.campaign import Campaign, Campaignpages, WorkerCampaignSchema
from app.result import Result, Form, Event
from app.server import Server
from app.apikey import APIKey
from app.redlure import CONSOLE_VERSION, MIN_SUPPORTED_CLIENT
import urllib3

# suppress insecure requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        'Campaignpages': Campaignpages,
        'Event': Event
    }


def init_cipher():

    if Config.PASSPHRASE != '':
        passphrase = Config.PASSPHRASE
        new_cipher_key(bytes(passphrase, 'utf-8'))
    else:
        passphrase = ''
        print(f'{Color.gray}[*] redlure encrypts sensitive database fields{Color.end}')
        print(f'{Color.gray}[*] Enter a passphrase that will be used in generating the key\n{Color.end}')
        while passphrase == '':
            passphrase =  input(f'{Color.gray}[+] Passphrase: {Color.red}').encode()
        print(f'\n[!] WARNING: Do not lose your passphrase - doing so will result in losing access to parts of your database{Color.end}')

        new_cipher_key(passphrase)

        input(f'\n{Color.gray}[+] Press enter to continue: {Color.end}')


def get_cipher():

    if Config.PASSPHRASE != '':
        passphrase = Config.PASSPHRASE.encode()
        new_cipher_key(passphrase)
        cipher_text = CipherTest.query.first().value
        str = cipher_text.decode()
        try:
            plain_text = decrypt(cipher_text)
            print(f'[+] {plain_text.decode()}\n{Color.end}')
        except InvalidToken:
            print(f'\n[!] Decryption failed - invalid passphrase{Color.end}')
            exit()

    else:
    
        cipher_text = CipherTest.query.first().value
        str = cipher_text.decode()
        print(f'\n{Color.gray}{str[:len(str)//2]}\n{str[len(str)//2:]}{Color.end}\n')
        passphrase = input(f'{Color.gray}[+] Enter the cipher passphrase: {Color.red}').encode()
        new_cipher_key(passphrase)
        try:
            plain_text = decrypt(cipher_text)
            print(f'[+] {plain_text.decode()}\n{Color.end}')
        except InvalidToken:
            print(f'\n[!] Decryption failed - invalid passphrase{Color.end}')
            exit()

def init_db():
    if os.path.isdir('migrations'):
        shutil.rmtree('migrations')

    print(f'\n{Color.red}[*] Creating database{Color.end}')

    proc = subprocess.Popen(shlex.split('flask db init'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.wait()
    proc = subprocess.Popen(shlex.split('flask db migrate'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.wait()
    proc = subprocess.Popen(shlex.split('flask db upgrade'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.wait()

    print(f'{Color.red}[+] Initializing database values\n{Color.end}')

    general_ws = Workspace(name='General')
    db.session.add(general_ws)
    db.session.commit()

    administrator = Role(name='redlure admin', role_type='Administrator')
    general_ws = Workspace.query.filter_by(id=1, name='General').first()
    if general_ws is not None:
        administrator.workspaces.append(general_ws)

    db.session.add(administrator)
    db.session.commit()

    admin = User(username='admin', role_id=1)
    admin.set_password('redlure')
    db.session.add(admin)
    db.session.commit()

    encrypted_val = encrypt(b'Bingo. Welcome to redlure')
    cipher_test = CipherTest(value=encrypted_val)
    db.session.add(cipher_test)
    db.session.commit()

    key = APIKey()

# check for scheduled campaigns that need to be rentered into the queue
def check_campaigns():
    campaigns = Campaign.query.filter_by(status='Scheduled').all()
    for campaign in campaigns:
        if datetime.now() < campaign.start_time:
            #schema = WorkerCampaignSchema()
            #campaign_data = schema.dump(campaign)
            campaign.cast()

        else:
            campaign.status = 'Start time missed (server outage)'
            db.session.commit()

def gen_certs():
    proc = subprocess.Popen(shlex.split('openssl req -x509 -newkey rsa:4096 -nodes -subj "/" -out redlure-cert.pem -keyout redlure-key.pem -days 365'))
    proc.wait()


def banner():
    print(f'''
{Color.red}                   .___{Color.gray}.__                        {Color.end}     
{Color.red}_______   ____   __| _/{Color.gray}|  |  __ _________   ____  {Color.end} 
{Color.red}\_  __ \_/ __ \ / __ | {Color.gray}|  | |  |  \_  __ \_/ __ \ {Color.end}
{Color.red} |  | \/\  ___// /_/ | {Color.gray}|  |_|  |  /|  | \/\  ___/ {Color.end}
{Color.red} |__|    \___  >____ | {Color.gray}|____/____/ |__|    \___  >{Color.end}
{Color.red}             \/     \/ {Color.gray}                        \/  {Color.end}
    
{Color.red}                      v{Color.gray}{CONSOLE_VERSION}          {Color.end}

''')
    print(f'[*] Your console requires redlure-client v{MIN_SUPPORTED_CLIENT} or newer')


if __name__ == '__main__':
    banner()
    # SECRET_KEY is required
    if Config.SECRET_KEY == '':
        print('[!] A secret key is required - set the SECRET_KEY attribute in config.py')
        print(f'[!] New suggested random secret key: {os.urandom(24)}')
        exit()

    # check if db exists yet
    if not os.path.isfile('redlure.db'):
            init_cipher()
            init_db()
    else:
        get_cipher()
        check_campaigns()

    # generate certs if they dont exist
    if Config.CERT_PATH == 'redlure-cert.pem' and Config.KEY_PATH == 'redlure-key.pem':
        if not os.path.isfile('redlure-cert.pem') or not os.path.isfile('redlure-key.pem'):
            gen_certs()

    # start the server
    app.logger.info('redlure-console starting up')
    #server = subprocess.Popen(['gunicorn', 'app:app', '-b 0.0.0.0:5000', '--certfile', Config.CERT_PATH, '--keyfile', Config.KEY_PATH])
    #server.wait()
    app.run(host='0.0.0.0', ssl_context=(Config.CERT_PATH, Config.KEY_PATH), use_reloader=False)
