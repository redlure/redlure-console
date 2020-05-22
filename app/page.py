from app import app, db
from marshmallow import Schema, fields
from datetime import datetime
from bs4 import BeautifulSoup
from flask import request, jsonify
from flask_login import login_required, current_user
import json
import re
import requests
from app.workspace import Workspace, validate_workspace, update_workspace_ts
from app.functions import user_login_required


####################
#  Page Classes
#####################
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    html = db.Column(db.LargeBinary, nullable=False)
    url = db.Column(db.String(64), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    campaigns = db.relationship('Campaignpages', backref='page', cascade='all, delete-orphan')


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


####################
#  Page Routes
#####################
@app.route('/clone', methods=['POST'])
@login_required
@user_login_required
def clone():
    '''
    For POST requests, return the source HTML of a given URL
    '''
    link = request.form.get('Link')
    app.logger.info(f'Cloned {link} - Cloned by {current_user.username} - Client IP address {request.remote_addr}')
    return clone_link(link)

    
@app.route('/workspaces/<workspace_id>/pages', methods=['GET', 'POST'])
@login_required
@user_login_required
def pages(workspace_id):
    '''
    For GET requests, return all pages for the given workspace.
    For POST requests, add a new pages to the given workspace.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    # request is a GET
    if request.method == 'GET':
        all_pages = Page.query.filter_by(workspace_id=workspace_id).order_by(Page.updated_at.desc()).all()
        schema = PageSchema(many=True)
        page_data = schema.dump(all_pages)
        return jsonify(page_data)

    # request is a POST
    elif request.method == 'POST':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        url = request.form.get('URL')

        page = Page.query.filter_by(name=name).first()

        if page is not None:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        page = Page(name=name, html=html, workspace_id=workspace_id, url=url)
        db.session.add(page)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        
        schema = PageSchema()
        page_data = schema.dump(page)
        app.logger.info(f'Added page {name} - Added by {current_user.username} - Client IP address {request.remote_addr}')
        return jsonify(page_data), 201


@app.route('/workspaces/<workspace_id>/pages/<page_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@user_login_required
def page(workspace_id, page_id):
    '''
    For GET requests, return the given page.
    For DELETE requests, delete the given page.
    For PUT requests, update the given page.
    '''
    if not validate_workspace(workspace_id):
        return 'workspace does not exist', 404

    page = Page.query.filter_by(id=page_id, workspace_id=workspace_id).first()
    if page is None:
        return 'page does not exist', 404

    #request is a GET
    if request.method == 'GET':
        page.find_form_fields()
        schema = PageSchema()
        page_data = schema.dump(page)
        return jsonify(page_data)

    # request is a DELETE
    elif request.method == 'DELETE':
        app.logger.info(f'Deleted page {page.name} - Deleted by {current_user.username} - Client IP address {request.remote_addr}')
        db.session.delete(page)
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        return 'deleted', 204
    
    # request is a PUT
    elif request.method == 'PUT':
        name = request.form.get('Name')
        html = request.form.get('HTML').encode()
        url = request.form.get('URL')

        same_page = Page.query.filter_by(name=name).first()

        if same_page is not None and str(same_page.id) != page_id:
            return json.dumps({'success': False}), 200, {'ContentType':'application/json'}

        page.name = name
        page.html = html
        page.url = url
        update_workspace_ts(Workspace.query.filter_by(id=workspace_id).first())
        db.session.commit()
        app.logger.info(f'Updated page {page.name} - Updated by {current_user.username} - Client IP address {request.remote_addr}')
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}


##########################
#  Class Specific Helpers
##########################
def clone_link(link):
    '''
    Take a URL and return the source HTML, adding in a base url for resources
    '''
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if re.match(regex, link) is None:
        return json.dumps({'success': False, 'message': 'Enter a valid URL'}), 200, {'ContentType':'application/json'}

    try:
        r = requests.get(link, verify=False)

        if r.status_code == 200:
            # add base tag to html to load external resources
            soup = BeautifulSoup(r.content, features='lxml')
            base = soup.new_tag('base', href=link)
            soup.find('head').insert_before(base)

            # if page has a form, set action to next_url placeholder
            try:
                soup.find('form')['action'] = '{{ next_url }}'
            except:
                pass
            return json.dumps({'success': True, 'html': str(soup)}), 200, {'ContentType':'application/json'}
        else:
            return json.dumps({'success': False, 'message': 'Error collecting site source'}), 200, {'ContentType':'application/json'}

    except Exception as e:
        return json.dumps({'success': False, 'message': 'Error collecting site source'}), 200, {'ContentType':'application/json'}
