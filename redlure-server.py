from app import app, db
from app.models import User, Profile, Role, Workspace, List, Person, Email, Domain, Campaign

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
        'Domain': Domain,
        'Campaign': Campaign
    }