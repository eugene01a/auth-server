# project/project/tests/base.py


import json

from flask_testing import TestCase

from auth.server import app, db
from auth.server.commands.init_db import find_or_create_user, find_or_create_registration, find_or_create_role

admin = {
    'role': 'Admin',
    'first_name': 'admin',
    'last_name': 'test',
    'email': 'admin.test@gmail.com',
    'reason': 'admin test',
    'password': 'adminPW',
}

non_admin = {
    'role': 'User',
    'first_name': 'user',
    'last_name': 'test',
    'email': 'user.test@gmail.com',
    'reason': 'user test',
    'password': 'userPW',
}


def create_registration(entity):
    return find_or_create_registration(entity['first_name'],
                                       entity['last_name'],
                                       entity['email'],
                                       entity['reason'])


def create_user(entity):
    role = find_or_create_role(entity['role'])
    registration = create_registration(entity)
    user = find_or_create_user(registration.id, entity['password'], role.id)
    return user, role, registration


def register(self, entity, headers=None):
    response = self.client.post(
        '/auth/register',
        data=json.dumps(dict(
            email=entity['email'],
            first_name=entity['first_name'],
            last_name=entity['last_name'],
            reason=entity['reason'],
        )),
        content_type='application/json',
        headers=headers, )
    data = json.loads(response.data.decode())
    return data, response.status_code


def login(self, entity, headers=None):
    response = self.client.post(
        '/auth/login',
        data=json.dumps(dict(
            email=entity['email'],
            password=entity['password']
        )),
        content_type='application/json',
        headers=headers,
    )
    data = json.loads(response.data.decode())
    return data, response.status_code


def pending_registrations(self, admin_token):
    response = self.client.get(
        '/auth/pending',
        content_type='application/json',
        headers={'Authorization': 'Bearer ' + admin_token},
    )

    data = json.loads(response.data.decode())
    return data, response.status_code


def all_roles(self, admin_token):
    response = self.client.get(
        '/auth/roles',
        content_type='application/json',
        headers={'Authorization': 'Bearer ' + admin_token},
    )

    data = json.loads(response.data.decode())
    return data, response.status_code


def approve(self, admin_token, registration_id, role_id):
    response = self.client.post(
        '/auth/pending/approve',
        data=json.dumps(dict(
            registration_id=registration_id,
            role_id=role_id
        )),
        content_type='application/json',
        headers={'Authorization': 'Bearer ' + admin_token},
    )

    data = json.loads(response.data.decode())
    return data, response.status_code


def request_reset_password(self, admin_token, email, role_id):
    response = self.client.post(
        '/auth/password/reset/request',
        data=json.dumps(dict(email=email, role_id=role_id)),
        content_type='application/json',
        headers={'Authorization': 'Bearer ' + admin_token},
    )
    print(response)
    data = json.loads(response.data.decode())
    return data, response.status_code


def reset_password(self, token, password):
    response = self.client.post(
        '/auth/password/reset/{}'.format(token),
        data=json.dumps(dict(
            password=password
        )),
        content_type='application/json')
    data = json.loads(response.data.decode())
    return data, response.status_code


def user_profile(self, auth_token):
    response = self.client.get('/auth/profile',
                               content_type='application/json',
                               headers={'Authorization': 'Bearer ' + auth_token})
    data = json.loads(response.data.decode())
    return data, response.status_code

def valid_reset_token(self, token):
    response = self.client.get('/auth/password/reset/{}'.format(token),
                               content_type='application/json')
    data = json.loads(response.data.decode())
    return data, response.status_code

class BaseTestCase(TestCase):
    """ Base Tests """

    def create_app(self):
        app.config.from_object('auth.server.config.DevelopmentConfig')
        return app

    def setUp(self):
        db.create_all()
        find_or_create_role('User')
        create_user(admin)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
