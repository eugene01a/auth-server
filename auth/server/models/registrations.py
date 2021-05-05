from datetime import datetime
from time import time

import jwt

from auth.server import app, db


class Registration(db.Model):
    __tablename__ = 'registrations'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    requested_on = db.Column(db.DateTime, nullable=False)
    approved_on = db.Column(db.DateTime, nullable=True)
    reason = db.Column(db.String(255))

    def __init__(self, email, first_name, last_name, reason, requested_on=datetime.now(), approved_on=None):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.reason = reason
        self.requested_on = requested_on
        self.approved_on = approved_on

    def get_reset_password_token(self, role_id, expires_in=600):
        print('registration_id={}'.format(self.id))
        print('role_id={}'.format(role_id))
        reset_token = jwt.encode(
            {'registration_id': self.id,
             'exp': time() + expires_in,
             'role_id': role_id},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')
        print(reset_token)
        return reset_token

    def is_approved(self):
        if self.approved_on:
            return True
        return False

    @staticmethod
    def verify_reset_password_token(token):
        try:
            print(token)
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(decoded_token)
            registration_id = decoded_token['registration_id']
            registration = Registration.query.get(registration_id)
            role_id = decoded_token['role_id']
        except Exception as e:
            print(e)
            return
        return registration, role_id
