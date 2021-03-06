from datetime import datetime, timedelta

import jwt
from flask_login import UserMixin
from flask_user import UserManager

from auth.server import db, bcrypt, app
from auth.server.models.blacklist_tokens import BlacklistToken


class User(db.Model, UserMixin):
    """ User Model for storing user related details """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    registration_id = db.Column(db.Integer, db.ForeignKey("registrations.id"))
    password = db.Column(db.String(255), nullable=False)
    last_active_on = db.Column(db.DateTime, nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))

    def __init__(self, registration_id, password, role_id):
        self.registration_id = registration_id
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.role_id = role_id

    def encode_auth_token(self, user_id, role_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'user_id': user_id,
                'role_id': role_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e


    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


user_manager = UserManager(app, db, User)
