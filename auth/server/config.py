import os

basedir = os.path.abspath(os.path.dirname(__file__))
db_user = 'postgres'
db_password = 'ONLIN3-ex4m'
db_url='localhost:5432'
postgres_local_base = f'postgresql://{db_user}:{db_password}@{db_url}/'
database_name = 'flask_jwt_auth'

class BaseConfig:
    """Base configuration."""
    SECRET_KEY = '553d2cc858278fc13fada7c58eec1b48fa10ee6153333a6d6b2478c4f332cc56'
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = "localhost"
    MAIL_PORT = 8025
    USER_EMAIL_SENDER_EMAIL = 'ichinose.household@gmail.com'
    ADMINS = ['ichinose.household@gmail.com']
    FRONTEND_SERVER_NAME = 'http://localhost:4200'


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name + '_dev'


class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False

class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY')
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name
    MAIL_SERVER = "smtp.googlemail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = 1
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
