import datetime

from flask_script import Command
from auth.server import db
from auth.server.models.roles import Role
from auth.server.models.users import User
from auth.server.models.registrations import Registration


class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('Database has been initialized.')


def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_users()


def create_users():
    """ Create users """

    # Create all tables
    db.create_all()

    # Adding role
    admin_role = find_or_create_role('Admin')
    user_role = find_or_create_role('User')

    # Add registration
    admin_registration = find_or_create_registration('Eugene', 'Ichinose', 'ichinose.household@gmail.com', 'initial admin')
    admin_test_registration = find_or_create_registration('admin', 'test', 'admin.test@gmail.com', 'admin test')
    user_test_registration = find_or_create_registration('user', 'test', 'user.test@gmail.com', 'user test')
    # Add user
    admin_user = find_or_create_user(admin_registration.id, 'adminPW', admin_role.id)
    admin_test_user = find_or_create_user(admin_test_registration.id, 'adminPW', admin_role.id)
    # Save to DB
    db.session.commit()


def find_or_create_role(name):
    """ Find existing role or create new role """
    role = Role.query.filter_by(name = name).first()
    if not role:
        role = Role(name=name)
        db.session.add(role)
        db.session.flush()
    return role


def find_or_create_registration(first_name, last_name, email, reason):
    """ Find existing user or create new registration """
    registration = Registration.query.filter(Registration.email == email).first()
    if not registration:
        registration = Registration(email=email,
                                    first_name=first_name,
                                    last_name=last_name,
                                    reason=reason)
        db.session.add(registration)
        db.session.flush()
    return registration


def find_or_create_user(registration_id, password, role_id):
    """ Find existing user or create new user """

    user = User.query.filter(User.registration_id == registration_id).first()
    if not user:
        registration = Registration.query.filter(Registration.id==registration_id).first()
        registration.approved_on=datetime.datetime.now()
        db.session.commit()
        user = User(registration_id=registration_id, password=password, role_id=role_id)
        db.session.add(user)
    return user
