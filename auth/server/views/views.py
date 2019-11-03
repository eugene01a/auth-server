# auth/auth/auth/views.py
from datetime import datetime

from flask import Blueprint
from flask import make_response, jsonify
from flask import request
from flask_login import login_required

from auth.server import bcrypt, db
from auth.server.email import send_password_reset_email
from auth.server.models.models import BlacklistToken, User, Role
from auth.server.models.registration import Registration
from auth.server.utils import create_json_response, check_auth_token, Errors

auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/auth/register', methods=["POST"])
def register():
    # get the post data
    post_data = request.get_json()
    # check if user already exists

    registration = Registration.query.filter_by(email=post_data.get('email')).first()
    if registration:
        if registration.approved_on:
            return create_json_response(400, 'fail', 'User already exists. Please Log in.')
        else:
            return create_json_response(400, 'fail', 'Already awaiting admin approval. Please be patient.')

    else:
        try:
            # create the registration
            registration = Registration(post_data.get('email'),
                                        post_data.get('first_name'),
                                        post_data.get('last_name'),
                                        post_data.get('reason'))

            db.session.add(registration)
            db.session.commit()
            return create_json_response(200, 'success', 'You will receive an email notification once approved.',
                                        registration_id=registration.id)

        except Exception as e:
            print(e)
            return create_json_response(500, 'fail', 'Unknown error submitting registration.', error=e.message)


@auth_blueprint.route('/auth/login', methods=["POST"])
def login():
    # get the post data
    post_data = request.get_json()
    try:
        print("\n" + post_data.get('email'))
        registration = Registration.query.filter(Registration.email == post_data.get('email')).first()
        if registration:
            user = User.query.filter_by(id=registration.id).first()
            if user:
                if bcrypt.check_password_hash(user.password, post_data.get('password')):
                    auth_token = user.encode_auth_token(user.id, user.role_id).decode('utf-8')
                    return create_json_response(200, 'success', 'Logged in', auth_token=auth_token)
        else:
            return create_json_response(400, 'fail', 'User does not exist.')

    except Exception as e:
        return create_json_response(500, 'fail', 'Unknown error logging in.', error=e.args[0])


@auth_blueprint.route('/auth/registrations', methods=["GET"])
def registrations():
    '''
    get pending registrations as administrator
    '''
    check_auth_token()
    print('/auth/registrations called!!!')
    try:
        print('registrations')
        registrations = Registration.query.filter_by(approved_on=None).order_by(Registration.requested_on.desc()).all()
        pending = []
        print('registrations: {}'.format(registrations))
        for registration in registrations:
            pending.append({
                'id': registration.id,
                'requested_on': registration.requested_on,
                'name': '{} {}'.format(registration.first_name, registration.last_name),
                'reason': registration.reason,
            })
        return make_response(jsonify({
            'registrations': pending,
            'status': 'success', })), 200
    except Exception as e:
        return create_json_response(500, 'fail', 'Unknown error getting registrations', error=e.message)


@auth_blueprint.route('/auth/approve', methods=["POST"])
def approve():
    '''
    post_data:
    registration_id: id of an existing entry in Registration table
    role_id: id of an existing entry in Role table

    '''
    user_response = current_user()
    print('Current user is: {}'.format(user_response.json['data']['email']))
    if user_response.json['data']['role'] != 'Admin':
        return create_json_response(Errors.not_admin.http_code, 'fail', Errors.not_admin.message)

    # get the post data
    post_data = request.get_json()
    registration_id = post_data.get('registration_id')
    role_id = post_data.get('role_id')

    # check if user already exists
    print('Searching for registration_id {}'.format(registration_id))
    registration = Registration.query.filter_by(id=registration_id).first()

    if registration:
        print("Found matching registration for {}".format(registration.email))
        user = User.query.filter_by(registration_id=registration_id).first()
        if user:
            create_json_response(401, 'fail', 'User already exists for {}.'.format(registration.email))
        elif registration.approved_on:
            create_json_response(401, 'fail', 'Registration already approved for {}'.format(registration.email))
        else:
            try:
                # approve the registration
                approve_date = datetime.now()
                registration.approved_on = approve_date
                db.session.commit()
                print("Approved on {}".format(approve_date))

                # send pw reset email
                send_password_reset_email(registration, role_id)

                responseObject = {
                    'status': 'success',
                    'registration_id': registration.id,
                    'role_id': role_id,
                    'email': registration.email,
                    'message': 'Password reset link sent to email. Awaiting user password creation'
                }
                return make_response(jsonify(responseObject)), 200
            except Exception as e:
                print("Error: {}".format(e))
                create_json_response(401, 'fail', 'Some error occurred. Please try again.')
    else:
        return create_json_response(401, 'fail', 'Some error occurred. Please try again.')


@auth_blueprint.route('/auth/reset_password_request', methods=["POST"])
def request_reset_password():
    '''
    sends password reset link to a user's email address
    '''
    post_data = request.get_json()
    registration = Registration.query.filter_by(email=post_data.get('email')).first()

    user_response = current_user()
    print('Current user is: {}'.format(user_response.json['data']['email']))

    #find role_id.
    # If currently logged in, and role is admin, assume request is for a new approved registration, so get the role_id in request param.
    # If not logged in or admin, assume request is for forgotten password, so get role_id by looking up user from email in request param
    if user_response.json['data']['role'] != 'Admin':
        user = User.query.filter_by(registration_id=registration.id).first()
        role_id = user.role_id
    else:
        role_id = post_data.get('role_id')

    if registration:
        try:
            pw_reset_token = send_password_reset_email(registration, role_id)
            return create_json_response(200, 'success', 'Check your email for the instructions to reset your password',
                                        token=pw_reset_token)
        except Exception as e:
            raise e
            return create_json_response(401, 'fail', 'Some error occurred. Please try again.')
    else:
        return create_json_response(401, 'fail', 'No registration found for provided email.')


@auth_blueprint.route('/auth/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    '''
    post data:
    password - new password
    token - encoded with valid role_id, and registration_id
    '''

    post_data = request.get_json()
    new_password = post_data['password']
    registration, role_id = Registration.verify_reset_password_token(token)

    if registration:
        try:
            user = User.query.filter_by(registration_id=registration.id).first()
            if user:
                user.password = new_password
            else:
                user = User(registration.id, new_password, role_id)
                db.session.add(user)
            db.session.commit()
            return create_json_response(200, 'success', 'Password successfully reset. You can now login.')

        except Exception as e:
            print("Error: {}".format(e))
            return create_json_response(401, 'fail', 'Some error occurred. Please try again.')
    else:
        return create_json_response(401, 'fail', 'Invalid reset_password token.')


@login_required
@auth_blueprint.route('/auth/logout', methods=["POST"])
def logout():
    # get auth token
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            # mark the token as blacklisted
            blacklist_token = BlacklistToken(token=auth_token)
            try:
                # insert the token
                db.session.add(blacklist_token)
                db.session.commit()
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged out.'
                }
                return make_response(jsonify(responseObject)), 200
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': e
                }
                return make_response(jsonify(responseObject)), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
    else:
        return create_json_response(401, 'fail', 'Provide a valid auth token.')


@auth_blueprint.route('/auth/profile', methods=["GET"])
def current_user():
    # get the auth token
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        user_id, role_id = User.decode_auth_token(auth_token)
        if not isinstance(user_id, str):
            user = User.query.filter_by(id=user_id).first()
            registration = Registration.query.filter_by(id=user.registration_id).first()
            role = Role.query.filter_by(id=role_id).first()
            responseObject = {
                'status': 'success',
                'data': {
                    'first_name': registration.first_name,
                    'last_name': registration.last_name,
                    'email': registration.email,
                    'role': role.name,
                    'registration_date': registration.approved_on,
                }
            }
            return make_response(jsonify(responseObject), 200)
        return create_json_response(401, 'fail', "Error decoding auth token: {}".format(auth_token))
    else:
        return create_json_response(401, 'fail', 'Provide a valid auth token.')
