# auth/auth/auth/views.py
from datetime import datetime

from flask import Blueprint
from flask import request
from flask_login import login_required

from auth.server import bcrypt, db, app
from auth.server.email import send_password_reset_email
from auth.server.models.blacklist_tokens import BlacklistToken
from auth.server.models.registrations import Registration
from auth.server.models.roles import Role
from auth.server.models.users import User
from utils.db import extract_registration, extract_user_info
from utils.utils import create_json_response, check_request_credentials

frontend_server = app.config['FRONTEND_SERVER_NAME']
auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/auth/register', methods=["POST"])
def register():
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
            return create_json_response(500, 'fail', 'Unknown error submitting registration.', error=e.message)


@auth_blueprint.route('/auth/login', methods=["POST"])
def login():
    # get the post data
    post_data = request.get_json()
    try:
        print("\n" + post_data.get('email'))
        registration = Registration.query.filter_by(email=post_data.get('email')).first()
        if registration:
            user = User.query.filter_by(registration_id=registration.id).first()
            if user:
                if bcrypt.check_password_hash(user.password, post_data.get('password')):
                    auth_token = user.encode_auth_token(user.id, user.role_id).decode('utf-8')
                    userInfo = extract_user_info(user)
                    return create_json_response(200, 'success', 'Logged in', auth_token=auth_token,
                                                role=userInfo['role'])
        else:
            return create_json_response(400, 'fail', 'User does not exist.')

    except Exception as e:
        raise e
        return create_json_response(500, 'fail', 'Unknown error logging in.', error=e.args[0])


@auth_blueprint.route('/auth/pending', methods=["GET"])
def pending():
    '''
    get pending registrations as administrator
    '''
    valid, msg = check_request_credentials(request, ['Admin'])
    if not valid:
        return create_json_response(400, 'fail', msg)
    try:
        registration_records = Registration.query.filter_by(approved_on=None).order_by(
            Registration.requested_on.desc()).all()
        pending = []
        record_count = 0
        for record in registration_records:
            record_count += 1
            registration = extract_registration(record)
            pending.append(registration)
        return create_json_response(200, 'success', "Retrieved {} pending records".format(record_count),
                                    pending_registrations=pending)
    except Exception as e:
        print("Error: {} {}".format(e, e.args))
        return create_json_response(500, 'fail', 'Unknown error getting registrations')


@auth_blueprint.route('/auth/roles', methods=["GET"])
def roles():
    '''
    get all roles as administrator
    '''
    valid, msg = check_request_credentials(request, ['Admin'])
    if not valid:
        return create_json_response(400, 'fail', msg)
    try:
        all_roles = []
        role_records = Role.query.order_by(Role.id).all()
        roles_count = 0
        for role_record in role_records:
            roles_count += 1
            all_roles.append({
                'role_id': role_record.id,
                'role_name': role_record.name})
        return create_json_response(200, 'success', "Retrieved {} possible roles".format(roles_count),
                                    roles=all_roles)
    except Exception as e:
        print("Error: {} {}".format(e, e.args))
        return create_json_response(500, 'fail', 'Unknown error getting registrations')


@auth_blueprint.route('/auth/pending/approve', methods=["POST"])
def approve():
    '''
    post_data:
    registration_id: id of an existing entry in Registration table
    role_id: id of an existing entry in Role table
    '''
    valid, msg = check_request_credentials(request, ['Admin'])
    if not valid:
        return create_json_response(400, 'fail', msg)

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

                return create_json_response(200, 'success',
                                            'Password reset link sent to email. Awaiting user password creation',
                                            role_id=role_id, email=registration.email)
            except Exception as e:
                print("Error: {}".format(e))
                create_json_response(401, 'fail', 'Some error occurred. Please try again.')
    else:
        return create_json_response(401, 'fail', 'No registration found for id {}'.format(registration_id))


@auth_blueprint.route('/auth/pending/deny', methods=["DELETE"])
def deny():
    '''
    post_data:
    registration_id: id of an existing entry in Registration table
    '''
    valid, msg = check_request_credentials(request, ['Admin'])
    if not valid:
        return create_json_response(400, 'fail', msg)

    # get the post data
    post_data = request.get_json()
    registration_id = post_data.get('registration_id')

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

                # delete the registration
                db.session.delete(registration)
                db.session.commit()
                return create_json_response(200, 'success', 'Pending registration successfully denied')

            except Exception as e:
                print("Error: {}".format(e))
                create_json_response(401, 'fail', 'Some error occurred. Please try again.')
    else:
        return create_json_response(401, 'fail', 'No registration found for id {}'.format(registration_id))


@auth_blueprint.route('/auth/password/reset/request', methods=["POST"])
def request_reset_password():
    '''
    sends password reset link to a user's email address
    '''
    post_data = request.get_json()
    registration = Registration.query.filter_by(email=post_data.get('email')).first()

    user_response = current_user()
    print(user_response)
    print('Current user is: {}'.format(user_response['email']))

    # find role_id.
    # If currently logged in, and role is admin, assume request is for a new approved registration, so get the role_id in request param.
    # If not logged in or admin, assume request is for forgotten password, so get role_id by looking up user from email in request param
    if user_response['role'] != 'Admin':
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


@auth_blueprint.route('/auth/password/reset/<token>', methods=['OPTIONS', 'GET', 'POST'])
def response_reset_password(token):
    if request.method == 'GET':
        return verify_password_token(token)
    elif request.method == 'POST':
        return reset_password(token)
    elif request.method == 'OPTIONS':
        print("print OPTIONS")
        return create_json_response(200, 'success', 'Options ok')


def verify_password_token(token):
    try:
        response = Registration.verify_reset_password_token(token)
        if response:
            return create_json_response(200, 'success', 'Token verified successfully')
        else:
            return create_json_response(409, 'fail', 'Invalid URL')
    except Exception as e:
        return create_json_response(401, 'fail', 'Some error occurred. Please try again.')


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
    print("logout: {}".format(request.headers.get('Authorization')))
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
                return create_json_response(200, 'success', 'Successfully logged out.')
            except Exception as e:
                return create_json_response(401, 'fail', e)
        else:
            return create_json_response(401, 'fail', resp)
    else:
        return create_json_response(401, 'fail', 'Provide a valid auth token.')


@auth_blueprint.route('/auth/profile', methods=["GET"])
def current_user():
    # get the auth token
    auth_header = request.headers.get('Authorization')
    print("auth_header={}".format(auth_header))
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        print("auth_token={}".format(auth_token))
        decode_response = User.decode_auth_token(auth_token)

        # if decode returns string, assume its error message
        if type(decode_response) == str:
            return create_json_response(401, 'fail', decode_response)

        user_id = decode_response['user_id']
        if not isinstance(user_id, str):
            user = User.query.filter_by(id=user_id).first()
            return extract_user_info(user)

        return create_json_response(401, 'fail', "Error decoding auth token: {}".format(auth_token))
    else:
        return create_json_response(401, 'fail', 'Provide a valid auth token.')
