from collections import namedtuple
from datetime import datetime

from auth.server import bcrypt, db, app
from auth.server.email import send_password_reset_email
from auth.server.models.blacklist_tokens import BlacklistToken
from auth.server.models.registrations import Registration
from auth.server.models.roles import Role
from auth.server.models.users import User
from flask import Blueprint
from flask import abort, jsonify
from flask import render_template, flash, redirect, url_for, request, make_response
from flask_login import current_user, login_required
from flask_restplus import Api, Resource, reqparse, fields
from utils.db import extract_registration, extract_user_info, extract_role
from utils.utils import create_json_response, check_request_credentials
from auth.server.forms import ResetPasswordForm

auth_blueprint = Blueprint('auth', __name__)
api = Api(auth_blueprint, version=1.0, title='Authentication API', description='A simple user management API')

auth = api.namespace('auth', description='authentication operations')
admin = api.namespace('admin', description='administrator operations')
user = api.namespace('user', description='user operations')

parser = reqparse.RequestParser()


class RequestParameter:
    def __init__(self, name, **kwargs):
        self.name = name
        self.kwargs = kwargs


def req_parser(*args):
    '''
    arg is a list of RequestParameter instances
    :param args:
    :return:
    '''
    parser = reqparse.RequestParser()
    for arg in args:
        parser.add_argument(arg.name, **arg.kwargs)

    return parser


RESPONSE = {'status': fields.String, 'message': fields.String}

Response = namedtuple('Response', ['http_code', 'status', 'message'])


@app.errorhandler(503)
def service_unavailable(e):
    return jsonify(error=str(e)), 503


@auth.route('/register')
class Register(Resource):
    success_response = Response(200, 'success', 'You will receive an email notification once approved.')

    register_input_model = auth.model("Register Input",
                                      {'email': fields.String(required=True),
                                       'first_name': fields.String(required=True),
                                       'last_name': fields.String(required=True),
                                       'reason': fields.String(required=True),
                                       })
    register_response_model = auth.model("Register Response",
                                         {'message': fields.String(example=success_response.message),
                                          'status': fields.String(example=success_response.status),
                                          'registration_id': fields.Integer()})

    @auth.expect(register_input_model)
    @api.marshal_with(register_response_model)
    def post(self):
        post_data = request.get_json()
        # check if user already exists
        try:
            registration = Registration.query.filter_by(email=post_data.get('email')).first()
        except Exception as e:
            abort(503, description="DB not available")

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
                return create_json_response(*self.success_response, registration_id=registration.id)

            except Exception as e:
                app.logger.error(str(e))
                return create_json_response(500, 'fail', 'Error submitting registration')


@auth.route('/login')
class Login(Resource):
    login_input_model = auth.model('Login Input',
                                   {'email': fields.String(required=True),
                                    'password': fields.String(required=True)})

    @auth.expect(login_input_model)
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            print(post_data)
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
            app.logger.error(str(e))
            return create_json_response(500, 'fail', "{}".format(e))


@login_required
@auth.route('/logout')
class Logout(Resource):
    @auth.doc(parser=req_parser(
        RequestParameter('Authorization', location='headers')
    ))
    def post(self):
        '''
        Blacklists the user's current authentication token
        '''
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
                    app.logger.error(str(e))
                    return create_json_response(401, 'fail', e)
            else:
                return create_json_response(401, 'fail', resp)
        else:
            return create_json_response(401, 'fail', 'Provide a valid auth token.')


@admin.route('/pending')
class Pending(Resource):
    def get(self):
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
            app.logger.error(str(e))
            return create_json_response(500, 'fail', 'Error getting registrations')


@admin.route('/roles')
class Roles(Resource):
    def get(self):
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
                all_roles.append(extract_role(role_record))
            return create_json_response(200, 'success', "Retrieved {} possible roles".format(roles_count),
                                        roles=all_roles)
        except Exception as e:
            app.logger.error(str(e))
            return create_json_response(500, 'fail', 'Error getting registrations')


@admin.route('/pending/approve')
class ApproveRegistration(Resource):
    def post(self):
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


@admin.route('/pending/deny')
class DenyRegistration(Resource):
    def delete(self):
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
                    app.logger.error(str(e))
                    create_json_response(401, 'fail', 'Some error occurred. Please try again.')
        else:
            return create_json_response(401, 'fail', 'No registration found for id {}'.format(registration_id))


@user.route('/password/reset')
class RequestPasswordReset(Resource):
    @auth.doc(parser=req_parser(
        RequestParameter('email', type=str, help='Your email address', location='form')
    ))
    def post(self):
        '''
        Sends password reset link to a user's email address
        '''
        post_data = request.get_json()
        registration = Registration.query.filter_by(email=post_data.get('email')).first()

        if isinstance(registration, Registration):
            if registration.is_approved():
                try:
                    user = User.query.filter_by(registration_id=registration.id).first()
                    role_id = user.role_id

                    pw_reset_token = send_password_reset_email(registration, role_id)
                    return create_json_response(200, 'success',
                                                'Check your email for the instructions to reset your password',
                                                token=pw_reset_token)
                except Exception as e:
                    app.logger.error(str(e))
                    return create_json_response(401, 'fail', 'Some error occurred. Please try again.')
            else:
                return create_json_response(200, 'pending registration',
                                            'The registration associated with this email is currently awaiting approval.')
        else:
            return create_json_response(401, 'fail', 'No registration found for provided email.')


@user.route('/reset_password/reset/<token>')
class RespondPasswordReset(Resource):
    @staticmethod
    def verify_password_token(token):
        try:
            response = Registration.verify_reset_password_token(token)
            if response:
                return create_json_response(200, 'success', 'Token verified successfully')
            else:
                return create_json_response(409, 'fail', 'Invalid URL')
        except Exception as e:
            app.logger.error(str(e))
            return create_json_response(401, 'fail', 'Some error occurred. Please try again.')

    @staticmethod
    def reset_password(token):
        '''
        post data:
        password - new password
        token - encoded with valid role_id, and registration_id
        '''

        post_data = request.form
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
                app.logger.error(str(e))
                return create_json_response(401, 'fail', 'Some error occurred. Please try again.')
        else:
            return create_json_response(401, 'fail', 'Invalid reset_password token.')

    def get(self, token):
        '''
        Verifies
        '''
        form = ResetPasswordForm()
        if form.validate_on_submit():
            self.reset_password(token)
            flash('Your password has been reset.')
            return redirect(url_for('login'))
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('reset_pw.html', form=form),200,headers)

    def post(self, token):
        '''
        Reset's a user's sign in password
        '''
        return self.reset_password(token)

    def options(self):
        return create_json_response(200, 'success', 'Options ok')


@user.route('/profile')
class Profile(Resource):
    @auth.doc(parser=req_parser(
        RequestParameter('Authorization', location='headers')
    ))
    def get(self):
        '''
        Retrieves a user's registration information
        '''
        # get the auth token
        try:
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
                    user_info = extract_user_info(user)
                    return create_json_response(200, 'success', "Retrieved user info", user_info=user_info)
                return create_json_response(401, 'fail', "Error decoding auth token: {}".format(auth_token))
            else:
                return create_json_response(401, 'fail', 'Provide a valid auth token.')
        except Exception as e:
            app.logger.error(str(e))
            return create_json_response(500, 'fail', 'Error getting profile')
