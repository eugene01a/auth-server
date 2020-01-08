from flask import make_response, jsonify, request

from auth.server.models.roles import Role
from auth.server.models.users import User
from auth.server.models.registrations import Registration



def create_json_response(http_code, status, message, **data):
    data.update({'message': message,
                 'status': status})
    return make_response(jsonify(data), http_code)

def decode_request_token(request):
    auth_header = request.headers.get('Authorization')
    auth_token = auth_header.split(" ")[1]
    return User.decode_auth_token(auth_token)

def check_request_credentials(request, valid_roles):
    decoded_token = decode_request_token(request)
    user_id = decoded_token['user_id']
    role_id = decoded_token['role_id']
    user = User.query.filter_by(id=user_id).first()
    registration = Registration.query.filter_by(id=user.registration_id).first()
    role = Role.query.filter_by(id=role_id).first()
    if user and registration:
        if role.name in valid_roles:
            return True, 'Valid'
        else:
            return False, "Invalid permissions"
    else:
        return False, "Invalid user or registration"


class ErrorResp:
    def __init__(self,  http_code, message, status='fail'):
        self.http_code = http_code
        self.status = status
        self.message = message


class Errors:
    not_admin = ErrorResp(403, 'Action requires administrator role.')
