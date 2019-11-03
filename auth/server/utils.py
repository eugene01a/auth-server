from flask import make_response, jsonify, request

from auth.server.models.models import User


def create_json_response(http_code, status, message, **data):
    data.update({'message': message,
                 'status': status})
    return make_response(jsonify(data), http_code)


def check_auth_token(user_id, admin=False):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
            if auth_token:
                resp = User.decode_auth_token(auth_token)
                if isinstance(resp, dict):
                    if resp['sub'] == user_id:
                        if admin:
                            if not resp['admin']:
                                return True, 'Valid admin'
                            else:
                                return False, 'Not an admin'
                        else:
                            return True, 'Valid user'
                    else:
                        return False, 'Invalid user'
                else:
                    return False, 'Invalid token'
    except Exception as e:
        raise e


class ErrorResp:
    def __init__(self,  http_code, message, status='fail'):
        self.http_code = http_code
        self.status = status
        self.message = message


class Errors:
    not_admin = ErrorResp(403, 'Action requires administrator role.')
