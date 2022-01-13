from auth.server.models.registrations import Registration
from auth.server.models.roles import Role

def extract_registration(record):
    return {
        'registration_id': record.id,
        'email': record.email,
        'requested_on': record.requested_on,
        'approved_on': record.approved_on,
        'first_name': record.first_name,
        'last_name': record.last_name,
        'reason': record.reason,
    }


def extract_role(record):
    return {'role_id': record.id,
            'role_name': record.name}

def extract_user_info(record):
    role = Role.query.filter_by(id=record.role_id).first()
    registration = Registration.query.filter_by(id=record.registration_id).first()
    return {
        'role': role.name,
        'email': registration.email,
        'first_name': registration.first_name,
        'last_name': registration.last_name,
        'registration_date': registration.approved_on,
    }


