from auth.server.models.roles import Role
from auth.tests.base import BaseTestCase, register, login, approve, admin, non_admin, reset_password, \
    request_reset_password, pending_registrations, user_profile, all_roles


class TestFailedRegistration(BaseTestCase):

    def test_registration(self):
        with self.client:
            #Login with unregistered user (fails)
            login_response, status_code = login(self, non_admin)
            print(login_response)
            self.assertEquals(status_code, 400)

            #register the user
            registration_response, status_code = register(self, non_admin)
            self.assertEquals(status_code, 200)
            registration_id = registration_response['registration_id']

            #login as admin
            login_response, status_code = login(self, admin)
            print(login_response)
            self.assertEquals(status_code, 200)
            admin_token = login_response['auth_token']

            #get pending registrations
            pending_response, status_code = pending_registrations(self, admin_token)
            print(pending_response)
            self.assertEquals(status_code, 200)
            non_admin_reg=None
            for reg in pending_response['pending_registrations']:
                if reg['registration_id']==registration_id:
                    non_admin_reg=reg
            self.assertIsNotNone(non_admin_reg)

            #deny the user registration
            non_admin_role = Role.query.filter_by(name=non_admin['role']).first()
            approve_response, status_code = approve(self, admin_token, registration_id, non_admin_role.id)
            print(approve_response)
            self.assertEquals(status_code, 200)
            role_id = approve_response['role_id']

            #send email containing password reset token
            req_pw_reset_response, status_code = request_reset_password(self, admin_token, non_admin['email'], role_id)
            print(req_pw_reset_response)
            self.assertEquals(status_code, 200)
            reset_token = req_pw_reset_response['token']

            #reset the password for new user
            reset_pw_response, status_code = reset_password(self, reset_token, "userPW")
            print(reset_pw_response)
            self.assertEquals(status_code, 200)

            #login as new user
            login_response, status_code = login(self, non_admin)
            print(login_response)
            self.assertEquals(status_code, 200)
            user_token = login_response['auth_token']

            #get user profile info
            profile_response = user_profile(self, user_token)
            print(profile_response)
            self.assertEquals(status_code, 200)

            # get pending registrations
            pending_response, status_code = pending_registrations(self, admin_token)
            print(pending_response)
            self.assertEquals(status_code, 200)
            non_admin_reg = None
            for reg in pending_response['pending_registrations']:
                if reg['registration_id'] == registration_id:
                    non_admin_reg = reg
            self.assertIsNone(non_admin_reg)
