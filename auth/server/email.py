from threading import Thread

from flask import current_app
from flask import render_template
from flask_mail import Message

from . import mail, app


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()


def send_password_reset_email(registration, role_id):
    '''
    sends email and returns token
    '''
    frontend_server = app.config['FRONTEND_SERVER_NAME']
    with current_app.test_request_context():
        token = registration.get_reset_password_token(role_id)
        print(token)
        print("Password reset_token created")
        send_email('Reset Your Password',
                   sender=app.config['ADMINS'][0],
                   recipients=[registration.email],
                   text_body=render_template('reset_password_email.txt',
                                             user=registration, token=token,
                                             url='{}/exams/user/reset-password/{}'.format(frontend_server, token)),
                   html_body=render_template('reset_password_email.html',
                                             user=registration, token=token,
                                             url='{}/exams/user/reset-password/{}'.format(frontend_server, token)))
        print("Password reset email sent")
        return token
