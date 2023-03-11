from rest_framework.exceptions import ValidationError
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
import phonenumbers
import threading
from decouple import config
from twilio.rest import Client


def phone_checker(p_number):
    if not (p_number and isinstance(p_number, str) and p_number.isdigit()):
        raise ValidationError('Phone Number is not valid!')


def phone_parser(p_number, c_code=None):
    try:
        phone_checker(p_number)
        p_number = '+' + p_number
        return phonenumbers.parse(p_number, c_code)
    except Exception as e:
        raise ValidationError('Phone Number is not valid!')


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self) -> None:
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content-type') == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {'code': code}
    )
    Email.send_email({
        'subject': 'Registration',
        'to_email': email,
        'body': html_content,
        'content_type': 'html'
    })


def send_phone(phone, code):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=f'Hello everyone! Your verification code is {code}\n',
        from_='+18088926285',
        to=f'{phone}'
    )
