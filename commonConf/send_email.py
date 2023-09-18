import requests
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _
from django.template.loader import render_to_string
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

def send_forgot_password_mail(to, context):
    template = 'email/forgot_password.html'
    html_content = render_to_string(template, context)

    msg = EmailMultiAlternatives(context['subject'], "", settings.DEFAULT_FROM_EMAIL, [to])
    msg.attach_alternative(html_content, 'text/html')
    msg.send()
    

def send_welcome_mail(to, context):
    template = 'email/welcome_mail.html'
    html_content = render_to_string(template, context)

    msg = EmailMultiAlternatives(context['subject'], "", settings.DEFAULT_FROM_EMAIL, [to])
    msg.attach_alternative(html_content, 'text/html')
    msg.send()



