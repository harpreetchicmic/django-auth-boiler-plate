import random
import threading
from base64 import urlsafe_b64encode

import requests
from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.db import IntegrityError, transaction
from django.forms import ValidationError
from django.utils.encoding import force_bytes
from django.utils.http import (url_has_allowed_host_and_scheme,
                               urlsafe_base64_decode)
from rest_framework import status, viewsets
from rest_framework.response import Response

from commonConf.baseViewSet import nBaseViewset
from commonConf.common import api_response
from commonConf.const import *
from commonConf.passwordValidator import password_check
from commonConf.send_email import send_forgot_password_mail
from sitepanel.authentications.forgotpassword.serializers import (
    ChangePasswordSerializer, ForgotPasswordSerializer)
from sitepanel.models import UserProfile


class ForgotPasswordMail(nBaseViewset):
    queryset = User.objects.filter()
    serializer_class = ForgotPasswordSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        
        try:
            email = request.data['email']
            user = User.objects.get(email=email)
            if UserProfile.objects.get(ref_user=user).verified ==  False:
                return api_response(USER_NOT_VERIFIED,False, FAIL,status.HTTP_400_BAD_REQUEST)
            
            uid=urlsafe_b64encode(force_bytes(user.pk))
            token=default_token_generator.make_token(user)
            
            context1 = {
                    "subject": "Forgot Password mail",
                    "username": user.username,
                    "url": request._current_scheme_host+'/api/app/auth/changepassword/'+uid.decode('utf-8') +'/'+token + "/",
                    "email": user.email,
                    "uid": urlsafe_b64encode(force_bytes(user.pk)),
                    "user": user,
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                    'code': request._current_scheme_host+'/verifyuser/'+str(user.id)
                }
            t = threading.Thread(target=send_forgot_password_mail, args=[
                email, context1])
            t.setDaemon(True)
            t.start()
            return api_response(MAIL_SENT_SUCCESSFULLY,True, SUCCESS,status.HTTP_200_OK)
        
        except KeyError:
            return api_response(EMAIL_REQUIRED,False, FAIL,status.HTTP_400_BAD_REQUEST)
        
        except User.DoesNotExist:
            return api_response(EMAIL_NOT_REGISTERED,False, FAIL,status.HTTP_400_BAD_REQUEST)
        
        except Exception as error:
            return api_response(str(error),False, FAIL,status.HTTP_400_BAD_REQUEST)
        

class ChangePassword(nBaseViewset):
    queryset = User.objects
    serializer_class = ChangePasswordSerializer
    http_method_names = ['get']
    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User._default_manager.get(pk=uid)    
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            user = None
        return user
    def list(self, request, *args, **kwargs):
        try:
            uid = self.kwargs['uid']
            token=self.kwargs['token']
            compact = {
                "uid":uid,
                "token":token
            }
            return Response({
                            'data': compact,
                            "message":"", 
                            "status": True,
                            "response": "success", }, status=status.HTTP_200_OK)
          
        except Exception as error:
            return api_response(str(error),False, FAIL,status.HTTP_400_BAD_REQUEST)


class ConfirmPassword(nBaseViewset):
    queryset = User.objects.filter()
    serializer_class = ChangePasswordSerializer
    http_method_names = ['post']
    def get_user(self, uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            user = None
        return user
    def create(self, request, *args, **kwargs):
        try:
            password=request.data['password']
            password_validate= password_check(password)
            if not password_validate['status']: 
                return Response(
                    {"message":password_validate['message'],
                        "status": password_validate['status'],
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
            uid = request.data['uid']
            token=request.data['token']
            user = self.get_user(uid)
            if user == None:
                return api_response(USER_DOES_NOT_EXISTS,False, FAIL,status.HTTP_400_BAD_REQUEST)
            
            if(default_token_generator.check_token(user,token)):
                user.set_password(password)
                user.save()
                return api_response(PASWRD_CHANGE_SUCCESS,True, SUCCESS,status.HTTP_201_CREATED)
            else:
                return Response( {"message": "Link broken",
                                    "status": False,
                                    "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return api_response(str(error),False, FAIL,status.HTTP_400_BAD_REQUEST)