from base64 import urlsafe_b64encode
import random
import threading
import requests
from django.forms import ValidationError
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.db import transaction, IntegrityError
from django.contrib.auth.models import User, Group
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator  
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode,
)
from commonConf.baseViewSet import nBaseViewset
from commonConf.passwordValidator import password_check
from commonConf.send_email import send_forgot_password_mail
from sitepanel.authentications.forgotpassword.serializers import ChangePasswordSerializer, ForgotPasswordSerializer
from sitepanel.models import UserProfile


class ForgotPasswordMail(nBaseViewset):
    queryset = User.objects.filter()
    serializer_class = ForgotPasswordSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        
        try:
            email = request.data['email']
            try:
                with transaction.atomic():
                    if User.objects.filter(email=email).exists():
                        user=User.objects.get(email=email)
                        if UserProfile.objects.get(ref_user=user).verified ==  False:
                            return Response(
                                {"message": "This email is not verified only verified user can use this process",
                                        "status": False,
                                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response(
                            {"message": "This email is not registered",
                                "status": False,
                                "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
                    userprofile=UserProfile.objects.get(ref_user=user)
                    # user.otp = random.randint(1000, 9999)
                    userprofile.otp=1234
                    userprofile.save()
                    uid=urlsafe_b64encode(force_bytes(user.pk))
                    token=default_token_generator.make_token(user)
                    context1 = {
                            "subject": "Forgot Password mail",
                            "username": user.username,
                            "code": userprofile.otp,
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
                    return Response( {"message": "Mail has been successfully sent",
                                "status": True,
                                "response": "success", }, status=status.HTTP_201_CREATED)
            except Exception as error:
                    return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
                    return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)

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
            compect = {
                "uid":uid,
                "token":token
            }
            return Response({
                            'data': compect,
                            "message":"", 
                            "status": True,
                            "response": "success", }, status=status.HTTP_200_OK)
          
        except Exception as error:
                    return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)

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
                return Response({
                                "message":"User Doesn't exists", 
                                "status": False,
                                "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
            if(default_token_generator.check_token(user,token)):
                user.set_password(password)
                user.save()

                return Response( {"message": "Password changed successfully",
                                    "status": True,
                                    "response": "success", }, status=status.HTTP_201_CREATED)
            else:
                return Response( {"message": "Link broken",
                                    "status": False,
                                    "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
                    return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)