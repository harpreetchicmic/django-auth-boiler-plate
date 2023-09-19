from base64 import urlsafe_b64encode
import threading
from django.forms import ValidationError
from django.shortcuts import render
from rest_framework import  status
from rest_framework.response import Response
from django.db import transaction
from django.contrib.auth.models import Group,User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import  urlsafe_base64_decode
from commonConf.baseViewSet import nBaseViewset, vBaseViewset , aBaseViewset
from commonConf.passwordValidator import password_check
from commonConf.send_email import send_welcome_mail, send_welcome_mail_with_otp
from sitepanel.authentications.signup.serializers import UserSerializers
from sitepanel.models import UserProfile
from commonConf.const import *
from commonConf.common import api_response , regex
import re
import random
from commonConf.common import regex

class AuthSignupViewset(nBaseViewset):
    queryset = User.objects
    serializer_class = UserSerializers
    profileQuerySet = UserProfile.objects
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        data = request.data
        try:
            email = str(data['email']).strip()
            with transaction.atomic():
                if User.objects.filter(email=email).exists():
                    user=self.queryset.get(email=email)
                    if self.profileQuerySet.get(ref_user=user).verified == False:
                        user.delete()
                    else:
                        return api_response(EMAIL_ALREADY_USED , False , FAIL , status.HTTP_400_BAD_REQUEST)
                    email_regex = regex
                    if str(email) == "" or not (re.fullmatch(email_regex, email)):
                        return api_response(ENTER_VALID_EMAIL , False , FAIL , status.HTTP_400_BAD_REQUEST)
             
                password_validate= password_check(data["password"])
                if not password_validate['status']: 
                    return Response(
                        {"message":password_validate['message'],
                            "status": password_validate['status'],
                            "response": FAIL, }, status=status.HTTP_400_BAD_REQUEST)
                try:
                    if self.queryset.filter(username=data["username"]).exists():
                        return api_response(USERNAME_ALREADY_USED , False , FAIL , status.HTTP_400_BAD_REQUEST)
                except:
                    pass

                userData =self.queryset.create(
                    username   =   data["username"],
                    email      = email,
                    first_name =  data["first_name"],
                    last_name  =  data["last_name"],
                    is_active  = True,
                )
                userData.set_password(data["password"])
                userData.save()
                
                #entry in user profile table 
                user_profile_obj = UserProfile.objects.create(ref_user=userData,verified=0)
                """
                below is the code which contains URL and function which sends the mail containing uid and token in url , 
                User is verified on the behalf of corresponding token and uid
                """
                # url = request._current_scheme_host+'/api/app/auth/verifyuser/'+urlsafe_b64encode(force_bytes(userdata.pk)).decode('utf-8') +'/'+default_token_generator.make_token(userData) + "/"     
                #send_mail_with_url_containing_uid_and_token(userData , url)     
                """
                below function sends otp in mail 
                front end will try to hit verifyUserWithOtp end point API  which verifies the user on the behalf of the otp 
                """     
                send_mail_with_otp(userData , user_profile_obj)

                group = Group.objects.get(name='user')
                group.user_set.add(userData)
                return api_response(REGT_SUCCESS_MAIL_SENT , True , SUCCESS , status.HTTP_200_OK , {"email":email})
        except Exception as error:
            return api_response(str(error), False , FAIL , status.HTTP_400_BAD_REQUEST)
             

class UserVerification(vBaseViewset):
    queryset = User.objects.all()
    serializer_class = UserSerializers
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
            try:
                user = self.get_user(uid)
                if user == None:
                    return render(request,'expired-link.html')
                userprofile=UserProfile.objects.get(ref_user=user)
                if userprofile.verified == True:
                    return render(request,'expired-link.html')
                if(default_token_generator.check_token(user,token)):
                    userprofile.verified = True
                    userprofile.save()
                    return render(request,'verified-link.html')
                else:
                    return render(request,'expired-link.html')
            except Exception as error:
                return Response({"message":str(error), "status": False,
                                "response": "fail", }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as error:
            return api_response(str(error), False , FAIL , status.HTTP_400_BAD_REQUEST)


def send_mail_with_url_containing_uid_and_token(userdata , url):
    """
    below is the function to send the mail with uid and token in url
    """
    context1 = {
                    "subject": "welcome mail",
                    "username": userdata.username,
                    "email": userdata.email,
                    "uid": urlsafe_b64encode(force_bytes(userdata.pk)),
                    "user": userdata,
                    'token': default_token_generator.make_token(userdata),
                    'protocol': 'http',
                    "url": url
                }
    t = threading.Thread(target=send_welcome_mail, args=[userdata.email, context1])
    t.setDaemon(True)
    t.start()       

def send_mail_with_otp(userdata,user_profile):
    """
    below is the function to send the otp in mail
    """
    otp = random.randint(1000, 9999)
    user_profile.otp = otp
    user_profile.save()
    context1 = {
                    "subject": "welcome mail",
                    "username": userdata.username,
                    "email": userdata.email,
                    "user": userdata,
                    'protocol': 'http',
                    'otp':otp,
                }
    t = threading.Thread(target=send_welcome_mail_with_otp, args=[userdata.email, context1])
    t.setDaemon(True)
    t.start()

class UserVerifictionWithOTP(aBaseViewset):
    queryset = UserProfile.objects
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        try:
            otp_filled      = int(request.data['otp'])
            email         = request.data['email']
            user= User.objects.get(email = email)
            user_profile = self.queryset.get(ref_user_id = user.id)
            user_actual_otp = user_profile.otp
            with transaction.atomic():
                if otp_filled == user_actual_otp:
                    user_profile.verified = True
                    user_profile.save()
                    return api_response(USER_VERIFIED, True , SUCCESS , status.HTTP_200_OK)
                else:
                    return api_response(ENTER_VALID_OTP, False , FAIL , status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return api_response(ENTER_VALID_EMAIL, False , FAIL , status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            return api_response(ENTER_VALID_USER_ID, False , FAIL , status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return api_response(str(error), False , FAIL , status.HTTP_400_BAD_REQUEST)