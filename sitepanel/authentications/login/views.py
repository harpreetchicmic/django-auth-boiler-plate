from django.contrib.auth import logout
from django.contrib.auth.models import Group, User
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

from commonConf.authentication import token_expire_handler
from commonConf.baseViewSet import aBaseViewset, nBaseViewset
from commonConf.common import api_response
from commonConf.const import *
from sitepanel.authentications.login.serializers import UserLoginSerializer
from sitepanel.models import UserProfile, UserSocial


def home(request):
    data = "<h1>Welcome to CancerLight</h1>"
    return HttpResponse(data)

class AuthLoginViewset(nBaseViewset):
    queryset = User.objects.all()
    serializer_class = UserLoginSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        try:
            social_type = request.data.get('social_type')
            username = get_random_string(15)
            first_name = request.data.get('first_name','')
            last_name = request.data.get('last_name','')
            loginid = request.data['login_id']
            password = request.data['password']
            
            if User.objects.filter(email=loginid).exists() or User.objects.filter(username=loginid).exists():
                user = User.objects.filter(Q(email=loginid) | Q(username=loginid)).first()
                #user checks like should not be admin , should be active and profile should exists 
                if not user.is_active:
                    return api_response(BLOCKED_BY_ADMIN , False , FAIL , status.HTTP_400_BAD_REQUEST)
                    
                if user.is_staff:
                    return api_response(USER_IS_ALREADY_ADMIN , False , FAIL , status.HTTP_400_BAD_REQUEST)
                
                if UserProfile.objects.get(ref_user=user).verified ==  False:
                    return api_response(USER_NOT_VERIFIED , False , FAIL , status.HTTP_400_BAD_REQUEST)
            else:
                return api_response(WRONG_CREDENTIALS , False , FAIL , status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                if social_type is not None:
                    social_id = request.data['social_id']
                    has_email=True
                    if social_type == 'instagram':
                        email=get_random_string(10)+"@yopmail.com"
                        instagram_username=request.data['username']
                        if not UserSocial.objects.filter(instagram_username=instagram_username).exists():
                            User.objects.create(first_name=first_name,
                                                    last_name=last_name,username=username)
                            user = User.objects.get(username=username)
                            usersocialobj = UserSocial.objects.create(ref_user=user, social_type='instagram',
                                                                        social_id=social_id,instagram_username=instagram_username)
                            UserProfile.objects.create(ref_user=user)
                            group = Group.objects.get(name='user')
                            group.user_set.add(user)
                                
                        else:
                            usersocial = UserSocial.objects.get(instagram_username=instagram_username)
                            user = User.objects.get(id=usersocial.ref_user.id)
                            if user.is_active == 0:
                                return api_response(BLOCKED_BY_ADMIN , False , FAIL , status.HTTP_400_BAD_REQUEST)
                        if user.email == '':
                            has_email = False
                    
                    else:
                        loginid = request.data['loginid']
                        if User.objects.filter(email=loginid).exists():
                            user=User.objects.get(email=loginid)
                            if UserSocial.objects.filter(ref_user=user).exists():
                                usersocial=UserSocial.objects.get(ref_user=user)
                                usersocial.social_id=social_id
                                usersocial.save()
                            else:
                                usersocialobj = UserSocial.objects.create(ref_user=user, social_type=social_type,
                                                                        social_id=social_id)
                            if not user.is_active:
                                 return api_response(BLOCKED_BY_ADMIN , False , FAIL , status.HTTP_400_BAD_REQUEST)
                            if user.is_staff:
                                   return api_response(USER_IS_ALREADY_ADMIN , False , FAIL , status.HTTP_400_BAD_REQUEST)
                        else:    
                            User.objects.create(email=loginid,first_name=first_name,
                                                    last_name=last_name,username=username)
                            user=User.objects.get(email=loginid)
                            usersocialobj = UserSocial.objects.create(ref_user=user, social_type=social_type,
                                                                        social_id=social_id)
                            UserProfile.objects.create(ref_user=user)
                            group = Group.objects.get(name='user')
                            group.user_set.add(user)
                    return Response(sociallogin(user,has_email),status=status.HTTP_201_CREATED)
                
                #furthur authenticate the user
                if user.check_password(password):
                    Token.objects.filter(user_id=user.id).delete()
                    token = Token.objects.create(user=user)
                    user.last_login = timezone.now()
                    user.save()
                    userprofile=UserProfile.objects.get(ref_user=user)
                    response_dict = {"token": token.key,
                                    "data": {
                                        'username':user.username,
                                        'user_id': user.id,
                                        'photo':userprofile.photo.url,
                                        'email':user.email,
                                        "first_name": user.first_name,
                                        "last_name": user.last_name
                                    }}
                    return api_response(LOGIN_SUCCESSFULL , True , SUCCESS , status.HTTP_200_OK ,response_dict)
                else:
                     return api_response(WRONG_CREDENTIALS , False , FAIL , status.HTTP_400_BAD_REQUEST)
        except Exception as error:
                      return api_response(str(error) , False , FAIL , status.HTTP_400_BAD_REQUEST)
                    
class AuthLogoutViewset(aBaseViewset):
    queryset = User.objects.filter()
    serializer_class = UserLoginSerializer
    http_method_names = ['post']    
    
    def create(self, request, *args, **kwargs):
        try:
            Token.objects.get(user = request.user).delete()   #for token based authentication
            logout(request)                                   #used for session based authentication 
            return api_response(LOGOUT_SUCCESSFULL , True , SUCCESS , status.HTTP_200_OK)
        except Exception as error:
                return api_response(str(error) , False , FAIL , status.HTTP_400_BAD_REQUEST)

class getEmailSocialLogin(aBaseViewset):
    queryset = User.objects.filter()
    serializer_class = UserLoginSerializer
    http_method_names = ['post'] 
    
    def create(self, request, *args, **kwargs):
        try:
            email=request.data['email']
            if User.objects.filter(email=email).exists():
                return Response({
                        "message": "email already exists",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
            user=request.user
            user.email=email
            user.save()
            return Response({
                "message":"email updated successfully",
                "status":True,
                "response":"success"
            },status=status.HTTP_200_OK)
        except Exception as error:
                return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)

def sociallogin(user,has_email):
    if Token.objects.filter(user_id=user.id).exists():
        Token.objects.get(user_id=user.id).delete()
            
    token, created = Token.objects.get_or_create(user=user)
    is_expired, token = token_expire_handler(token)
    user.last_login = timezone.now()
    user.save()
    userprofile=UserProfile.objects.get(ref_user=user)
    context={
            "message": "you've successfully logged in",
            "status": True,
            "response": "success",
            "token": token.key,
            "data": {
                'user_id': user.id,
                'email':user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_questioned" : userprofile.is_question,
                "choosen_no" : userprofile.choosen_no,
                "has_email":has_email,
            }
        }
    return context
                    
