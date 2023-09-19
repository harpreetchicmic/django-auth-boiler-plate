import re

from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.contrib.auth import authenticate

from commonConf.authentication import token_expire_handler
from commonConf.baseViewSet import aBaseViewset, nBaseViewset
from sitepanel.authentications.login.serializers import UserLoginSerializer
from sitepanel.models import UserProfile


def home(request):
    data = "<h1>Welcome to ChicMic Canteen</h1>"
    return HttpResponse(data)

class AuthLoginViewset(nBaseViewset):
    queryset = User.objects.all()
    serializer_class = UserLoginSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        try:
            email = request.data.get('email', '').strip()
            password = request.data.get('password', '')

            if not email or not re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', email):
                return Response({"message": "Please enter a valid email address.",
                                "status": False,
                                "response": "fail"}, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(email=email, password=password)

            if user is not None:
                if int(request.data.get('is_staff', 0)) == 1 and user.is_staff:
                    with transaction.atomic():
                        Token.objects.filter(user_id=user.id).delete()
                            
                        token, created = Token.objects.get_or_create(user=user)
                        is_expired, token = token_expire_handler(token)
                        user.last_login = timezone.now()
                        user.save()
                        userProfile = UserProfile.objects.filter(ref_user=user)
                        if not userProfile:
                            userProfile = UserProfile.objects.create(
                                ref_user=user,
                                verified=1,
                                user_type="Admin"
                            )

                        photo = userProfile.photo if hasattr(userProfile, 'photo') else None

                        return Response({
                            "message": "You have successfully logged in",
                            "status": True,
                            "response": "success",
                            "token": token.key,
                            "data": {
                                'user_id': user.id,
                                'email': user.email,
                                "first_name": user.first_name,
                                "last_name": user.last_name,
                                "photo": photo
                            }}, status=status.HTTP_201_CREATED)
                else:
                    return Response(
                        {"message": "You are not authorized",
                        "status": False,
                        "response": "fail"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(
                    {"message": "Invalid credentials",
                    "status": False,
                    "response": "fail"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return Response({
                "message": str(error),
                "status": False,
                "response": "fail"}, status=status.HTTP_400_BAD_REQUEST)

# AuthLogoutViewset is aBaseViewset we are using this Admin Logout 
# we need only token using this class admin token will be deleted 

                    
class AuthLogoutViewset(aBaseViewset):
    queryset = User.objects.filter()
    serializer_class = UserLoginSerializer
    http_method_names = ['post']    
    
    def create(self, request, *args, **kwargs):
        try:
            Token.objects.get(user_id=request.user.id).delete()
          
            return Response({
                "message":"Logged out successfully",
                "status":True,
                "response":"success"
            },status=status.HTTP_200_OK)
        except Exception as error:
                return Response({
                        "message": str(error),
                        "status": False,
                        "response": "fail"}, status=status.HTTP_400_BAD_REQUEST)



