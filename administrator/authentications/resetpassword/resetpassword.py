
from rest_framework import status
from rest_framework.response import Response
from django.db import transaction
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from commonConf.baseViewSet import aBaseViewset
from commonConf.passwordValidator import password_check
from sitepanel.authentications.resetpassword.serializers import PasswordResetSerializer
User = get_user_model()
from  commonConf.common import api_response
from  commonConf.const import *


class ResetPassword(aBaseViewset):
    queryset = User.objects.filter()
    serializer_class = PasswordResetSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        
        try:
            old_password = request.data['old_password']
            new_password = request.data['new_password']
           
            with transaction.atomic():
                password_validate= password_check(new_password)
                if not password_validate['status']: 
                    return Response(
                        {"message":password_validate['message'],
                            "status": password_validate['status'],
                            "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
                if request.user.check_password(old_password):
                    user=User.objects.get(id=request.user.id)
                    user.set_password(new_password)
                    user.save()
                    return api_response(PASWRD_CHANGE_SUCCESS , True , SUCCESS , status.HTTP_201_CREATED)
                return api_response(OLD_PASS_NOT_MATCHED , False , FAIL , status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return api_response(str(error) , False , FAIL , status.HTTP_400_BAD_REQUEST)

                    
                    

                    