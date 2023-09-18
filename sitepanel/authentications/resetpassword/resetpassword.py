
from rest_framework import status
from rest_framework.response import Response
from django.db import transaction
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from commonConf.baseViewSet import aBaseViewset
from commonConf.passwordValidator import password_check
from sitepanel.authentications.resetpassword.serializers import PasswordResetSerializer
User = get_user_model()



class ResetPassword(aBaseViewset):
    queryset = User.objects.filter()
    serializer_class = PasswordResetSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        
        try:
            old_password = request.data['old_password']
            new_password = request.data['new_password']
            try:
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
                        return Response({
                        "message": "Password changed successfully",
                        "status": True,
                        "response": "success", }, status=status.HTTP_201_CREATED)
                    return Response({
                        "message": " Old password doesn't match",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
                    
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
                    
                    

                    