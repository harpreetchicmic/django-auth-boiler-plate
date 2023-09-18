from django.shortcuts import render

from commonConf.baseViewSet import aBaseViewset
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.response import Response
from sitepanel.serializers import UserSerializers
from sitepanel.models import UserProfile

# Create your views here.
class AdminManageProfile(aBaseViewset):
    queryset = User.objects
    subQueryset = UserProfile.objects
    serializer_class = UserSerializers
    http_method_names = ['get','put']
    
    def list(self, request, *args, **kwargs):
        try:
            data = self.queryset.get(id=request.user.id)
            serializedData = self.serializer_class(data).data
            return Response({
                        "data" :serializedData,
                        "message": "User fetch successfully",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_200_OK)
        except Exception as error:
                    return Response({
                        "message": "User profile does not exist.",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        try:
            requestedData = request.data
            user = self.queryset.get(id=request.user.id)
            user.first_name = requestedData['first_name']
            user.last_name = requestedData['last_name']
            user.save()
            userProfile = self.subQueryset.get(ref_user=user)
            profilephoto=request.FILES['profilephoto']

            userProfile.photo=profilephoto
            userProfile.phone_number=requestedData['number']
            userProfile.age=requestedData['age']
            userProfile.gender=requestedData['gender']
            userProfile.save()
            serializedData = self.serializer_class(user).data
            return Response({
                        "data" :serializedData,
                        "message": "User updated successfully",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_200_OK)
        except Exception as error:
                    return Response({
                        "message": "User profile does not exist.",
                        "status": False,
                        "response": "fail", }, status=status.HTTP_400_BAD_REQUEST)
    
   