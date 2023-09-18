from rest_framework import serializers
from django.contrib.auth.models import User

from sitepanel.models import UserProfile


class ProfileSerializers(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('__all__')
        
class UserSerializers(serializers.ModelSerializer):
    profileDetails = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ('first_name','id' ,'last_name','username','profileDetails')

    def get_profileDetails(self,obj):
        try:
            data = ProfileSerializers(UserProfile.objects.get(ref_user=obj.id)).data
        except:
            data ="details not found"
            
        return data





