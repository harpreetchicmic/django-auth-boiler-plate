from rest_framework import serializers

from sitepanel.models import UserSocial


class UserLoginSerializer(serializers.ModelSerializer):
    loginid = serializers.CharField(max_length=300)
    password = serializers.CharField(max_length=128)
    class Meta:
        model=UserSocial
        fields=('loginid','password','social_type','social_id',)