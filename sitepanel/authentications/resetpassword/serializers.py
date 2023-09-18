from rest_framework import serializers

class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=128)
    class Meta:
        fields=('old_password','new_password')