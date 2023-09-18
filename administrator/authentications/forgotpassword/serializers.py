from rest_framework import serializers

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    class Meta:
        fields=('email')
        
class ForgotPasswordotpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    class Meta:
        fields=('email')
        
class ChangePasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    class Meta:
        fields=('email')