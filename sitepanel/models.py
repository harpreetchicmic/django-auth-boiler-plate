from django.db import models

# Create your models here.
from django.contrib.auth.models import User
from django.forms import CharField
import uuid
from django.utils.translation import ugettext_lazy as _


from commonConf.choices import SocialChoices, UserChoices

class UserProfile(models.Model):

    ref_user = models.OneToOneField(
        User, related_name="user_profile", on_delete=models.CASCADE)
    uuid = models.UUIDField(
        primary_key=False, default=uuid.uuid4, editable=False)
    photo = models.ImageField(upload_to='users_photo/', default="user.png",
                              null=True, blank=True, verbose_name=_("photo"))
    phone_number = models.CharField(null=True, max_length=12)
    verified = models.BooleanField(default=0)
    fcm_token = models.TextField(null=True,blank=True)  
    user_type = models.CharField(
        max_length=30,
        choices=UserChoices.choices(),
        default="unassigned"
    )
    otp = models.IntegerField( null=True, blank=True, default=None)
    age = models.IntegerField(null=True,blank=True)
    gender = models.CharField(max_length=128,null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = "user_profile"

class UserSocial(models.Model):
    ref_user = models.OneToOneField(
        User, related_name="user_social", on_delete=models.CASCADE)
    social_type = models.CharField(
        max_length=30,
        choices=SocialChoices.choices()
    )
    social_id = models.CharField(max_length=255, blank=True, null=True)
    twitter_username = models.CharField(max_length=255,null=True)
    instagram_username = models.CharField(max_length=255,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_social"
