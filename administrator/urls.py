from rest_framework import routers
from django.urls import path
from administrator.authentications.forgotpassword.forgotpassword import ChangePassword, ConfirmPassword, ForgotPasswordMail
from administrator.authentications.login.views import AuthLoginViewset, AuthLogoutViewset
from administrator.authentications.resetpassword.resetpassword import ResetPassword
from administrator.views import AdminManageProfile
router = routers.DefaultRouter()

router.register(r'auth/login', AuthLoginViewset)
router.register(r'auth/logout',AuthLogoutViewset)
router.register(r'auth/resetpassword', ResetPassword)
router.register(r'auth/forgotpassword',ForgotPasswordMail)
router.register(r'auth/ConfirmPassword',ConfirmPassword)
router.register(r'auth/ManageProfile',AdminManageProfile)


urlpatterns = [
    path('auth/changepassword/<uid>/<token>/',ChangePassword.as_view({'get':'list'}),name="changepassword"),
]

