from rest_framework import routers
from django.urls import path
from sitepanel.authentications.forgotpassword.forgotpassword import ChangePassword, ConfirmPassword, ForgotPasswordMail
from sitepanel.authentications.login.views import AuthLoginViewset, AuthLogoutViewset, getEmailSocialLogin
from sitepanel.authentications.resetpassword.resetpassword import ResetPassword
from sitepanel.authentications.signup.views import AuthSignupViewset, UserVerification
from sitepanel.views import ManageProfile
router = routers.DefaultRouter()

router.register(r'auth/register', AuthSignupViewset)
router.register(r'auth/login', AuthLoginViewset)
router.register(r'getUserEmail',getEmailSocialLogin)
router.register(r'auth/logout',AuthLogoutViewset)
router.register(r'auth/resetpassword', ResetPassword)
router.register(r'auth/forgotpassword',ForgotPasswordMail)
router.register(r'auth/ConfirmPassword',ConfirmPassword)
router.register(r'auth/ManageProfile',ManageProfile)


urlpatterns = [
    path('auth/verifyuser/<uid>/<token>/',UserVerification.as_view({'get':'list'}),name="userverification"),
    path('auth/changepassword/<uid>/<token>/',ChangePassword.as_view({'get':'list'}),name="changepassword"),
]

