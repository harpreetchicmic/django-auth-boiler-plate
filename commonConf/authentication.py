from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token

from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed


class cTokenAuthentication(TokenAuthentication):
    keyword = 'Bearer'

    def authenticate_credentials(self, key):
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed("Invalid Token")

        if not token.user.is_active:
            raise AuthenticationFailed("User is not active")

        is_expired, token = token_expire_handler(token)

        return token.user, token


def is_token_expired(token):
    user_last_login = Token.objects.get(key=token).user.last_login
    if user_last_login:
        today = timezone.now()
        if (today - user_last_login).days >= 7:
            return True
        else:
            return False
    else:
        return False


def token_expire_handler(token):
    is_expired = is_token_expired(token)
    if is_expired:
        token.delete()
        token = Token.objects.create(user=token.user)
    return is_expired, token
