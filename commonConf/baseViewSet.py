from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, DjangoModelPermissions

from commonConf.authentication import cTokenAuthentication

from commonConf import rData

class AuthPerm(DjangoModelPermissions):
    # Map methods into required permission codes.
    # Override this if you need to also provide 'view' permissions,
    # or if you want to provide custom permission codes.
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    # def has_permission(self, request, view):
    #     return True

    # def has_permission(self, request, view):
    #      # Workaround to ensure DjangoModelPermissions are not applied
    #     # to the root view when using DefaultRouter.
    #     if getattr(view, '_ignore_model_permissions', False):
    #         return True

    #     if not request.user or (
    #        not request.user.is_authenticated and self.authenticated_users_only):
    #         return False

    #     queryset = self._queryset(view)
    #     perms = self.get_required_permissions(request.method, queryset.model)

    #     return request.user.has_perms(perms)


"""
    Admin Base View Set
"""


class aBaseViewset(viewsets.ModelViewSet):
    authentication_classes = [cTokenAuthentication]
    permission_classes = [AuthPerm]

    def list(self, request, *args, **kwargs):
        rData.request = request
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        rData.request = request
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        rData.request = request
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        rData.request = request
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        rData.request = request
        return super().destroy(request, *args, **kwargs)


"""
    App User Viewset
"""


class appBaseViewset(viewsets.ModelViewSet):
    authentication_classes = [cTokenAuthentication]
    permission_classes = [AuthPerm]

    def create(self, request, *args, **kwargs):
        rData.request = request
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        rData.request = request
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        rData.request = request
        return super().destroy(request, *args, **kwargs)


"""
    Viewset with out token
"""


class nBaseViewset(viewsets.ModelViewSet):
    def create(self, request, *args, **kwargs):
        rData.request = request
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        rData.request = request
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        rData.request = request
        return super().destroy(request, *args, **kwargs)


class vBaseViewset(viewsets.ModelViewSet):
    def list(self, request, *args, **kwargs):
        rData.request = request
        return super().list(request, *args, **kwargs)
