
from rest_framework import permissions


class IsAuthenticatedAndInAdminGroup(permissions.BasePermission):
    """
    Allows access only to authenticated users who are in the ADMIN .
    """
    def has_permission(self, request, view):
        print("rrr",request.user.Role)
        if not request.user.is_authenticated:
            return False
        # Check if the user is in the ADMIN 
        if request.user.Role_id == 1:
            return True
        
from rest_framework.permissions import BasePermission

class IsAdminOrTeacher(BasePermission):
    """
    Custom permission to allow only users with 'admin' or 'teacher' roles to access the view.
    """

    def has_permission(self, request, view):
        # Extract the role from the user object, assuming `Role` is related to the user.
        user = request.user
        if not user or not user.is_authenticated:
            return False  # Deny if user is not authenticated

        # Check if the user has 'admin' or 'teacher' role
        return user.Role.name in ['admin', 'teacher']
       
class IsAdmin(BasePermission):
    """
    Custom permission to check if the user is an admin.
    """

    def has_permission(self, request, view):
        
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return False  # User must be authenticated

        # Check if the user is an admin
        return  request.user.Role.id == 1

