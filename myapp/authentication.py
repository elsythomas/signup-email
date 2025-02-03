# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework.exceptions import AuthenticationFailed
# from .models import Student

# class CustomJWTAuthentication(JWTAuthentication):
#     def get_user(self, validated_token):
#         student_id = validated_token.get("user_id")
#         if not student_id:
#             raise AuthenticationFailed("Token missing user_id.")
#         try:
#             student = Student.objects.get(id=student_id)
#             return student
#         except Student.DoesNotExist:
#             raise AuthenticationFailed("Student not found.")
