# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework.response import Response

# # Define a function to simulate decoding and validating the token (for testing)
# def validate_token(token):
#     jwt_auth = JWTAuthentication()
#     try:
#         validated_token = jwt_auth.get_validated_token(token)
#         user = jwt_auth.get_user(validated_token)  # This should return the student object
#         return user
#     except AuthenticationFailed:
#         return "Token is invalid or expired"

# # Your token (replace this with the actual token string)
# token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQwMjA1OTg4LCJpYXQiOjE3Mzc2MTM5ODgsImp0aSI6IjRkMWY4Njg2M2MyMDQ2NTNiYzgyYjQyYWE4NzRiMjY4IiwidXNlcl9pZCI6MTl9.3VYY0Ct4bkLR0BlYuTLJeQYmKC8o6oZwRawky0ZK2g8"

# # Validate token and print the result
# user = validate_token(token)
# print(user)
