from django.shortcuts import render, redirect

from myproject import settings
from .models import Admin,Student,Role
from django.http import HttpResponse, JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model,authenticate
from rest_framework import status
from django.core.mail import send_mail
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import LoginSerializer
from .permissions import IsAdminOrTeacher
from django.http import HttpResponse
from .permissions import IsAdmin 
from .models import Role
from django.core.mail import send_mail
from django.conf import settings 
# from .permissions import check_admin_permissions

from rest_framework.decorators import permission_classes
from .permissions import IsAuthenticatedAndInAdminGroup
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password
import jwt
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def add_member(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        # email = request.POST.get('email')
        # phone = request.POST.get('phone')
        # password =request.POST.get('password')
        roleid =request.POST.get('roleid')
        
        if Admin.objects.filter(roleid=roleid).exists():
            return HttpResponse(f"Error: A member with the {roleid} already exists.")
        
        # Create and save the new member
        admin_cre = Admin(name=name,roleid=roleid)
        admin_cre.save()

        # Redirect or return a response
        return HttpResponse(f" {name} added successfully!")

    return render(request, 'myapp/add_member')

# @csrf_exempt
@api_view(['POST'])
def role_create(request):
    # if request.method =='POST':
    name=request.POST.get('name')
    
    if Role.objects.filter(name=name).exists():
        return HttpResponse(f" {name} already exists.")
        
    new_role=Role(name=name)
    new_role.save()
    
    return HttpResponse(f"{name} added sucessfully")
    
    
# @csrf_exempt
@api_view(['POST'])
def signup(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password =request.POST.get('password')
        role_name=request.POST.get('role')
        print("rollname",role_name)
        role = Role.objects.filter(id=role_name).first() 
        
        # if not role:
        #     return HttpResponse(f"Error: Role '{role_name}' does not exist.")
        # print(role)
        # return HttpResponse("succcss")
      
    if Student.objects.filter(email=email).exists():
        return HttpResponse(f"correct details already exists")
        
    hashed_password = make_password(password)
    student = Student(name=name,email=email,password=hashed_password,Role=role)
    student.save()
        # user = LoginSerializer(Student)
        # Refresh = RefreshToken.for_user(user)
        # acess =Refresh.access_token
        # return Response({
            # "data": "data created sucessfully",
            # "acess":str( acess),
            # "refresh":str( Refresh)
            
        # },status= status.HTTP_201_CREATED)
                
    subject = "Welcome to Our Platform"
    message = f"Hi {name},\n\nWelcome! Your account has been created successfully.\n\nBest regards,\nYour Team"
    from_email = 'elsythomas36987@gmail.com'
    recipient_list = [email]
    print(recipient_list)

    try:
        send_mail(subject, message, from_email, recipient_list)
        email_status = "Email sent successfully!"
    except Exception as e:
        email_status = f"Email failed: {str(e)}"

    return Response({
    "message": "User registered successfully.",
    "email_status": email_status
}, status=status.HTTP_201_CREATED)

# return new_func(email_status)

        # send_mail(subject, message, from_email, recipient_list)

        # return Response({
        #     "data": "Data created successfully, email sent!"
        # }, status=status.HTTP_201_CREATED)
        
    
    
    
@api_view(['POST'])
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password =request.POST.get('password')
        
        try:
            data = Student.objects.get(email=email, password = password)

            # data = LoginAdminSerializer(data).data

            refresh = RefreshToken.for_user(data)
            access = refresh.access_token
            
            return Response({
                'refresh': str(refresh),
                'access': str(access),
            })
        except Student.DoesNotExist:
            return Response (
                {'details' : 'Invalid Credentials'}
            )    

@api_view(['PUT'])
# @csrf_exempt
@permission_classes([IsAuthenticated, IsAdminOrTeacher])
def user_edit(request, user_id):
    try:
        user = Student.objects.get(id=user_id)
        user.name = request.data.get('name', user.name)
        user.email = request.data.get('email', user.email)
        user.password = (request.data.get('password', user.password))
        
        # Update role if provided
        role_id = request.data.get('role_id')
        if role_id:
            role = Role.objects.filter (id=role_id).first()
            if not role:
                return Response({"error": "Invalid role ID."}, status=status.HTTP_400_BAD_REQUEST)
            user.Role = role
        
        user.save()
        return Response({"message": f"User {user.name} updated successfully."}, status=status.HTTP_200_OK)

    except Student.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)



api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsAdminOrTeacher])
def user_delete(request, user_id):
    try:
        user = Student.objects.get(id=user_id)
        user.delete()
        return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)

    except Student.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    
    
    
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminOrTeacher])
def user_list(request, user_id=None):
    if user_id:
        try:
            user = Student.objects.get(id=user_id)
            return Response({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.Role.name if user.Role else None,
            }, status=status.HTTP_200_OK)

        except Student.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    else:
        users = Student.objects.all().values("id", "name", "email", "Role__name")
        return Response({"users": list(users)}, status=status.HTTP_200_OK)




@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Ensure the user is authenticated
def user_model(request):
    # Check if the current user is an admin or teacher
    if request.user.Role.name not in ['admin', 'teacher']:
        return Response({"error": "You do not have permission to create a user."}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'POST':
        name = request.data.get('name')
        email = request.data.get('email')
        password = request.data.get('password')
        role_name = request.data.get('role')
        print("Role name:", role_name)

        # Fetch the role based on the ID or name provided
        role = Role.objects.filter(id=role_name).first()
        print("Fetched role:", role) 
        if not role:
            return Response({"error": f"Role '{role_name}' does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        if Student.objects.filter(email=email).exists():
            return Response({"error": "Student with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        hashed_password = (password)

        student = Student(name=name, email=email, password=hashed_password, Role=role)
        student.save()

        return Response({
            "data": "User created successfully."
        }, status=status.HTTP_201_CREATED)

# def create_role(user_role_id):
#     if user_role_id == 1:  # Admin
#         # Proceed to create a role
#         print("Role creation successful.")
#     else:
#         # Cannot create roles
#         print("You do not have permission to create roles.")

# @api_view(['POST'])
# def login(request):
#     if request.method == 'POST':

# from rest_framework.permissions import BasePermission
# import jwt
# from django.conf import settings

# class IsAdminUserRole(BasePermission):
#     def has_permission(self, request, view):

#         token = request.headers.get("Authorization")
#         if not token or not token.startswith("Bearer "):
#             return False  # No token or invalid format
        
#         # Remove "Bearer " prefix to get the actual token
#         token = token.split("Bearer ")[1]
        
#         try:
#             # Decode the token
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
#             # Check if the user role is 'admin'
#             if decoded_token.get("role") == "admin":
#                 return True
            
#         except jwt.ExpiredSignatureError:
#             return False  # Token expired
#         except jwt.InvalidTokenError:
#             return False  # Token invalid
        
#         return False  # User is not an admin



from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
# from .permissions import IsAdminUserRole

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_only_api(request):
    # Your logic for the admin-only API
    return Response({"message": "Welcome, Admin! You have access to this API."})

# @api_view(['GET'])
# # @permission_classes([IsAu
# def user_create(request):
#     print("Authenticates user:",request.user)
#     # The `request.user` should automatically be set by JWTAuthentication
#     user = request.user  # This should be the authenticated student object
#     if hasattr(user, 'Role') and user.Role.name == 'admin':
#         return Response({"message": "Welcome, Admin! You have access to this API."})
#     else:
#         return Response({"detail": "Permission denied. Admin access required."}, status=403)
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer


@api_view(['POST'])
@permission_classes([IsAuthenticatedAndInAdminGroup]) 
def user_create(request):
    return Response("sucess")
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "User created successfully!", "data": serializer.data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework.permissions import IsAuthenticated

@api_view(['POST'])
def student_profile(request):
    permission_classes = [IsAuthenticated]
    student = request.user.Role
    
    print(student)
    return Response ("sucess")
    return Response({
        "name": student.name,
        "email": student.email,
        "role": student.Role.name if student.Role else None,
    })




@csrf_exempt
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
def admin_crud(request, admin_id=None):
    if request.method == 'POST':
        name = request.data.get('name')
        roleid = request.data.get('roleid')

        if Admin.objects.filter(roleid=roleid).exists():
            return Response({"error": f"Admin with roleid {roleid} already exists."}, status=status.HTTP_400_BAD_REQUEST)

        admin = Admin(name=name, roleid=roleid)
        admin.save()
        return Response({"message": f"Admin {name} added successfully."}, status=status.HTTP_201_CREATED)

    if request.method == 'GET':
        if admin_id:
            try:
                admin = Admin.objects.get(id=admin_id)
                return Response({"id": admin.id, "name": admin.name, "roleid": admin.roleid})
            except Admin.DoesNotExist:
                return Response({"error": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            admins = Admin.objects.all().values()
            return Response({"admins": list(admins)})

    if request.method == 'PUT':
        try:
            admin = Admin.objects.get(id=admin_id)
            admin.name = request.data.get('name', admin.name)
            admin.roleid = request.data.get('roleid', admin.roleid)
            admin.save()
            return Response({"message": "Admin updated successfully."})
        except Admin.DoesNotExist:
            return Response({"error": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            admin = Admin.objects.get(id=admin_id)
            admin.delete()
            return Response({"message": "Admin deleted successfully."})
        except Admin.DoesNotExist:
            return Response({"error": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)


# Role CRUD
# @csrf_exempt
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
def role_crud(request, role_id=None):
    if request.method == 'POST':
        name = request.data.get('name')

        if Role.objects.filter(name=name).exists():
            return Response({"error": f"Role {name} already exists."}, status=status.HTTP_400_BAD_REQUEST)

        role = Role(name=name)
        role.save()
        return Response({"message": f"Role {name} created successfully."}, status=status.HTTP_201_CREATED)

    if request.method == 'GET':
        if role_id:
            try:
                role = Role.objects.get(id=role_id)
                return Response({"id": role.id, "name": role.name})
            except Role.DoesNotExist:
                return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            roles = Role.objects.all().values()
            return Response({"roles": list(roles)})

    if request.method == 'PUT':
        try:
            role = Role.objects.get(id=role_id)
            role.name = request.data.get('name', role.name)
            role.save()
            return Response({"message": "Role updated successfully."})
        except Role.DoesNotExist:
            return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            role = Role.objects.get(id=role_id)
            role.delete()
            return Response({"message": "Role deleted successfully."})
        except Role.DoesNotExist:
            return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)


# Student CRUD
# @csrf_exempt
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
def student_crud(request, student_id=None):
    if request.method == 'POST':
        name = request.data.get('name')
        email = request.data.get('email')
        password = request.data.get('password')
        role_id = request.data.get('role_id')

        if Student.objects.filter(email=email).exists():
            return Response({"error": f"Student with email {email} already exists."}, status=status.HTTP_400_BAD_REQUEST)

        hashed_password = make_password(password)
        role = Role.objects.filter(id=role_id).first()
        if not role:
            return Response({"error": "Invalid role ID."}, status=status.HTTP_400_BAD_REQUEST)

        student = Student(name=name, email=email, password=hashed_password, Role=role)
        student.save()
        return Response({"message": f"Student {name} created successfully."}, status=status.HTTP_201_CREATED)

    if request.method == 'GET':
        if student_id:
            try:
                student = Student.objects.get(id=student_id)
                return Response({
                    "id": student.id,
                    "name": student.name,
                    "email": student.email,
                    "role": student.Role.name if student.Role else None,
                })
            except Student.DoesNotExist:
                return Response({"error": "Student not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            students = Student.objects.all().values()
            return Response({"students": list(students)})

    if request.method == 'PUT':
        try:
            student = Student.objects.get(id=student_id)
            student.name = request.data.get('name', student.name)
            student.email = request.data.get('email', student.email)
            student.password = make_password(request.data.get('password', student.password))
            role_id = request.data.get('role_id')
            if role_id:
                role = Role.objects.filter(id=role_id).first()
                if role:
                    student.Role = role
            student.save()
            return Response({"message": "Student updated successfully."})
        except Student.DoesNotExist:
            return Response({"error": "Student not found."}, status=status.HTTP_404_NOT_FOUND)
    if request.method == 'DELETE':
        if not student_id:
            return Response({"error": "Student ID is required for deletion."}, status=status.HTTP_400_BAD_REQUEST)
    try:
            student = Student.objects.get(id=student_id)  # Use student_id here
            student.delete()
            return Response({"message": "Student deleted successfully."})
    except Student.DoesNotExist:
     return Response({"error": "Student not found."}, status=status.HTTP_404_NOT_FOUND)


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def create_role(request):
    role_name = request.data.get('role_name')  # Use `request.data` for REST framework compatibility
    if not role_name:
        return HttpResponse("Role name is required.", status=400)

    # Create the new role
    Role.objects.create(name=role_name)
    return HttpResponse("Role created successfully!")

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def get_all_roles(request):
    roles = Role.objects.all()
    # You can serialize the roles if needed
    roles_list = [{'id': role.id, 'name': role.name} for role in roles]
    return JsonResponse(roles_list, safe=False)


# @csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def get_role(request, role_id):
    try:
        role = Role.objects.get(id=role_id)
    except Role.DoesNotExist:
        return HttpResponse("Role not found.", status=404)

    return JsonResponse({'id': role.id, 'name': role.name})

# @csrf_exempt
@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsAdmin])
def update_role(request, role_id):
    try:
        role = Role.objects.get(id=role_id)
    except Role.DoesNotExist:
        return HttpResponse("Role not found.", status=404)

    role_name = request.data.get('role_name')
    if not role_name:
        return HttpResponse("Role name is required.", status=400)

    role.name = role_name
    role.save()
    return HttpResponse("Role updated successfully!")

# @csrf_exempt
@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsAdmin])
def delete_role(request, role_id):
    try:
        role = Role.objects.get(id=role_id)
    except Role.DoesNotExist:
        return HttpResponse("Role not found.", status=404)

    role.delete()
    return HttpResponse("Role deleted successfully!")






















































    # if request.method != 'POST':
    #     return HttpResponse("Invalid request method.", status=405)

    # # Check user permissions
    # permission_response = has_permissions(request.user)
    # if permission_response:
    #     return permission_response

    # role_name = request.POST.get('role_name')
    # if not role_name:
    #     return HttpResponse("Role name is required.", status=400)

    # Role.objects.create(name=role_name)
    # return HttpResponse("Role created successfully!")

















# from django.http import HttpResponse
# @csrf_exempt

# def create_role(request):
#     if request.method != 'POST':
#         return HttpResponse("Invalid request method.", status=405)

#     # Check user permissions
#     permission_response = check_admin_permissions(request.user)
#     if permission_response:
#         return permission_response

#     role_name = request.POST.get('role_name')
#     if not role_name:
#         return HttpResponse("Role name is required.", status=400)

#     Role.objects.create(name=role_name)
#     return HttpResponse("Role created successfully!")
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
# @csrf_exempt
# def create_role(request):
#     if request.method != 'POST':
#         return HttpResponse("Invalid request method.", status=405)

#     if not request.user.is_authenticated:
#         return HttpResponse("You must be logged in to create a role.", status=401)

#     if request.user.roleid != 1:  # Only admins can create roles
#         return HttpResponse("You do not have permission to create roles.", status=403)

#     role_name = request.POST.get('role_name')
#     if not role_name:
#         return HttpResponse("Role name is required.", status=400)

#     Role.objects.create(name=role_name)
#     return HttpResponse("Role created successfully!")















 
 
 
 
 

    # if request.method == 'DELETE':
    #     try:
    #         student = Student.objects.get(id=id)
    #         student.delete()
    #         return Response({"message": "Student deleted successfully."})
    #     except Student.DoesNotExist:
    #         return Response({"error": "Student not found."}, status=status.HTTP_404_NOT_FOUND)


# # Login API
# @csrf_exempt
# @api_view(['POST'])
# def login(request):
#     email = request.data.get('email')
#     password = request.data.get('password')

#     student = authenticate(username=email, password=password)
#     if student:
#         refresh = RefreshToken.for_user(student)
#         return Response({
#             "access": str(refresh.access_token),
#             "refresh": str(refresh),
#         })
#     return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


# # Student Profile API
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def student_profile(request):
#     student = request.user
#     return Response({
#         "name": student.name,
#         "email": student.email,
#         "role": student.Role.name if student.Role else None,
#     })



# import jwt
# import datetime

# SECRET_KEY = "your_secret_key"

# token = jwt.encode(
#     {
#         "user_id": 1,
#         "role": "admin",
#         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
#         "iat": datetime.datetime.utcnow()
#     },
#     SECRET_KEY,
#     algorithm="HS256"
# )

# print(token)








# VALID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQwMDQzNTUxLCJpYXQiOjE3Mzc0NTE1NTEsImp0aSI6IjlmNWIzNWNjYjA0NDQ0MDE4YTRkNDg0MTZkOGY5NzBkIiwidXNlcl9pZCI6MTh9.VDygr9yDufEtXcCOQh7siSR9MM80FWpIl5DqiahSV4w",

# @csrf_exempt

# def secure_data(request):
#     # Check if the token is passed in the Authorization header
#     token = request.headers.get('Authorization')

#     if token != f"Bearer {VALID_TOKEN}":
#         return JsonResponse({"error": "Unauthorized"}, status=401)

#     # If the token is valid, return secure data
#     return JsonResponse({"message": "This is secure data"})


# SECRET_KEY = "your_secret_key"

# # Define roles (example: role[1] is for user_id=1)
# roles = {1: "admin", 2: "editor", 3: "viewer"}

# @api_view(['POST'])
# # @csrf_exempt
# def token_validation(request):
#     print("els")
#     # Extract the token from the Authorization header
#     token = request.headers.get("Authorization")
    
#     if not token or not token.startswith("Bearer "):
#         return Response({"error": "Unauthorized: Token missing or invalid format"}, status=401)
    
#     # Remove the "Bearer " prefix to get the actual token
#     token = token.split("Bearer ")[1]
    
#     try:
#         # Decode the JWT token
#         decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        
#         # Validate if the user_id is in the roles and matches the desired role
#         user_id = decoded_token.get("user_id")
#         if user_id != 1 or roles.get(user_id) != "admin":
#             return Response({"error": "Unauthorized: Invalid role or user"}, status=403)
        
#         # If token and role are valid
#         return Response({"message": "Token and role validated successfully!"}, status=200)
    
#     except jwt.ExpiredSignatureError:
#         return Response({"error": "Unauthorized: Token expired"}, status=401)
#     except jwt.InvalidTokenError:
#         return Response({"error": "Unauthorized: Invalid token"}, status=401)



# import jwt
# import datetime

# SECRET_KEY = "your_secret_key"

# # Create a token for user_id=1
# token = jwt.encode(
#     {
#         "user_id": 1,
#         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # 1-hour validity
#         "iat": datetime.datetime.utcnow()
#     },
#     SECRET_KEY,
#     algorithm="HS256"
# )

# print(token)


# @api_view(['POST'])
# def token_validation(request):
#     token =request.headers.get("authorization")
    
#     if token_validation == role[1]:
#         return 
    
#     pass
























# def user_edit(request):
#     pass

# def user_delete(request):
#     pass
# def user_list(request):
#     pass


# def token_validation():
#     toke
#     pass

