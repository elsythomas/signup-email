from django.urls import path
from . import views
# from .views import user_create

from django.contrib.auth.views import LoginView
from.views import dashboard_user,user_list_json,add_member,role_create,signup,login,admin_only_api,user_create,user_list_html,admin_crud,role_crud,extract_title,student_crud,user_edit,user_delete,user_list,user_model,get_all_roles,get_role,update_role,delete_role,student_details

# from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
# from .views import login_view, protected_view

    
urlpatterns = [
    # path('login/', login_view, name='login'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    # path('protected/', protected_view, name='protected'),
    # path('addmember.html/',add_member,name='addmember.html'),
    # path('login_view/',views.login_view, name='login_view'),
    # # path('login_view/<int:id>/', views.login_view, name='login_view'),
    path('<int:page_number>/',user_list_json, name='user_list_json'),
    path('add-member/', add_member, name='add_member'),
    path('role-create/', role_create ,name='role_create'),
    path('signup/', signup,  name='signup'),
    # path('login.html/', signup,  name='login.html'),
    path('login/',login,name='login'),
    # path('signup.html/', login,  name='signup.html'),
    path('user_create/', user_create,name='user_create'),
    path('login/dashboard/',dashboard_user),
    path('admin_crud/',admin_crud,name='admin_crud'),
    path('admin_crud/<int:id>/', admin_crud, name='admin_crud'),
    path('role_crud/',role_crud,name='role_crud'),
    path('role_crud/<int:id>/', role_crud,name='role_curd'),
    path('student_crud/',student_crud,name='student_crud'),
    path('student_crud/<int:student_id>/',student_crud,name='student_crud'),
    # path('secure-data/', secure_data, name='secure_data'),
    # path('token_validation/',token_validation,name='token_validation'),
    path('admin_only_api/',admin_only_api,name='admin_only_api'),
    # path('user_edit/<int:user_id>/',user_edit,name='user_edit'),
    # # path('users/edit/<int:user_id>/', user_edit, name='user_edit'),
    path('users/edit/<int:user_id>/', user_edit, name='user_edit'),
    path('users/', user_list_html, name='user_list_html'),
    path('user_delete/<int:user_id>/',user_delete,name='user_delete'),
    path('user_list/<int:user_id>/',user_list,name='user_list'),
    # path('users/',user_list,name='userlist')
    path('users/', user_list_html, name='user_list'),
    path('user_model/',user_model,name='user_model'),
    path('create_role/',views.create_role,name='create_role'),
    # path('profile/', student_profile, name='student_profile')
    # path('has_permission/',has_permission,name='has_permission')
    path('get_all_roles/',get_all_roles,name='get_all_roles'),
    path('get_role/<int:role_id>/',get_role,name='get_role'),
    path('update_role/<int:role_id>/',update_role,name='update_role'),
    path('delete_role/<int:role_id>/',delete_role,name='delete_role'),
    path('extract_title/',extract_title,name='extract_title'),
    # path('login/', LoginView.as_view(template_name='login.html'), name='login'),
    path('users/create/', user_create, name='user_create'),
    path('students/', student_crud, name='student_list_create'),
    path('students/<int:student_id>/', student_crud, name='student_detail'),
    # path('role-management/', role_management_view, name='role_management'),
    path('student/<int:student_id>/', student_details, name='student_details'),
    # path('signup/', signup_page, name='signup'),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('api/user/', user_info, name="user_info"),
    #  path('login/', login_view, name='login'),
    # path('logout/', logout_view, name='logout'),
    # path('profile/', profile_view, name='profile'),
    # # path('login/', login_view, name='login_api'),
    # path('login-page/', login_page, name='login_page'),
    
    # path('do_GET',do_GET,name='do_GET'),
    # path('_send_response',_send_response ,name='_send_response')
    # path('user_create/',user_create, name ='user_create')
    #  path('signup/', views.signup_view, name='signup'),
    



]   
