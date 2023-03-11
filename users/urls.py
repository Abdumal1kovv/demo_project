from .views import CreateUserView, VerifyApiView, GetNewVerification, ChangeUserInformationView, LoginView, \
    CustomTokenRefreshView, LogoutView
from django.urls import path

urlpatterns = [
    path('signup/', CreateUserView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/refresh/', CustomTokenRefreshView.as_view(), name='login_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('verify/', VerifyApiView.as_view(), name='verify'),
    path('new-verify/', GetNewVerification.as_view(), name='new_verify_code'),
    path('update-user-information/', ChangeUserInformationView.as_view(), name='change_user_information'),
]
