"""project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
	https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
	1. Add an import:  from my_app import views
	2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
	1. Add an import:  from other_app.views import Home
	2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
	1. Import the include() function: from django.urls import include, path
	2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from partnar.accounts import views
# from rest_framework_simplejwt.views import (
# 	TokenObtainPairView,
# 	TokenRefreshView,
# )

urlpatterns = [
	path(
		'login', 
		views.LoginView.as_view(), 
		name='account_login'
	),
	path(
		'refresh', 
		views.MyRefreshToken.as_view(), 
		name='token_refresh'
	),
	path(
		'signup', 
		views.SignupView.as_view(), 
		name='account_signup'
	),
	path(
		'profile', 
		views.ProfileView.as_view(), 
		name='account_profile'
	),
	path(
		"changepassword/<int:pk>",
		views.ChangePasswordView.as_view(),
		name="account_change_password_view"
	),
	path(
		"forget-password",
		views.ForgetPasswordView.as_view(),
		name="account_forget_password_view"
	),
	path(
		"reset-password",
		views.ResetPasswordView.as_view(),
		name="account_reset_password_view"
	),
		
]