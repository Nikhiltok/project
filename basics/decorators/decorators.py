from django.conf import settings
# from basics.data_secuirity.secure import Secuirity
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied, ImproperlyConfigured
import json
from customer.models import *
# from admins.models import *
from rest_framework_simplejwt.authentication import JWTAuthentication

def permission_check_test(original_function):
	def wrapper_function(self, request, pk=None, *args, **kwargs):
		user = request.user
		if user:
			function_name = (self.__name__)
			method = request.method
			has_permission=False
			userinfo = UserSellerProfile.objects.filter(user_id=user,user_category='admin')
			if userinfo:
				has_permission = True

			if user.is_superuser:
				has_permission = True

			if has_permission:
				userinfo = UserSellerProfile.objects.get(user_id=user)
				if userinfo.parent_id:
					request.super_id = userinfo.parent_id
				else:
					request.super_id = user.id
				if pk:
					return original_function(self, request, *args, pk=pk)
				else:
					return original_function(self, request, *args, **kwargs)
			else:
				# message= "You do not have permission. Kindly contact administration !"
				# return JsonResponse({'message': message},status= 301)
				raise PermissionDenied
		else:
			raise PermissionDenied

	return wrapper_function


def permission_check(original_function):
	def wrapper_function(self, request, pk=None, *args, **kwargs):
		user = request.user
		function_name = (self.__name__)
		tok_data = request.META.get("HTTP_AUTHORIZATION")
		jwt_object = JWTAuthentication()
		row_tok = tok_data.split(" ")[1]
		validated_token = jwt_object.get_validated_token(row_tok)
		user_type = validated_token.get("user_type",0)

		if user_type == 2 or request.user.is_superuser == True or user_type == 3:
			if pk:
				return original_function(self, request, *args, pk=pk)
			else:
				return original_function(self, request, *args, **kwargs)
		else:
			# raise PermissionDenied
			message={'error': ['Your credential is not correct.']}
			return JsonResponse({"errors":message},status= 403)

	return wrapper_function

def permission_check_superadmin(original_function):
	def wrapper_function(self, request, pk=None, *args, **kwargs):
		user = request.user
		function_name = (self.__name__)

		if request.user.is_superuser == True:
			if pk:
				return original_function(self, request, *args, pk=pk)
			else:
				return original_function(self, request, *args, **kwargs)
		else:
			# raise PermissionDenied
			message={'error': ['Your credential is not correct.']}
			return JsonResponse({"errors":message},status= 403)

	return wrapper_function