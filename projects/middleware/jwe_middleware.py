# class JweMiddleware:
# 	def process_request(self, request):
# 		token = request.META.get('HTTP_AUTHORIZATION')
# 		print(token)
# 		return None
import jwe
from django.conf import settings
# from admins.accounts.accounts_model.models import AdminToken
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.response import Response

class JweMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response
		# One-time configuration and initialization.

	def __call__(self, request):
		# Code to be executed for each request before
		# the view (and later middleware) are called.
		# apitoken = request.META.get('HTTP_TOKEN',None)
		token = request.META.get('HTTP_AUTHORIZATION',None)
		# if apitoken and not token:
		# 	# print(apitoken)
		# 	##create token
		# 	token_ins = AdminToken.objects.filter(token=apitoken).last()
		# 	if token_ins:
		# 		# User.objects.filter(id=user_id).last()
		# 		refresh = RefreshToken.for_user(token_ins.user)
		# 		refresh["store_id"]=int(token_ins.store_id)
		# 		refresh["user_type"]=int(token_ins.user_type)
		# 		refresh["admin"]=0
		# 		refresh["login_status"]=True
		# 		# print(str(refresh))
		# 		refresh_token = str(refresh)
		# 		ac_token = str(refresh.access_token)
		# 		key = settings.SECRET_KEY
		# 		key = key.encode('utf-8')
		# 		salt = settings.SALT
		# 		derived_key = jwe.kdf(key, salt)
		# 		access_encoded = jwe.encrypt(ac_token.encode('utf-8'), derived_key)
		# 		request.META['HTTP_AUTHORIZATION']=str(access_encoded.decode('utf-8'))

		token = request.META.get('HTTP_AUTHORIZATION')
		if token:
			key = settings.SECRET_KEY
			key = key.encode('utf-8')
			salt = settings.SALT
			derived_key = jwe.kdf(key, salt)
			try:
				new_token = jwe.decrypt(token.encode('utf-8'), derived_key)
				new_token = new_token.decode('utf-8')
				request.META['HTTP_AUTHORIZATION'] = "Bearer "+new_token
			except:
				res = {"error":"Invalid Token"}
				request.META['HTTP_AUTHORIZATION'] = "Bearer "+"error"
		response = self.get_response(request)

		# Code to be executed for each request/response after
		# the view is called.

		return response