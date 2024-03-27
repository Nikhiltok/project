from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from customer.accounts.serializers import *
from customer.accounts.create_or_update import *
from customer.accounts.info import *
from django.db.models import Q
from django.contrib.auth.models import User
from django.contrib.auth.hashers import *
from django.contrib.auth import authenticate, login
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.tokens import RefreshToken
import jwe
from django.conf import settings
import json
import datetime,time
from customer.accounts.accounts_model.models import UserProfile
from customer.common.serializers import KeyErrorSerializer
from customer.common.views import *
# FOR FORGET AND RESET PASSWORD
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import *
from django.utils.encoding import *
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.parsers import MultiPartParser

class GuestLoginView(GenericAPIView):
	"""
		Enter the username or email and password to login in this project
	"""
	permission_classes = (AllowAny,)
	serializer_class = GuestLoginSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="Guest login api for project", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data_validation = GuestLoginSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			device_id = data.get('device_id')
			password = "guest"
			username = "guest@guest.com"
			instance = User.objects.filter(
				Q(username__exact=username) |
				Q(email__exact=username)
			).last()
			user = instance
			if user:
				refresh = RefreshToken.for_user(user)
				
				refresh["device_id"]=device_id
				refresh["login_status"]=False
				refresh_token = str(refresh)
				ac_token = str(refresh.access_token)
				key = settings.SECRET_KEY
				key = key.encode('utf-8')
				salt = settings.SALT
				derived_key = jwe.kdf(key, salt)
				access_encoded = jwe.encrypt(ac_token.encode('utf-8'), derived_key)
				refresh_encoded = jwe.encrypt(refresh_token.encode('utf-8'), derived_key)
				response["refresh_token"] = str(refresh_encoded.decode('utf-8'))
				response["access_token"] = str(access_encoded.decode('utf-8'))
				response["message"] = "success"
			else:
				response["errors"] = {"username":["Username or password is wrong"]}
				status_code = 400
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class LoginView(GenericAPIView):
	"""
		Enter the username or email and password to login in this project
	"""
	response_schema_dict = {
		"200": openapi.Response(
			description="Success",
			examples={
				"application/json": {
					"access_token": "dfdfdfs",
					"refresh_token": "sdfsdfsdf",
					"message":"success"
				}
			},
			schema=LoginSerializer
		),
		"400": openapi.Response(
			description="Key error",
			examples={
				"application/json": {
					"error": "key error"
				}
			},
			schema=KeyErrorSerializer
		),
	}
	permission_classes = (AllowAny,)
	serializer_class = LoginSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="login api for project", responses=response_schema_dict,tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data_validation = LoginSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			username = data.get('username').lower()
			password = data.get('password')
			device_id = data.get('device_id')
			# store_data = getStoreIns(request_origin)
			# if store_data:
			filterquery = Q()
			filterquery.add ( 
				Q(userprofile__otp_status=True) & 
				Q(userprofile__is_user_activate=True) & 
				Q(is_active=True),
				Q.AND
			)
			if username.isdigit():
				filterquery.add(
				Q(userprofile__phone__exact=username) &
				Q.AND
			)
			else:
				filterquery.add(
				(Q(username__exact=username) |
				Q(email__exact=username)),
				Q.AND
			)
			instance = User.objects.filter(
				filterquery
			)
			if instance.last():
				instance = instance.last()
				if instance.is_active and instance.userprofile.isdeleted is False:
					username = instance.username
					user = authenticate(
						username=username,
						password=password
					)

					if user:
						refresh = RefreshToken.for_user(user)
						refresh["device_id"]=device_id
						refresh["login_status"]=True
						refresh["user_type"]=2
						# refresh["store_id"] = store_data.store_id
						# print(str(refresh))
						# print(str(refresh.access_token))
						refresh_token = str(refresh)
						ac_token = str(refresh.access_token)
						key = settings.SECRET_KEY
						key = key.encode('utf-8')
						salt = settings.SALT
						derived_key = jwe.kdf(key, salt)
						access_encoded = jwe.encrypt(ac_token.encode('utf-8'), derived_key)
						refresh_encoded = jwe.encrypt(refresh_token.encode('utf-8'), derived_key)
						# print("encoded ",encoded.decode('utf-8'))
						"""
							filter temp cart by device id. if product found and insert all products to cart table
							and remove records from temp cart.
						"""
						# CreateOrUpdate.CartCreateOrUpdate(self,user,device_id,store_data.store_id)

						response["refresh_token"] = str(refresh_encoded.decode('utf-8'))
						response["access_token"] = str(access_encoded.decode('utf-8'))
						response["message"] = "success"
						response["name"] = instance.userprofile.full_name
						response["email"] = instance.email
						# response["sname"]= store_data.store.name
						# response["logo"] = str(store_data.store.image)
					else:
						response["errors"] = {"username":["Username or password is wrong"]}
						status_code = 400
				else:
					response["errors"] = {"username":["Your account is not active"]}
					status_code = 400
			else:
				response["errors"] = {"username":["Username is wrong"]}
				status_code = 400
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class MyRefreshToken(GenericAPIView):
	permission_classes = (AllowAny,)
	serializer_class = MyRefreshSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="refresh token api",tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		token = data.get('refresh')
		if token:
			key = settings.SECRET_KEY
			key = key.encode('utf-8')
			salt = settings.SALT
			derived_key = jwe.kdf(key, salt)
			try:
				new_token = jwe.decrypt(token.encode('utf-8'), derived_key)
				new_token = new_token.decode('utf-8')
			except:
				# new_token = token
				response["errors"] = {"refresh":["Refresh token is invalid or expire..."]}
				status_code = 400
				return Response(response, status=status_code)
			
			new_data = {"refresh": new_token }
			data_validation = MyRefreshSerializer(data=new_data)
			is_valid_data = data_validation.is_valid()
			if is_valid_data:
				refresh = RefreshToken(new_data['refresh'])
				# print(int(refresh.access_token.lifetime.total_seconds()))
				# refresh_token = str(refresh)
				ac_token = str(refresh.access_token)
				# print("new ac token ",ac_token)
				key = settings.SECRET_KEY
				key = key.encode('utf-8')
				salt = settings.SALT
				derived_key = jwe.kdf(key, salt)
				access_encoded = jwe.encrypt(ac_token.encode('utf-8'), derived_key)
				response["access_token"] = access_encoded
			else:
				status_code = 400
				response["errors"] = data_validation.errors
		else:
			response["errors"] = {"refresh":["refresh token can not be empty"]}
			status_code = 400
		return Response(response, status=status_code)

class SignupView(GenericAPIView):
	"""
		Fill up the signup form to get the login creds
		URL http://localhost:8000/basic/account/signup
	"""
	permission_classes = (AllowAny,)
	serializer_class = SignupSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="signup api for project", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data_validation = SignupSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			instance = CreateOrUpdate.UserCreateOrUpdate(
				self,
				data,
			)
			# data["user_id"] = instance.id
			# data["appartment_name"] = data["street_name"]
			# data["street_name"] = data["address"]
			# data.pop("id","not found")
			# data.pop("address","not found")
			# data["address_type"] = "Home"
			# # first time create address store
			# if UserAddress.objects.filter(user_id=data["user_id"],isactive=True).count() < 1:
			# 	address = CreateOrUpdate.UserAddressCreateOrUpdate(
			# 		self,
			# 		data
			# 	)
			response["phone"] = data.get("phone")
			response["message"] = "signup successfully. EmailId/Phone is your username"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class ResendOTPView(GenericAPIView):
	"""
		Resend OTP API
	"""
	permission_classes = (AllowAny,)
	serializer_class = OTPSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="Resend OTP API", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data_validation = OTPSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			# store_data = getStoreIns(request_origin)
			data = data_validation.validated_data
			phone = data.get("phone")
			# send_sms(phone)
			response["message"] = "OTP Sent"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)



class SendOTPView(GenericAPIView):
	"""
		Send OTP API
	"""
	permission_classes = (AllowAny,)
	serializer_class = OTPSendSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="Send OTP API", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data_validation = OTPSendSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			# store_data = getStoreIns(request_origin)
			data = data_validation.validated_data
			phone = data.get("phone")
			# send_sms(phone,store_data.store_id)
			response["message"] = "OTP Sent"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)


class VerifyOTPView(GenericAPIView):
	"""
		Verify OTP if not verify
		URL http://localhost:8000/basic/account/verify-otp
	"""
	queryset = User.objects
	permission_classes = (AllowAny,)
	serializer_class = VerifyOTPSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="verify otp api for project", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data_validation = VerifyOTPSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			# store_data = getStoreIns(request_origin)
			code = data.get("otp")
			phone = data.get("phone")
			if check_otp(phone,code) == "approved":
				instance = CreateOrUpdate.VerifyOtp(
					self,
					data
				)
				response["message"] = "OTP verification is successful"
			else:
				status_code = 400
				response["message"] = "OTP is invalid or expire"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class VerifyPhoneOTPView(GenericAPIView):
	"""
		Verify OTP if not verify
		URL http://localhost:8000/basic/account/verify-otp
	"""
	queryset = User.objects
	permission_classes = (AllowAny,)
	serializer_class = VerifyPhoneOTPSerializer
	@classmethod
	@swagger_auto_schema(operation_summary="verify phone otp api", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data_validation = VerifyPhoneOTPSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			# store_data = getStoreIns(request_origin)
			code = data.get("otp")
			phone = data.get("phone")
			if check_otp(phone,code) == "approved":
				instance = CreateOrUpdate.VerifyOtp(
					self,
					data
				)
				response["message"] = "OTP verification is successful"
			else:
				status_code = 400
				response["message"] = "OTP is invalid or expire"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)


class ProfileView(GenericAPIView):
	"""
		Get the profile data and update it
	"""
	parser_classes = (MultiPartParser,)
	permission_classes = (IsAuthenticated,)
	serializer_class = ProfileSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="profile api for project", tags=['Account'])
	def put(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data = data.copy()
		device_id,login_status,store_id = retrieve_token(request)
		pk = request.user.id
		data_validation = ProfileSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			instance = CreateOrUpdate.UserCreateOrUpdate(
				self,
				data,
			)
			response["message"] = "Profile updated successfully"
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

	@classmethod
	@swagger_auto_schema(operation_summary="get profile data", tags=['Account'])
	def get(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.GET
		data = data.dict() # convert QueryDict to normal dict QueryDict is immutable
		pk = request.user.id
		# data.update({
		# 	"id":10
		# })
		try:
			user_instance = User.objects.get(id=pk,userprofile__isactive=True,userprofile__isdeleted=False)
			response["result"] = UserInfo.Details(
				self,
				user_instance
			)
		except Exception as e:
			response["errors"] = {"id":["Invalid User"]}
			status_code = 400
		return Response(response, status=status_code)


# class AddressView(GenericAPIView):
# 	"""
# 		Address add, update, list delete api
# 	"""
# 	permission_classes = (IsAuthenticated,)
# 	serializer_class = AddressSerializer

# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Exisiting User Address book", tags=['Account'])
# 	def post(self, request, *args, **kwargs):
# 		response = {}
# 		status_code = 200
# 		data = request.data
# 		pk = request.user.id
# 		data.update({
# 			"user_id":pk
# 		})
# 		data_validation = AddressSerializer(data=data)
# 		is_valid_data = data_validation.is_valid()
# 		if is_valid_data:
# 			data = data_validation.validated_data
# 			instance = CreateOrUpdate.UserAddressCreateOrUpdate(
# 				self,
# 				data
# 			)
# 			response["message"] = "Address added successfully"
# 		else:
# 			status_code = 400
# 			response["errors"] = data_validation.errors
# 		return Response(response, status=status_code)

# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Update Exisiting User Address book", request_body=AddressUpdateSerializer, tags=['Account'])
# 	def put(self, request, *args, **kwargs):
# 		response = {}
# 		status_code = 200
# 		data = request.data
# 		pk = request.user.id
# 		data.update({
# 			"user_id":pk
# 		})
# 		data_validation = AddressUpdateSerializer(data=data)
# 		is_valid_data = data_validation.is_valid()
# 		if is_valid_data:
# 			data = data_validation.validated_data
# 			instance = CreateOrUpdate.UserAddressCreateOrUpdate(
# 				self,
# 				data
# 			)
# 			response["message"] = "Address updated successfully"
# 		else:
# 			status_code = 400
# 			response["errors"] = data_validation.errors
# 		return Response(response, status=status_code)

# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Remove Address", query_serializer=AddressDeleteSerializer, tags=['Account'])
# 	def delete(self, request, *args, **kwargs):
# 		response = {}
# 		status_code = 200
# 		data = request.GET
# 		user_id = request.user.id
# 		# data = data.copy()
# 		pk = data.get('address_id');
# 		is_defalult=False
# 		try:
# 			useradd_instance = UserAddress.objects.get(id=pk)
# 			is_defalult = useradd_instance.isdefault
# 			useradd_instance.isdeleted=True
# 			useradd_instance.isactive=False
# 			useradd_instance.isdefault=False
# 			useradd_instance.save()
# 			if is_defalult:
# 				first_ins = UserAddress.objects.filter(
# 					user_id=user_id,
# 					isdefault=False,
# 					isdeleted=False,
# 					isactive=True
# 				).first()
# 				if first_ins:
# 					first_ins.isdefault=True
# 					first_ins.save()

# 			response["message"] = "Address deleted successfully"
# 		except Exception as e:
# 			response["errors"] = {"id":["Invalid User"]}
# 			status_code = 400
# 		return Response(response, status=status_code)

# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Change default address", request_body=AddressDeleteSerializer, tags=['Account'])
# 	def patch(self, request, *args, **kwargs):
# 		response = {}
# 		status_code = 200
# 		data = request.data
# 		user_id = request.user.id
# 		# data = data.copy()
# 		pk = data.get('address_id')
# 		is_defalult=False
# 		try:
# 			useradd_instance = UserAddress.objects.get(id=pk)
# 			is_defalult = useradd_instance.isdefault
# 			if not is_defalult:
# 				first_ins = UserAddress.objects.filter(
# 					user_id=user_id,
# 					isdefault=True,
# 					isdeleted=False,
# 					isactive=True
# 				).first()
# 				if first_ins:
# 					first_ins.isdefault=False
# 					first_ins.save()
# 			useradd_instance.isdefault = True
# 			useradd_instance.save()
# 			response["message"] = "Default address updated"
# 		except Exception as e:
# 			response["errors"] = {"address_id":["Invalid Address Id"]}
# 			status_code = 400
# 		return Response(response, status=status_code)

# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Get address list api",query_serializer=AddressListSerializer,tags=['Account'])
# 	def get(self, request, *args, **kwargs):
# 		response = {}
# 		data = request.GET
# 		data = data.copy()
# 		user_id = request.user.id
# 		data.update({
# 			"user_id":user_id
# 		})
# 		data_validation = AddressListSerializer(data=data)
# 		is_valid_data = data_validation.is_valid()

# 		if is_valid_data:
# 			data = data_validation.validated_data
# 			limit = data.get("limit")
# 			page = data.get("page")
# 			search_text = data.get("search", "")
# 			order = data.get("order")
# 			offset = (page - 1) * limit
# 			newLimit = (page * limit)
# 			filterquery = Q(
# 				isdeleted=False,
# 				isactive=True,
# 				user_id=user_id
# 			)
# 			if search_text:
# 				filterquery.add(
# 					Q(first_name__icontains=search_text) |
# 					Q(phone__istartswith=search_text) |
# 					Q(street_name__icontains=search_text),
# 					Q.AND
# 				)
# 			filter_data = UserAddress.objects.filter(
# 				filterquery
# 			).order_by(
# 				order
# 			).values()[offset:newLimit]
# 			total = UserAddress.objects.filter(filterquery).count()
# 			status_code = 200
# 			response["total"] = total
# 			response['result'] = filter_data
# 			response['length'] = len(filter_data)
# 		else:
# 			status_code = 400
# 			response["errors"] = data_validation.errors
# 		return Response(response, status=status_code)

# class AddressByIDView(GenericAPIView):
# 	"""
# 		get the particular address data by providing address id
# 	"""
# 	queryset = UserAddress.objects
# 	permission_classes = (IsAuthenticated,)
# 	serializer_class = AddressByIdSerializer
# 	@classmethod
# 	@swagger_auto_schema(operation_summary="Get address list api",query_serializer=AddressByIdSerializer,tags=['Account'])
# 	def get(self, request, *args, **kwargs):
# 		response = {}
# 		data = request.GET
# 		data = data.copy()
# 		user_id = request.user.id
# 		pk = kwargs.get("pk")
# 		data.update({
# 			"user_id":user_id,
# 			"address_id":pk
# 		})
# 		data_validation = AddressByIdSerializer(data=data)
# 		is_valid_data = data_validation.is_valid()

# 		if is_valid_data:
# 			data = data_validation.validated_data
# 			user_id = data.get("user_id")
# 			address_id = data.get("address_id")
# 			fields =[
# 				"first_name","last_name","phone","alternate_phone","appartment_name","street_name",
# 				"delivery_remark","address_type","city_name","state_name","pincode","isdefault"
# 			]
# 			address_data = UserAddress.objects.filter(
# 				id=address_id
# 			).values(*fields).first()
				
# 			status_code = 200
# 			response['result'] = address_data
# 		else:
# 			status_code = 400
# 			response["errors"] = data_validation.errors
# 		return Response(response, status=status_code)

class ChangePasswordView(GenericAPIView):
	"""
		change the password with new password
	"""
	# model = User
	queryset = User.objects
	permission_classes = (IsAuthenticated,)
	serializer_class = ChangePasswordSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Change password api", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		data =request.data
		pk = kwargs.get("pk")
		data.update({
			"id":pk
		})
		status_code = 200
		data_validation = ChangePasswordSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			instance = CreateOrUpdate.changepassword(
				self,
				data
			)
			if instance:
				response["message"] = "password change successfully"
			else:
				status_code = 400
				response["errors"] = {"current_password":["something went wrong"]}
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class ForgetPasswordView(GenericAPIView):
	"""
		forget password send new password on given email id
	"""
	permission_classes = (AllowAny,)
	serializer_class = ForgetPasswordSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Forget password api", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		data =request.data
		status_code = 200
		data_validation = ForgetPasswordSerializer(data=data)
		request_origin_data = request.META.get("HTTP_ORIGIN")
		request_origin = None
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			username = data.get("username")
			user = User.objects.filter(
				Q(username__exact=username) |
				Q(email__exact=username),
				Q(is_active=True)
			).last()
			# instance = CreateOrUpdate.forgetpassword(
			# 	self,
			# 	data
			# )
			if user:
				user_id = urlsafe_base64_encode(smart_bytes(user.id))
				token = PasswordResetTokenGenerator().make_token(user)
				frnt_url=settings.FRONTEND_URL
				if request_origin_data:
					frnt_url = request_origin_data+"/"
				data_to_send = frnt_url+'new-password?key=' + str(user_id)+'&token='+ str(token)
				"""
					send email with link
				"""
				message = send_email(
					to_emails= user.email,
					subject='Reset Password',
					html_content='Hi '+user.first_name+',<br> <a href ="'+data_to_send+'">Click here </a> to reset the password </b> <br><br><br><br><br><br> Thank you'
				)
				print("data_to_send= ",data_to_send)
				response["message"] = "Reset link is sent to your email"
			else:
				status_code = 400
				response["errors"] = {"username":["something went wrong"]}
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class ResetPasswordView(GenericAPIView):
	"""
		Reset password API
	"""
	permission_classes = (AllowAny,)
	serializer_class = ResetPasswordSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Reset password api", tags=['Account'])
	def post(self, request, *args, **kwargs):
		response = {}
		data =request.data
		status_code = 200
		data_validation = ResetPasswordSerializer(data=data)
		is_valid_data = data_validation.is_valid()
		if is_valid_data:
			data = data_validation.validated_data
			key = data.get("key")
			token = data.get("token")
			password = data.get("password")
			try:
				user_id = force_str(urlsafe_base64_decode(key))
				user = User.objects.get(id=user_id)
				if not PasswordResetTokenGenerator().check_token(user, token):
					raise Exception('Link has been Expired', 401)
				else:
					user.set_password(password)
					user.save()
					response["message"] = "new password is save successfully"
			except Exception as e:
				status_code = 401
				response["errors"] = {"token":["Link has been Expired"]}
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)


class DocumentUploadView(GenericAPIView):
	"""
		Document uploaded in database
	"""
	parser_classes = (MultiPartParser,)
	permission_classes = [IsAuthenticated]
	serializer_class = DocumentUploadSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Document uploaded",tags=['Admin'])
	# @permission_check
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data = data.copy()
		data_validation = DocumentUploadSerializer(data=data)
		is_valid_data = data_validation.is_valid()

		if is_valid_data:
			data = data_validation.validated_data
			document = data.get("document")
			try:
				DocumentUpload.objects.create(
					document=document,
				)
				response['result'] = "Document uploaded Succesfully"
			except Exception as e:
				response["errors"] = {"error":[str(e)]}
				status_code = 400
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class DocumentListView(GenericAPIView):
	"""
		Admin product List api
	"""
	permission_classes = (IsAuthenticated,)
	serializer_class = DocumentListSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Admin Product List",query_serializer=DocumentListSerializer,tags=['Admin'])
	# @permission_check
	def get(myself, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.GET
		data = data.copy()
		data_validation = DocumentListSerializer(data=data)
		is_valid_data = data_validation.is_valid()

		if is_valid_data:
			data = data_validation.validated_data
			limit = data.get("limit")
			page = data.get("page")
			search_text = data.get("search", "")
			order = data.get("order")
			fields = [
					"id","document"
				]

			order = getorderColumn(order,fields)
			offset = (page - 1) * limit
			newLimit = (page * limit)
			"""
				query to get product list
			"""
			filterquery = Q()

			if search_text:
				filterquery.add(
					Q(document__icontains=search_text),
					Q.AND
				)
			pro_list = DocumentUpload.objects.filter(
				filterquery
			).values(*fields)
			total = pro_list.count()
			res= pro_list.order_by(order)[offset:newLimit]
			response["result"] = res
			response["length"]= len(res)
			response["total"] = total
			
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)


class CreatePackageView(GenericAPIView):
	"""
		create package in database
	"""
	parser_classes = (MultiPartParser,)
	permission_classes = [IsAuthenticated]
	serializer_class = CreatePackageSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="create package",tags=['Admin'])
	# @permission_check
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data = data.copy()
		data_validation = CreatePackageSerializer(data=data)
		is_valid_data = data_validation.is_valid()

		if is_valid_data:
			data = data_validation.validated_data
			try:
				PackageModel.objects.create(
					image=data.get("image"),
					price=data.get("price"),
					description=data.get("description"),
				)
				response['result'] = "Package created succesfully"
			except Exception as e:
				response["errors"] = {"error":[str(e)]}
				status_code = 400
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

class PackageListView(GenericAPIView):
	"""
		Admin package List api
	"""
	permission_classes = (IsAuthenticated,)
	serializer_class = DocumentListSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="Admin package List",query_serializer=DocumentListSerializer,tags=['Admin'])
	# @permission_check
	def get(myself, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.GET
		data = data.copy()
		data_validation = DocumentListSerializer(data=data)
		is_valid_data = data_validation.is_valid()

		if is_valid_data:
			data = data_validation.validated_data
			limit = data.get("limit")
			page = data.get("page")
			order = data.get("order")
			fields = [
					"id","image",'price', 'description'
				]

			order = getorderColumn(order,fields)
			offset = (page - 1) * limit
			newLimit = (page * limit)
			"""
				query to get product list
			"""
			filterquery = Q()

			pro_list = PackageModel.objects.filter(
				filterquery
			).values(*fields)
			total = pro_list.count()
			res= pro_list.order_by(order)[offset:newLimit]
			response["result"] = res
			response["length"]= len(res)
			response["total"] = total
			
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)


class CreatePackageOrderView(GenericAPIView):
	"""
		create package in database
	"""
	parser_classes = (MultiPartParser,)
	permission_classes = [IsAuthenticated]
	serializer_class = CreatePackageOrderSerializer

	@classmethod
	@swagger_auto_schema(operation_summary="create package",tags=['Admin'])
	# @permission_check
	def post(self, request, *args, **kwargs):
		response = {}
		status_code = 200
		data = request.data
		data = data.copy()
		data_validation = CreatePackageOrderSerializer(data=data)
		is_valid_data = data_validation.is_valid()

		if is_valid_data:
			data = data_validation.validated_data
			try:
				PackageModel.objects.create(
					user_id=data.get("user_id"),
					package_id=data.get("package_id"),
					total_price=data.get("total_price"),
				)
				response['result'] = "Package order created succesfully"
			except Exception as e:
				response["errors"] = {"error":[str(e)]}
				status_code = 400
		else:
			status_code = 400
			response["errors"] = data_validation.errors
		return Response(response, status=status_code)

