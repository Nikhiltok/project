from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from customer.accounts.accounts_model.models import UserProfile
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import *
from django.utils.encoding import *


class PGuestLoginSerializer(serializers.Serializer):
	device_id = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):

		errors = {}
		if errors:
			raise serializers.ValidationError(errors)

		return super(PGuestLoginSerializer, self).validate(self, data)


class PLoginSerializer(serializers.Serializer):
	username = serializers.CharField(
		required=True
	)
	password = serializers.CharField(
		required=True
	)
	device_id = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors = {}
		username = data.get("username").lower()
		filterquery = Q()
		filterquery.add( 
			Q(userprofile__otp_status=True) &
			Q(userprofile__user_type=3) & 
			Q(is_active=True),
			Q.AND
		)
		if username.isdigit():
			filterquery.add(
			Q(userprofile__phone__exact=username),
			Q.AND
		)
		else:
			filterquery.add(
			Q(username__exact=username + '_p') &
			Q(email__exact=username),
			Q.AND
		)
		instance = User.objects.filter(
			filterquery
		).last()
		if not instance:
			errors["username"] = "This username does not exist."
		if errors:
			raise serializers.ValidationError(errors)

		return super(PLoginSerializer, self).validate(self, data)		


class PMyRefreshSerializer(serializers.Serializer):
	refresh = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors = {}
		try:
			valid_token = TokenRefreshSerializer.validate(self,data)
		except:
			errors["refresh"] = "Refresh token is invalid or expired."
		if errors:
			raise serializers.ValidationError(errors)

		return super(PMyRefreshSerializer, self).validate(self, data)


class PSignupSerializer(serializers.Serializer):
	first_name = serializers.CharField(
		required=True,
		min_length=2
	)
	last_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	email = serializers.EmailField(
		required=True
	)
	callingcode = serializers.IntegerField(
		min_value=1,
		max_value=999,
		default=91
	)
	phone = serializers.IntegerField(
		required=True
	)
	alternate_phone = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	address = serializers.CharField(
		required=True,
	)
	city_name = serializers.CharField(
		required=True,
	)
	state_name = serializers.CharField(
		required=True,
	)
	pincode = serializers.CharField(
		required=True,
	)
	password = serializers.CharField(
		required=True,
		min_length=6
	)
	password_confirm = serializers.CharField(
		required=True,
		min_length=6
	)
	terms_condition_privacy = serializers.BooleanField(
		required=True
	)

	@classmethod
	def validate(self, data):

		errors = {}

		username = str(data.get("email")).lower()
		phone = data.get("phone")
		password = data.get("password")
		password_confirm = data.get("password_confirm")
		terms_condition_privacy = data.get("terms_condition_privacy")
		if not phone:
			errors["phone"]="Please Enter your Phone Number"
		if not terms_condition_privacy:
			errors["terms_condition_privacy"] = "Please check Terms and Conditions"
		
		filterquery = Q()
		filterquery.add(
			Q(userprofile__otp_status=True) &
			Q(userprofile__isactive=True),
			Q.AND
		)
		username1 = str(username).lower() + '_p'
		filterquery.add(
			Q(username__exact= username1)|
			Q(userprofile__phone__exact=phone),
			# Q(email__exact=username),
			Q.AND
		)
		instance = User.objects.filter(
			filterquery
		).last()
		if instance:
			if (instance.email == username):
				errors["email"] = "This email already exists."
			if (instance.userprofile.phone == phone):
				errors["phone"] = "This phone number already exists."
		if password != password_confirm:
			errors["password"] = "password and confirmation do not match"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PSignupSerializer, self).validate(self, data)

class POTPSerializer(serializers.Serializer):
	phone = serializers.IntegerField(
		required=True
	)
	device_id = serializers.CharField(
		required=True
	)

	@classmethod
	def validate(self, data):
		errors = {}
		phone = data.get("phone")
		store_id = data.get("store_id")
		instance = UserProfile.objects.filter(
			phone=phone,
			otp_status=False,
			store_id=store_id,
		).last()
		if not instance:
			errors["id"] = "Invalid Attempt"
		if errors:
			raise serializers.ValidationError(errors)

		return super(POTPSerializer, self).validate(self, data)

class POTPSendSerializer(serializers.Serializer):
	phone = serializers.IntegerField(
		required=True
	)
	device_id = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors = {}
		phone = data.get("phone")
		instance = UserProfile.objects.filter(
			phone=phone,
		).last()
		if instance:
			errors["id"] = "This Phone Number is already in use"
		if errors:
			raise serializers.ValidationError(errors)

		return super(POTPSendSerializer, self).validate(self, data)

class PVerifyOTPSerializer(POTPSerializer):
	otp = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors = {}
		if errors:
			raise serializers.ValidationError(errors)

		return super(PVerifyOTPSerializer, self).validate(data)

class PVerifyPhoneOTPSerializer(POTPSendSerializer):
	otp = serializers.CharField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors = {}
		if errors:
			raise serializers.ValidationError(errors)

		return super(PVerifyPhoneOTPSerializer, self).validate(data)

class PProfileSerializer(serializers.Serializer):
	id = serializers.IntegerField(
		required=True
	)
	first_name = serializers.CharField(
		required=True,
		min_length=2
	)
	last_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	email = serializers.EmailField(
		required=True
	)
	callingcode = serializers.IntegerField(
		required=True,
		min_value=1,
		max_value=999
	)
	phone = serializers.IntegerField(
		required=True
	)
	alternate_phone = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	images = serializers.ImageField(
		required=False,
		allow_null=True
	)
	address = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	delivery_remark = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	street_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	city_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	state_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	country = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	pincode = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	current_password = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
		min_length=6
	)
	new_password = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
		min_length=6
	)
	new_password_confirm = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
		min_length=6
	)

	@classmethod
	def validate(self, data):

		errors = {}
		id = data.get("id")
		username = data.get("email")
		phone = data.get("phone")
		pincode = data.get("pincode")
		city = data.get('city')
		state = data.get('state')
		country = data.get("country")
		current_password = data.get("current_password")
		new_password = data.get("new_password")
		new_password_confirm = data.get("new_password_confirm")
		id_exists = User.objects.filter(
			id=id,
			userprofile__isdeleted=False,
			userprofile__isactive=True
		).last()
		if not id_exists:
			errors["id"] ="Invalid user"
		filterquery = Q()
		if username.isdigit():
			filterquery.add(
			Q(userprofile__phone__exact=username),
			Q.AND
		)
		else:
			filterquery.add(
			Q(username__exact=username) |
			Q(email__exact=username)&
			Q(userprofile__is_employee=False),
			Q.AND
		)
		instance = User.objects.filter(
			filterquery
		)																
		# print(instance)
		instance = User.objects.filter(
			filterquery
		).exclude(id=id)
		if instance.exists():
			if (instance[0].email == username):
				errors["email"] = "This email already exists."
			if (instance[0].userprofile.phone == phone):
				errors["phone"] = "This phone number already exists."
		if pincode and (pincode.isdigit() == False or len(pincode) != 5):
			errors["pincode"] = "Please enter correct pincode"
		if current_password and new_password and new_password_confirm:
			if new_password !=new_password_confirm:
				errors["new_password"] = "New password and confirmation do not match"
			elif not id_exists.check_password(current_password):
				errors["current_password"] = "current password is incorrect"

		if errors:
			raise serializers.ValidationError(errors)

		return super(PProfileSerializer, self).validate(self, data)


class PAddressSerializer(serializers.Serializer):
	first_name = serializers.CharField(
		required=True,
		min_length=2
	)
	last_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	user_id = serializers.IntegerField(
		required=True
	)
	phone = serializers.IntegerField(
		required=True
	)
	alternate_phone = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	appartment_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
	)
	street_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	delivery_remark = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
	)
	address_type = serializers.ChoiceField(
		required=True,
		choices=(
			("Home","Home"),
			("Work","Work"),
			("Other","Other"),
		)
	)
	callingcode = serializers.IntegerField(
		required=False,
		min_value=1,
		max_value=998,
		default=1
	)
	city_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	state_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	country = serializers.IntegerField(
		required=False,
		allow_null=True,
	)
	pincode = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
	)

	@classmethod
	def validate(self, data):

		errors = {}
		user_id = data.get("user_id")
		phone = data.get("phone")
		pincode = data.get("pincode")
		id_exists = User.objects.filter(
			id=user_id,
			userprofile__isdeleted=False,
			userprofile__isactive=True,
		).exists()
		if not id_exists:
			errors["user_id"] ="Invalid user"
		if pincode and (pincode.isdigit() == False or len(pincode) != 5):
			errors["pincode"] = "Please enter correct pincode"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PAddressSerializer, self).validate(self, data)


class PAddressUpdateSerializer(serializers.Serializer):
	user_id = serializers.IntegerField(
		required=True
	)
	first_name = serializers.CharField(
		required=True,
		min_length=2
	)
	last_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	callingcode = serializers.IntegerField(
		required=False,
		min_value=1,
		max_value=999,
		default=1
	)
	phone = serializers.IntegerField(
		required=True
	)
	id = serializers.IntegerField(
		required=True
	)
	alternate_phone = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	appartment_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	street_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	delivery_remark = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	address_type = serializers.ChoiceField(
		required=True,
		choices=(
			("Home","Home"),
			("Work","Work"),
			("Other","Other")
		)
	)
	city_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	state_name = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)
	country = serializers.IntegerField(
		required=False,
		allow_null=True
	)
	pincode = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True
	)

	@classmethod
	def validate(self, data):

		errors = {}
		id = data.get("id")
		user_id = data.get("user_id")
		phone = data.get("phone")
		pincode = data.get("pincode")
		address_exists = UserAddress.objects.filter(
			id=id,
			isactive=True,
			isdeleted=False
		).exists()
		if not address_exists:
			errors["id"] ="Invalid address Id"
		id_exists = User.objects.filter(
			id=user_id,
			userprofile__isdeleted=False,
			userprofile__isactive=True,
		).exists()
		if not id_exists:
			errors["user_id"] ="Invalid user"
		if pincode and (pincode.isdigit() == False or len(pincode) != 5):
			errors["pincode"] = "Please enter correct pincode"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PAddressUpdateSerializer, self).validate(self, data)


class PAddressDeleteSerializer(serializers.Serializer):
	address_id = serializers.IntegerField(
		required=True
	)
	
	@classmethod
	def validate(self, data):
		errors = {}
		if errors:
			raise serializers.ValidationError(errors)

		return super(PAddressDeleteSerializer, self).validate(self, data)

class PAddressListSerializer(serializers.Serializer):
	search = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
		max_length=250,
		help_text="Pass search keyword here. Leave blank if do not want to search."
	)
	limit = serializers.IntegerField(
		required=False,
		min_value=1,
		default=10,
		help_text="Pass limit in integer. Default is 10."
	)
	page = serializers.IntegerField(
		required=False,
		min_value=1,
		default=1
	)
	order = serializers.CharField(
		required=False,
		max_length=250,
		default="id",
		help_text="Pass field name for ordering. Use '-' before field name to order descending. Default order is ID."
	)
	user_id= serializers.IntegerField(
		required=True,
		help_text="Pass 0 in this field."
	)
	store_address = serializers.BooleanField(
		required=False,
		default=False
	)

	@classmethod
	def validate(self, data):
		errors = {}
		user_id= data.get("user_id")
		id_exists = User.objects.filter(
			id=user_id,
			userprofile__isdeleted=False,
			userprofile__isactive=True,
			userprofile__is_employee=False
		).exists()
		if not id_exists:
			errors["user_id"] ="Invalid user"

		if errors:
			raise serializers.ValidationError(errors)

		return super(PAddressListSerializer, self).validate(self, data)

class PAddressByIdSerializer(serializers.Serializer):
	address_id = serializers.IntegerField(
		required=True
	)
	user_id = serializers.IntegerField(
		required=True
	)
	@classmethod
	def validate(self, data):
		errors= {}
		user_id = data.get("user_id")
		address_id = data.get("address_id")
		address_exists = UserAddress.objects.filter(
			id=address_id,
			user_id=user_id,
			isdeleted=False,
			isactive=True,
		).exists()
		if not address_exists:
			errors["address_id"] = "Invalid Address Id"
		if errors:
			raise serializers.ValidationError(errors)
		return super(PAddressByIdSerializer, self).validate(self, data)



class PUserSerializer(serializers.ModelSerializer):
	class Meta:
		model = User
		fields = ("id",'username', "email", "password")

class PTokenSerializer(serializers.Serializer):
	"""
	This serializer serializes the token data
	"""
	token = serializers.CharField(max_length=255)


class PChangePasswordSerializer(serializers.Serializer):
	id = serializers.IntegerField(
		required=True,
		help_text="enter 0 in this field in body data"
	)
	current_password = serializers.CharField(
		required=True,
		min_length=6
	)
	new_password = serializers.CharField(
		required=True,
		min_length=6
	)
	new_password_confirm = serializers.CharField(
		required=True,
		min_length=6
	)

	@classmethod
	def validate(self, data):

		errors = {}
		id = data.get("id")
		current_password = data.get("current_password")
		new_password = data.get("new_password")
		new_password_confirm = data.get("new_password_confirm")
		
		id_ins = User.objects.filter(
			id=id
		).last()
		if not id_ins:
			errors["id"] ="Invalid Id"
		else:
			if not id_ins.check_password(current_password):
				errors["current_password"] = "current password is not correct"

		if new_password != new_password_confirm:
			errors["new_password"] = "password and confirmation do not match"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PChangePasswordSerializer, self).validate(self, data)

class PForgetPasswordSerializer(serializers.Serializer):
	username = serializers.CharField(
		required=True,
		min_length=6
	)

	@classmethod
	def validate(self, data):

		errors = {}
		username = data.get("username")
		id_ins = User.objects.filter(
			Q(username__exact=username) |
			Q(email__exact=username),
			Q(is_active=True)
		).last()
		if not id_ins:
			errors["username"] ="Invalid Username"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PForgetPasswordSerializer, self).validate(self, data)

class PResetPasswordSerializer(serializers.Serializer):
	key = serializers.CharField(
		required=True
	)
	token = serializers.CharField(
		required=True
	)
	password = serializers.CharField(
		required=True,
		min_length=6
	)
	confirm_password = serializers.CharField(
		required=True,
		min_length=6
	)

	@classmethod
	def validate(self, data):

		errors = {}
		password = data.get("password")
		confirm_password = data.get("confirm_password")
		
		if password != confirm_password:
			errors["confirm_password"] = "Password and Confirmation do not patch"
		if errors:
			raise serializers.ValidationError(errors)

		return super(PResetPasswordSerializer, self).validate(self, data)
