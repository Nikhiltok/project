#create_or_update.py
from rest_framework.generics import GenericAPIView
from customer.accounts.accounts_model.models import UserProfile
from django.contrib.auth.models import User
from django.db.models import Q
from customer.common.views import *
import random
import string
from django.conf import settings
import os
class CreateOrUpdate(GenericAPIView):
	@staticmethod
	def UserCreateOrUpdate(self, data):
		instance = None
		sms_flag=True
		if data.get('id'):
			instance = UserProfile.objects.filter(
				user_id=data.get('id'),
			).last()
		else:
			username1 = str(data.get("email")).lower() + '_p'
			instance = UserProfile.objects.filter(
				Q(phone=data.get('phone'))|
				Q(user__email=data.get("email")),
				Q(user__username=username1),
			).last()
		if not instance:
			otp = random.randint(1000,9999)
			username = data.get("email") + '_p'
			user = User.objects.create_user(
					username.lower(),
					data.get("email").lower(),
					data.get("password")
				)
			phone=data.get('phone')
			instance = UserProfile.objects.create(
				phone=phone,
				otp="1234",
				otp_status=True,
				user=user
			)
			user.is_active=True

		else:
			user = User.objects.filter(
				id=instance.user_id
			).last()
			instance.phone = data.get('phone')
			user.username = (data.get('email')).lower()
			user.email = data.get('email').lower()
			if data.get('password') and data.get('id') is None:
				user.set_password(data.get('password'))
			if data.get('new_password') and data.get("id") is not None:
				user.set_password(data.get('new_password'))
		
		user.first_name = data.get("first_name")
		user.last_name = data.get("last_name")
		user.save()
		instance.full_name = data.get("first_name")+" "+data.get("last_name")
		instance.callingcode = data.get("callingcode")
		instance.phone = data.get("phone")
		if instance.images:
			filename =settings.BASE_DIR+'/media/'+str(instance.images)
			if os.path.exists(filename):
				os.remove(filename)
		instance.images = data.get("images")
		instance.isactive=True
		instance.isdeleted=False
		instance.user_type=3
		instance.alternate_phone=data.get('alternate_phone')
		instance.address=data.get('address')
		instance.street_name=data.get('street_name')
		instance.city_name=data.get('city_name')
		instance.state_name=data.get('state_name')
		instance.pincode=data.get('pincode')
		instance.save()
		return user

	@staticmethod
	def VerifyOtp(self, data):
		phone=data.get("phone")
		# otp=data.get('otp')
		user = UserProfile.objects.filter(
				phone=phone
			).last()
		if user:
			user.otp_status=True
			user.save()
		return user

	@staticmethod
	def changepassword(self, data):
		id=data.get("id")
		new_password = data.get("new_password")
		user = User.objects.filter(id=id).last()
		if user:
			user.set_password(new_password)
			user.save()
		return user

	@staticmethod
	def get_random_password_string(length):
		password_characters = string.ascii_letters + string.digits
		password = ''.join(random.choice(password_characters) for i in range(length))
		# print("Random string password is:", password)
		return password

	# @staticmethod
	# def UserAddressCreateOrUpdate(self, data):
	# 	instance = None
	# 	if data.get('id'):
	# 		instance = UserAddress.objects.filter(
	# 			id=data.get('id')
	# 		).last()

	# 	if not instance:
	# 		address_count = UserAddress.objects.filter(
	# 			user_id=data.get("user_id"),
	# 			isactive=True,
	# 			isdeleted=False
	# 		).count()
	# 		instance = UserAddress.objects.create(
	# 			user_id=data.get("user_id")
	# 		)
	# 		instance.isdefault = False
	# 		if address_count < 1:
	# 			instance.isdefault = True
	# 	instance.first_name = data.get("first_name")
	# 	instance.last_name = data.get("last_name")
	# 	instance.appartment_name = data.get("appartment_name")
	# 	instance.street_name = data.get("street_name")
	# 	instance.delivery_remark = data.get("delivery_remark")
	# 	instance.address_type = data.get("address_type")
	# 	instance.callingcode = data.get("callingcode")
	# 	instance.phone = data.get("phone")
	# 	instance.isactive=True
	# 	instance.isdeleted=False
	# 	instance.alternate_phone=data.get('alternate_phone')
	# 	instance.city_name=data.get('city_name')
	# 	instance.state_name=data.get('state_name')
	# 	instance.pincode=data.get('pincode')
	# 	instance.save()
	# 	return instance

