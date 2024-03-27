from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from django.db.models import Q,F
from django.contrib.auth.models import User
# from superadmin.models import *

class UserInfo(GenericAPIView):

	@staticmethod
	def Details(self, userInfo):
		try:
			# name = userInfo.username
			firstName = userInfo.first_name
			lastName = userInfo.last_name
			email=userInfo.email
			phone = userInfo.userprofile.phone
			callingcode = userInfo.userprofile.callingcode
			images = str(userInfo.userprofile.images)
			alternate_phone = userInfo.userprofile.alternate_phone
			address = userInfo.userprofile.address
			city_name = userInfo.userprofile.city_name
			state_name = userInfo.userprofile.state_name
			country = userInfo.userprofile.country_id
			country_name = userInfo.userprofile.country.name if country is not None else ""
			pincode = userInfo.userprofile.pincode
			street_name = userInfo.userprofile.street_name
			delivery_remark = userInfo.userprofile.delivery_remark
		except Exception as e:
			print(e)
			firstName = ""
			lastName = ""
			email = ""
			phone = ""
			callingcode=""
			images = ""
			alternate_phone=""
			address=""
			city_name=""
			state_name=""
			country=""
			pincode=""
			delivery_remark=""
			street_name=""

		result = {
			"firstName": firstName,
			"lastName": lastName,
			"email": email,
			"callingcode":callingcode,
			"phone":phone,
			"images":images,
			"alternate_phone":alternate_phone,
			"address":address,
			"street_name":street_name,
			"delivery_remark":delivery_remark,
			"city_name":city_name,
			"state_name":state_name,
			"country":{
				"id":country,
				"name":country_name
			},
			"pincode":pincode

		}
		return result

		
		



