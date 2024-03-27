from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from django.db.models import Q, F, Sum, Value,Case,When,BooleanField,CharField,ExpressionWrapper,DecimalField,Func,FilteredRelation,IntegerField
from django.db.models.functions import Concat, Coalesce
import datetime
from customer.models import *
from django.conf import settings
from basics.decorators.background import postpone
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail, From, Attachment, FileContent, FileName, FileType
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.postgres.aggregates import ArrayAgg
import json
import requests
from decimal import Decimal
# from twilio.rest import Client
import base64
import os
from django.db import connection

# sendgrid_api_key = settings.SANDGRID_APIKEY
class Round(Func):
	function = 'ROUND'
	arity = 2

# @postpone
# def send_email(to_emails,subject,html_content,store_sandgrid_apikey=None,store_from_email=None,store_from_name=None,file_path=None,file_name=None):
# 	## from_email should be verified in sandgrid
# 	## to verified emai go to https://app.sendgrid.com/settings/sender_auth/senders and create senders and verify
# 	from_email=settings.ADMIN_EMAIL
# 	from_name=''
# 	if store_from_email:
# 		from_email = store_from_email
# 	if store_from_name:
# 		from_name=store_from_name
# 	message = Mail(
# 		from_email=From(from_email,from_name),
# 		to_emails= to_emails,
# 		subject=subject,
# 		html_content=html_content
# 	)
# 	if file_path:
# 		with open(file_path, 'rb') as f:
# 			data = f.read()
# 			f.close()
# 		encoded = base64.b64encode(data).decode()
# 		attachment = Attachment()
# 		attachment.file_content = FileContent(encoded)
# 		attachment.file_type = FileType('application/pdf')
# 		attachment.file_name = FileName(str(file_name)+'.pdf')
# 		message.attachment = attachment
# 	try:
# 		if store_sandgrid_apikey:
# 			sg = SendGridAPIClient(store_sandgrid_apikey)
# 		else:
# 			sg = SendGridAPIClient(sendgrid_api_key)
# 		response = sg.send(message)
# 	except Exception as e:
# 		# print("exception")
# 		print(str(e))
# 		print("email not sent")

# 	return True


def retrieve_token(request,admin=False):
	tok_data = request.META.get("HTTP_AUTHORIZATION")
	jwt_object = JWTAuthentication()
	row_tok = tok_data.split(" ")[1]
	validated_token = jwt_object.get_validated_token(row_tok)
	if admin:
		store_id_auto = validated_token.get("store_id")
		return store_id_auto
	else:
		device_id = validated_token["device_id"]
		login_status = validated_token["login_status"]
		return (device_id,login_status)

def getorderColumn(order,fields):
	if order == '':
		order = '-id'
	else:
		fieldname = order
		if order[0] == '-':
			fieldname = order.split('-')[1]
		if len(fieldname) < 1 or not fieldname in fields:
			order = '-id'
	return order

# @postpone
# def send_sms(phone,store_id):
# 	# print("calling sms",phone,store_id)
# 	if phone and store_id:
# 		store_data = Store.objects.filter(id=store_id).last()
# 		if store_data and store_data.t_account_id and store_data.t_auth and store_data.t_service_id:
# 			try:
# 				account_sid = remove_extra_str(store_data.t_account_id)
# 				auth_token = remove_extra_str(store_data.t_auth)
# 				services_id = remove_extra_str(store_data.t_service_id)
# 				phone_number = "+1"+str(phone)
# 				client = Client(account_sid, auth_token)
# 				verification = client.verify.services(
# 					services_id
# 				).verifications.create(
# 					to=phone_number, channel='sms'
# 				)
# 				# print(verification.status)
# 			except:
# 				pass
# 	return True

# def check_otp(phone,store_id,code):
# 	return_data="pending"
# 	if phone and store_id:
# 		store_data = Store.objects.filter(id=store_id).last()
# 		if store_data and store_data.t_account_id and store_data.t_auth and store_data.t_service_id:
# 			try:
# 				account_sid = remove_extra_str(store_data.t_account_id)
# 				auth_token = remove_extra_str(store_data.t_auth)
# 				services_id = remove_extra_str(store_data.t_service_id )
# 				phone_number = "+1"+str(phone)
# 				client = Client(account_sid, auth_token)
# 				verification_check = client.verify.services(
# 					services_id
# 				).verification_checks.create(
# 					to=phone_number, code=code
# 				)
# 				# print(verification_check.status)
# 				return_data = str(verification_check.status)
# 			except:
# 				pass
# 	return return_data


def remove_extra_str(str_data):
	res_data =""
	if str_data:
		str_len = len(str_data) - 5
		str_data = str_data[:str_len]
		res_data = str_data[:2]+str_data[4:]
	return res_data

def delete_old_file(path_file):
    #Delete old file when upload new one
    if os.path.exists(path_file):
        os.remove(path_file)
