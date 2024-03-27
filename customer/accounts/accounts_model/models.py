from django.db import models
from django.contrib.auth.models import User
import os
class UserProfile(models.Model):
	USER_TYPE=  (
    ('1', 'Customer'),
    ('2', 'Admin'),
    ('3', 'Partnar')
    
	)
	user = models.OneToOneField(
		User,
		on_delete=models.CASCADE
	)
	user_type = models.CharField(
		help_text=" User type (Customer, Admin, Partnar)", 
		choices=USER_TYPE, default='1', 
		max_length=20
		)
	full_name = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	callingcode = models.IntegerField(
		null=True,
		blank=True
	)
	phone = models.BigIntegerField(
		null=True,
		blank=True
	)
	alternate_phone = models.BigIntegerField(
		null=True,
		blank=True
	)
	images = models.ImageField(
		upload_to='upload/userprofile',
		null=True,
		blank=True
	)
	terms_condition_privacy = models.BooleanField(
		default=False
	)
	address = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	street_name = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	delivery_remark = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	city_name = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	state_name = models.CharField(
		max_length=255,
		null=True,
		blank=True
	)
	pincode = models.CharField(
		max_length=30,
		null=True,
		blank=True
	)
	otp = models.CharField(
		max_length=30,
		null=True,
		blank=True
	)
	otp_status = models.BooleanField(
		default=False
	)
	isdeleted = models.BooleanField(
		default=False
	)
	isactive = models.BooleanField(
		default=True
	)
	is_user_activate = models.BooleanField(
		default=True
	)
	created_date = models.DateTimeField(
		auto_now_add=True
	)
	updated_date = models.DateTimeField(
		auto_now=True
	)
	created_by = models.IntegerField(
		null=True,
		blank=True
	)
	updated_by = models.IntegerField(
		null=True,
		blank=True
	)

	def __str__(self):
		return self.full_name

# class UserAddress(models.Model):
# 	user = models.ForeignKey(
# 		User, 
# 		on_delete=models.CASCADE,
# 		blank=True,
# 		null=True,
# 		related_name='user_address'
# 	)
# 	first_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	last_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	callingcode = models.IntegerField(
# 		null=True,
# 		blank=True
# 	)
# 	phone = models.BigIntegerField(
# 		null=True,
# 		blank=True
# 	)
# 	alternate_phone = models.BigIntegerField(
# 		null=True,
# 		blank=True
# 	)
# 	appartment_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	street_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	delivery_remark = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	address_type = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	city_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	state_name = models.CharField(
# 		max_length=255,
# 		null=True,
# 		blank=True
# 	)
# 	pincode = models.CharField(
# 		max_length=30,
# 		null=True,
# 		blank=True
# 	)
# 	isdefault = models.BooleanField(
# 		default=True
# 	)
# 	isdeleted = models.BooleanField(
# 		default=False
# 	)
# 	isactive = models.BooleanField(
# 		default=True
# 	)
# 	created_date = models.DateTimeField(
# 		auto_now_add=True
# 	)
# 	updated_date = models.DateTimeField(
# 		auto_now=True
# 	)
# 	created_by = models.IntegerField(
# 		null=True,
# 		blank=True
# 	)
# 	updated_by = models.IntegerField(
# 		null=True,
# 		blank=True
# 	)

# 	def __str__(self):
# 		return self.first_name


def get_upload_path_document(instance, filename):
    	return os.path.join(
		"upload/document", filename
	)
class DocumentUpload(models.Model):
	document = models.FileField(
		upload_to=get_upload_path_document,
		null=True,
		blank=True
	)
	status = models.CharField(
		max_length=15,
		null=True,
		blank=True
	)
	isdeleted = models.BooleanField(
		default=False
	)
	isactive = models.BooleanField(
		default=True
	)
	created_date = models.DateTimeField(
		auto_now_add=True
	)
	updated_date = models.DateTimeField(
		auto_now=True
	)


def get_upload_path_package(instance, filename):
    	return os.path.join(
		"upload/package", filename
	)
class PackageModel(models.Model):
	image = models.ImageField(
		upload_to=get_upload_path_package,
		null=True,
		blank=True
	)
	price = models.DecimalField(
		max_digits=10, 
		decimal_places=2,
		null=True,
		blank=True
	)
	description = models.TextField(
		null=True,
		blank=True
	)
	isdeleted = models.BooleanField(
		default=False
	)
	isactive = models.BooleanField(
		default=True
	)
	created_date = models.DateTimeField(
		auto_now_add=True
	)
	updated_date = models.DateTimeField(
		auto_now=True
	)

class PackageOrder(models.Model):	
	user = models.ForeignKey(
		User,
		related_name="package_order_user",
		on_delete=models.CASCADE,
		null=True,
		blank=True
	)
	package = models.ForeignKey(
		PackageModel,
		related_name="package_order_package",
		on_delete=models.CASCADE,
		null=True,
		blank=True
	)
	order_status = models.CharField(
		max_length=15,
		null=True,
		blank=True
	)
	total_price = models.DecimalField(
		max_digits=10, 
		decimal_places=2,
		null=True,
		blank=True
	)