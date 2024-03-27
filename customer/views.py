from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from customer.accounts.accounts_model.models import UserProfile
from django.contrib.auth.models import User
from django.http import HttpResponse

# Create your views here.
def ApiIndexView(request):
	return HttpResponse("<h1>Welcome to APIs by Developed by Nishant </h1>")

# http://localhost:8001/api/customer/create-super-user/?username=admin@navsoft.in&phone=000000&password=123456&key=1234567890

def CreateSuperUser(request):
	username = request.GET.get("username")
	phone = request.GET.get("phone")
	password = request.GET.get("password")
	key = request.GET.get("key")
	envkey = settings.SUPERUSERKEY
	if key != envkey:
		return HttpResponse("Not valid Request")
	user = User.objects.filter(
		username=username
	).last()
	if not user:
		user = User.objects.create_user(
			username,
			username,
			password
		)
	user.is_active = True
	user.is_staff = True
	user.is_superuser = True
	user.set_password(password)
	user.save()
	userprofile = UserProfile.objects.filter(
		user = user.id
	).last()
	if not userprofile:
		userprofile = UserProfile.objects.create(
			user = user
		)
	userprofile.phone = phone
	userprofile.callingcode=1
	userprofile.full_name='admin'
	userprofile.user_type=1
	userprofile.otp_status=True
	userprofile.save()


	return HttpResponse("Created")

def CreateGuestUser(request):
	username = "guest@guest.com"
	phone = 0000000000
	password = "guest"

	user = User.objects.filter(
		username=username
	).last()
	if not user:
		user = User.objects.create_user(
			username,
			username,
			password
		)
	user.is_active = True
	user.is_staff = False
	user.is_superuser = False
	user.set_password(password)
	user.save()
	userprofile = UserProfile.objects.filter(
		user = user.id
	).last()
	if not userprofile:
		userprofile = UserProfile.objects.create(
			user = user
		)
	userprofile.isdeleted=True
	userprofile.isactive=False
	userprofile.phone = phone
	userprofile.callingcode=1
	userprofile.full_name='Guest'
	userprofile.otp_status=True
	userprofile.save()


	return HttpResponse("Created")

