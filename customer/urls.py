from django.urls import path, include
from customer import views

urlpatterns = [
	path(
		'create-super-user/',
		views.CreateSuperUser,
		name="create_super_user"
	),
	path(
		'create-guest-user/',
		views.CreateGuestUser,
		name="create_guest_user"
	),
	path(
		'account/',
		include(
			"customer.accounts.urls"
		)
	),
]