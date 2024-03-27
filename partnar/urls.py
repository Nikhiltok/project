from django.urls import path, include
from partnar import views

urlpatterns = [
	path(
		'account/',
		include(
			"partnar.accounts.urls"
		)
	),
]