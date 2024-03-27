from django.db import models
from django.contrib.auth.models import User
from customer.accounts.accounts_model import PackageModel

class PartnarCommition(models.Model):	
	user = models.ForeignKey(
		User,
		related_name="partnar_commision_user",
		on_delete=models.CASCADE,
		null=True,
		blank=True
	)
	package = models.ForeignKey(
		PackageModel,
		related_name="partnar_commision_package",
		on_delete=models.CASCADE,
		null=True,
		blank=True
	)
	order_status = models.CharField(
		max_length=15,
		null=True,
		blank=True
	)
	commision = models.DecimalField(
		max_digits=10, 
		decimal_places=2,
		null=True,
		blank=True
	)