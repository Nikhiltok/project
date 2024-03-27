# Generated by Django 4.1.5 on 2024-03-18 16:42

import customer.accounts.accounts_model.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DocumentUpload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.FileField(blank=True, null=True, upload_to=customer.accounts.accounts_model.models.get_upload_path_document)),
                ('status', models.CharField(blank=True, max_length=15, null=True)),
                ('isdeleted', models.BooleanField(default=False)),
                ('isactive', models.BooleanField(default=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('updated_date', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='PackageModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(blank=True, null=True, upload_to=customer.accounts.accounts_model.models.get_upload_path_package)),
                ('price', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('isdeleted', models.BooleanField(default=False)),
                ('isactive', models.BooleanField(default=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('updated_date', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_type', models.CharField(choices=[('1', 'Customer'), ('2', 'Admin'), ('3', 'Partnar')], default='1', help_text=' User type (Customer, Admin, Partnar)', max_length=20)),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('callingcode', models.IntegerField(blank=True, null=True)),
                ('phone', models.BigIntegerField(blank=True, null=True)),
                ('alternate_phone', models.BigIntegerField(blank=True, null=True)),
                ('images', models.ImageField(blank=True, null=True, upload_to='upload/userprofile')),
                ('terms_condition_privacy', models.BooleanField(default=False)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('street_name', models.CharField(blank=True, max_length=255, null=True)),
                ('delivery_remark', models.CharField(blank=True, max_length=255, null=True)),
                ('city_name', models.CharField(blank=True, max_length=255, null=True)),
                ('state_name', models.CharField(blank=True, max_length=255, null=True)),
                ('pincode', models.CharField(blank=True, max_length=30, null=True)),
                ('otp', models.CharField(blank=True, max_length=30, null=True)),
                ('otp_status', models.BooleanField(default=False)),
                ('isdeleted', models.BooleanField(default=False)),
                ('isactive', models.BooleanField(default=True)),
                ('is_user_activate', models.BooleanField(default=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('updated_date', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('updated_by', models.IntegerField(blank=True, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PackageOrder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order_status', models.CharField(blank=True, max_length=15, null=True)),
                ('total_price', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('package', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='package_order_package', to='customer.packagemodel')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='package_order_user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]