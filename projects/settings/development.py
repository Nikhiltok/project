from .base import *
import os
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
# SECRET_KEY = os.getenv("SECRET_KEY","")
ALLOWED_HOSTS = ["*"]
ENCRYPTION_KEY = '12345678'
INI_VEC = '2456789'
ENCRYPTION_REQUIRED = True


# DATABASES = {
# 	'default': {
# 		'ENGINE': 'django.db.backends.postgresql_psycopg2',
# 		'NAME': 'cartoon_projects',
# 		'USER': 'postgres',
# 		'PASSWORD': 'postgresql',
# 		'HOST': 'localhost', #os.getenv("DB_HOST_LOCAL","NOT FOUNT"),
# 		'PORT': 5432 #os.getenv("DB_PORT",5432),
# 	}
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        # 'NAME': BASE_DIR / 'db.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),

    }
}