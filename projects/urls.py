"""projects URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

# from django.contrib import admin
# # from basics import views
# from django.urls import path, include
# from django.conf import settings
# from django.conf.urls.static import static 
# from customer import views
# from rest_framework import permissions
# from drf_yasg.views import get_schema_view
# from drf_yasg import openapi
# from drf_yasg.generators import OpenAPISchemaGenerator
# # schema_view = get_schema_view(
# # 	openapi.Info(
# # 		title="Project",
# # 		default_version='v1',
# # 		description="Project description",
# # 		terms_of_service="https://www.google.com/policies/terms/",
# # 		contact=openapi.Contact(email="contact@snippets.local"),
# # 		license=openapi.License(name="BSD License"),
# # 	),
# # 	public=True,
# # 	permission_classes=(permissions.AllowAny,),
# # )
# class BothHttpAndHttpsSchemaGenerator(OpenAPISchemaGenerator):
#     def get_schema(self, request=None, public=False):
#         schema = super().get_schema(request, public)
#         schema.schemes = ["http", "https"]
#         return schema

# swagger_info = openapi.Info(
# 		title="Gershon Grocery Store",
# 		default_version='v1',
# 		description="Online Ecommerce Store",
# 		# terms_of_service="https://www.google.com/policies/terms/",
# 		contact=openapi.Contact(email="contact@gershongrocerystore.com"),
# 		# license=openapi.License(name="BSD License"),
# 	)
# schema_view = get_schema_view(
#     validators=['ssv', 'flex'],
#     # url='https://api.poswithlogic.com/',
#     generator_class=BothHttpAndHttpsSchemaGenerator,
#     public=True,
#     permission_classes=[permissions.AllowAny],
# )
# urlpatterns = [
# 	path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
# 	path('redoc', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
# 	path('', views.ApiIndexView,name="initial_page"),
# 	path('django-admin/', admin.site.urls),
# 	path('api/customer/', include('customer.urls')),
# 	path('api/partnar/', include('partnar.urls')),
# ]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static 
from customer import views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.generators import OpenAPISchemaGenerator
from django.db.models import Q

# schema_view = get_schema_view(
# 	openapi.Info(
# 		title="Project",
# 		default_version='v1',
# 		description="Project description",
# 		terms_of_service="https://www.google.com/policies/terms/",
# 		contact=openapi.Contact(email="contact@snippets.local"),
# 		license=openapi.License(name="BSD License"),
# 	),
# 	public=True,
# 	permission_classes=(permissions.AllowAny,),
# )

class BothHttpAndHttpsSchemaGenerator(OpenAPISchemaGenerator):
    def get_schema(self, request=None, public=False):
        schema = super().get_schema(request, public)
        schema.schemes = ["http", "https"]
        return schema

swagger_info = openapi.Info(
		title="GST Related",
		default_version='v1',
		description="Online Ecommerce Store",
		# terms_of_service="https://www.google.com/policies/terms/",
		contact=openapi.Contact(email="contact@gershongrocerystore.com"),
		# license=openapi.License(name="BSD License"),
	)
schema_view = get_schema_view(
    validators=['ssv', 'flex'],
    # url='https://api.poswithlogic.com/',
    generator_class=BothHttpAndHttpsSchemaGenerator,
    public=True,
    permission_classes=[permissions.AllowAny],
)
urlpatterns = [
	path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
	path('redoc', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
	path('', views.ApiIndexView,name="initial_page"),
	path('django-admin/', admin.site.urls),
	# path('api/basics/', include('basics.urls')),
	path('api/partnar/', include('partnar.urls')),
	path('api/customer/', include('customer.urls')),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


