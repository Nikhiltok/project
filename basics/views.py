from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
def ApiIndexView(request):
	return HttpResponse("<h1>Welcome to APIs by Developed by Nishant </h1>")