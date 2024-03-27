from django.db.models import Q
from django.views import View




class MenuListView(APIView):
	@classmethod
	@encryption_check
	def get(self, request, *args, **kwargs):
		response = {}
		data = args[0]

		# Default Filter Query
		filterquery = Q()

		# Search Filter Query
		search_query = Q()

		# Retrieving Object method
		result = []

		# Converts result encoding depending on encryption required
		result = Data.Result(self, result, *args, **kwargs)

		response["message"] = result
		response["status"] = 200
		return Response(response)