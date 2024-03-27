from rest_framework.generics import GenericAPIView
from django.db.models import Q
import datetime as typedate




class MasterFilterQuery(GenericAPIView):
	@staticmethod
	def filterquery(self, filter_query, queryfieldname, field_query, querytype, field_value, and_or_operator=''):
		positive_filter_query = {}
		negative_filter_query = {}
		negative_query_list = [
			"doesnotcontain",
			"notequal"
		]
		if queryfieldname:
			if querytype:
				if field_query in negative_query_list:
					negative_filter_query.update({
						'{0}__{1}'.format(queryfieldname, querytype): field_value,
					})
				else:
					positive_filter_query.update({
					    '{0}__{1}'.format(queryfieldname, querytype): field_value,

					})
			else:
				if field_query in negative_query_list:
					negative_filter_query.update({
						'{0}'.format(queryfieldname): field_value,
					})
				else:
					positive_filter_query.update({
					    '{0}'.format(queryfieldname): field_value,

					})

		if positive_filter_query:
			filterquery = Q(**positive_filter_query)
			if and_or_operator == 'or':
				# filterquery |= Q(**positive_filter_query)
				# filter_query.add(
				# 	filterquery,
				# 	Q.OR
				# )
				filter_query |= Q(**positive_filter_query)
			else:
				# filter_query.add(
				# 	filterquery,
				# 	Q.AND
				# )
				filter_query &= Q(**positive_filter_query)
				
		if negative_filter_query:
			filterquery = ~Q(**negative_filter_query),
			if and_or_operator == 'or':
				# filterquery |= Q(**positive_filter_query)
				# filter_query.add(
				# 	filterquery,
				# 	Q.OR
				# )
				filter_query |= ~Q(**negative_filter_query)

			else:
				# filter_query.add(
				# 	filterquery,
				# 	Q.AND
				# )
				filter_query &= ~Q(**negative_filter_query)
		return filter_query

	@staticmethod
	def GetQueryType(self, field_query, fieldvalue=None):
		querytype = ""
		is_list_value = False
		is_int_value = False
		if fieldvalue:
			is_list_value = isinstance(fieldvalue, list)
			is_int_value = isinstance(fieldvalue, int)
			is_date_value = isinstance(fieldvalue, typedate.date)

		if is_list_value:
			querytype = "in"
		else:
			if field_query == 'contains':
				querytype = "icontains"

			elif field_query == 'doesnotcontain':
				querytype = "icontains"

			elif field_query == 'startswith':
				querytype = "istartswith"

			elif field_query == 'endswith':
				querytype = "iendswith"

			elif field_query == 'equals':
				querytype = "iexact"
				if is_int_value or is_date_value:
					querytype = ""

			elif field_query == 'notequal':
				querytype = "iexact"
				if is_int_value or is_date_value:
					querytype = ""

			elif field_query == 'lessthan':
				querytype = "lt"

			elif field_query == 'lessthanequal':
				querytype = "lte"

			elif field_query == 'greaterthan':
				querytype = "gt"

			elif field_query == 'greaterthanequal':
				querytype = "gte"

		return querytype