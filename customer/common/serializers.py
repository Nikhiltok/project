from rest_framework import serializers

class KeyErrorSerializer(serializers.Serializer):
	error = serializers.CharField(
		required=False,
		help_text="Key error. Please check the error message"
	)

	@classmethod
	def validate(self, data):
		errors = {}

		if errors:
			raise serializers.ValidationError(errors)

		return super(KeyErrorSerializer, self).validate(self, data)

class ListSerializer(serializers.Serializer):
	search = serializers.CharField(
		required=False,
		allow_null=True,
		allow_blank=True,
		max_length=250,
		help_text="Pass search keyword here. Leave blank if do not want to search."
	)
	limit = serializers.IntegerField(
		required=False,
		min_value=1,
		default=10,
		help_text="Pass limit in integer. Default is 10."
	)
	page = serializers.IntegerField(
		required=False,
		min_value=1,
		default=1
	)
	order = serializers.CharField(
		required=False,
		max_length=250,
		default="id",
		help_text="Pass field name for ordering. Use '-' before field name to order descending. Default order is ID."
	)
	status = serializers.ChoiceField(
		required=False,
		default="all",
		choices=(
			("true", "true"),
			("false", "false"),
			("all", "all"),
		),
		help_text="Options are true, false, all."
	)

	@classmethod
	def validate(self, data):
		errors = {}

		if errors:
			raise serializers.ValidationError(errors)

		return super(ListSerializer, self).validate(self, data)