#common.py
from rest_framework.generics import GenericAPIView
from openpyxl import Workbook
class CommonInfo(GenericAPIView):
	@staticmethod
	def write_xls(report_excel_sheet, download_data,fields,custom_fields=None):
		wb = Workbook(write_only=True)
		ws = wb.create_sheet()
		# headers = list(set(itertools.chain.from_iterable(download_data)))
		headers = fields
		if custom_fields:
			ws.append(custom_fields)
		else:
			ws.append(headers)
		for elements in download_data:
			ws.append([elements.get(h) for h in headers])
		wb.save(report_excel_sheet)
		return report_excel_sheet