import xlsxwriter
import arrow


def xls_eport(reports):
    file_name = "trringo-reports.xlsx"
    with xlsxwriter.Workbook(file_name) as workbook:
        for chindex, chart in enumerate(reports['charts']):
            if chart['data']:
                worksheet_name = 'worksheet_{0}.xlsx'.format(chindex)
                worksheet = workbook.add_worksheet(worksheet_name)
                for index, col  in  enumerate(chart['data']['cols']):
                    worksheet.write(0, index, col['label'])
                
                for rindex, row in  enumerate(chart['data']['rows']):
                    for cindex, col in  enumerate(row['c']):
                        worksheet.write(rindex+1, cindex, col['v'])
        return {'file_name': file_name, 'mime_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}




