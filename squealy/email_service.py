from datetime import datetime, timedelta

from django.core.mail import send_mail
from django.template import Template, Context
from django.http import HttpResponse

from django.conf import settings

from .models import ScheduledReport, ScheduledReportChart,\
                           ReportParameter, ReportRecipient
from .exceptions import SMTPException, EmailRecipientException, EmailSubjectException
from .data_processor import DataProcessor
from celery.utils.log import get_task_logger
from .exporter import xls_eport
from django.core.mail import EmailMultiAlternatives
import arrow

logger = get_task_logger(__name__)


def check_smtp_credentials():
    """
        This method checks if the user has provided the SMTP credentials or not
    """
    return settings.EMAIL_HOST and settings and settings.EMAIL_HOST and\
        settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD


class ReportConfig(object):

    def __init__(self, scheduled_report):
        """
            Expects a scheduled report object and inititializes
            its own scheduled_report attribute with it
        """
        self.scheduled_report = scheduled_report

    def get_report_config(self):
        """
            Returns the configuration related to a scheduled report, needed
            to populate the email
        """
        return {
                "template_context": self._get_related_charts_data(),
                "recipients": self._get_report_recipients()
                }

    def _get_report_recipients(self):
        """
            Returns the recipient list for a scheduled report
        """
        return list(ReportRecipient.objects.filter(report=self.scheduled_report)\
                    .values_list('email', flat=True))

    def _get_report_parameters(self):
        """
            Returns the query parameters for a scheduled report
        """
        report_parameters = ReportParameter.objects.\
            filter(report=self.scheduled_report)

        param_dict = {}

        for parameter in report_parameters:
            param_dict[parameter.parameter_name] = parameter.parameter_value

        return param_dict

    def _get_related_charts_data(self):
        """
            Returns the data needed to populate the reports
            mapped with a scheduled report
        """
        related_charts_data = {
            "charts": []
        }

        filtered_scheduled_reports = ScheduledReportChart.objects.\
            filter(report=self.scheduled_report)
        report_parameters = self._get_report_parameters()

        for report in filtered_scheduled_reports:
            chart_data = DataProcessor().\
                fetch_chart_data(report.chart.url, report_parameters, None)
            related_charts_data['charts'].append(
                {
                    "data": chart_data,
                    "name": report.chart.name
                }
            )

        return related_charts_data


def create_email_data(content=None):
    if not content: content = "{% include 'report.html' %}"
    content = '''
    <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Title</title>
        </head>
        <body> ''' + str(content) + '''</body></html>'''
    return content


def email_reports(reports):
    try:
        for report in reports:
            report_config = ReportConfig(report).get_report_config()
            template = Template(create_email_data(report.template))
            report_template = template.render(Context(report_config['template_context']))
            report.save()
            if not report.subject:
                logger.error("Skipping sending Mail as subject haven't been specified")
                raise EmailSubjectException('Subject not provided for scheduled report %s' % report.id)
            if not report_config['recipients']:
                logger.error("Skipping sending Mail as reciepients list is empty")
                raise EmailRecipientException('Recipients not provided for scheduled report %s' % (report.id))
            
            logger.info("SMTP has been configured, sending reporting email with subject: {0}".format(report.subject))
            email = EmailMultiAlternatives(
                report.subject,
                'Here is the message.',
                settings.EMAIL_HOST_USER, 
                report_config['recipients']
            )
            attachement = xls_eport(report_config['template_context'])
            email.attach_alternative(report_template, 'text/html')
            email.attach_file(attachement['file_name'], attachement['mime_type'])
            email.send(fail_silently=False)
    except Exception as e:
        logger.error("Unable to send email - {0}".format(e))
        raise e

def send_emails():
    if check_smtp_credentials():
        current_time = datetime.utcnow()
        scheduled_reports = ScheduledReport.objects.filter(next_run_at__lte=current_time)
        email_reports(scheduled_reports)
    else:
        logger.error("Skipping sending Mail as SMTP credential are not there")
        raise SMTPException('Please specify the smtp credentials to use the scheduled reports service')

        