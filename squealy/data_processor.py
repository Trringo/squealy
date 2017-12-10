from django.db.utils import IntegrityError
from django.shortcuts import render
from django.db import transaction
from django.db import connections


# from pyathenajdbc import connect

from squealy.constants import SQL_WRITE_BLACKLIST, SWAGGER_JSON_TEMPLATE, SWAGGER_DICT
from squealy.jinjasql_loader import configure_jinjasql

from squealy.serializers import ChartSerializer, FilterSerializer
from .exceptions import RequiredParameterMissingException,\
                        ChartNotFoundException, MalformedChartDataException, \
                        TransformationException, DatabaseWriteException, DuplicateUrlException,\
                        FilterNotFoundException, DatabaseConfigurationException,\
                        SelectedDatabaseException, ChartNameInvalidException
from .transformers import *
from .formatters import *
from .parameters import *
from .table import Table
from .models import Chart, Transformation, Validation, Filter, Parameter, FilterParameter
from .validators import run_validation
import json, ast

jinjasql = configure_jinjasql()


class DataProcessor(object):

    def fetch_chart_data(self, chart_url, params, user, chart_type=None):
        """
        This method gets the chart data
        """
        chart_attributes = ['parameters', 'validations']
        chart = Chart.objects.filter(url=chart_url).prefetch_related(*chart_attributes).first()

        if not chart:
            raise ChartNotFoundException('Chart with url - %s not found' % chart_url)

        if not chart.database:
            raise SelectedDatabaseException('Database is not selected')

        if not chart_type:
            chart_type = chart.type
        return self._process_chart_query(chart, params, user, chart_type)

    def fetch_filter_data(self, filter_url, params, format_type, user):
        """
        Method to process the query and fetch the data for filter
        """
        filter_obj = Filter.objects.filter(url=filter_url).first()

        if not filter_obj:
            raise FilterNotFoundException('Filter with url - %s not found' % filter_url)

        if not filter_obj.database:
            raise SelectedDatabaseException('Database is not selected')

        # Execute the Query, and return a Table
        table = self._execute_query(params, user, filter_obj.query, filter_obj.database)
        if format_type:
            data = self._format(table, format_type)
        else:
            data = self._format(table, 'GoogleChartsFormatter', 'Table')

        return data

    def _process_chart_query(self, chart, params, user, chart_type):
        """
        Process and return the result after executing the chart query
        """

        # Parse Parameters
        parameter_definitions = chart.parameters.all()
        if parameter_definitions:
            params = self._parse_params(params, parameter_definitions)

        # Run Validations
        validations = chart.validations.all()
        if validations:
            self._run_validations(params, user, validations, chart.database)

        # Execute the Query, and return a Table
        table = self._execute_query(params, user, chart.query, chart.database)

        # Run Transformations
        if chart.transpose:
            table = Transpose().transform(table)

        # Format the table according to google charts / highcharts etc
        data = self._format(table, chart.format, chart_type)

        return data

    def _parse_params(self, params, parameter_definitions):
        for index, param in enumerate(parameter_definitions):
            # Default values
            if param.default_value and \
                    param.default_value!= '' and \
                    params.get(param.name) in [None, '']:
                params[param.name] = param.default_value

            # Check for missing required parameters
            mandatory = param.mandatory

            if mandatory and params.get(param.name) is None:
                raise RequiredParameterMissingException("Parameter required: " + param.name)

            # Formatting parameters
            parameter_type_str = param.data_type

            #FIXME: kwargs should not come as unicode. Need to debug the root cause and fix it.
            if isinstance(param.kwargs, unicode):
                kwargs = ast.literal_eval(param.kwargs)
            else:
                kwargs = param.kwargs

            parameter_type = eval(parameter_type_str.title())
            if params.get(param.name):
                params[param.name] = parameter_type(param.name, **kwargs).to_internal(params[param.name])
        return params

    def _run_validations(self, params, user, validations, db):
        for validation in validations:
            run_validation(params, user, validation.query, db)

    def _check_read_only_query(self, query):
        pass

    def _execute_query(self, params, user, chart_query, db):

        query, bind_params = jinjasql.prepare_query(chart_query,
                                                    {
                                                     "params": params,
                                                     "user": user
                                                    })
        conn = connections[str(db)]
        # if conn.settings_dict['NAME'] == 'Athena':
        #     conn = connect(driver_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'athena-jdbc/AthenaJDBC41-1.0.0.jar'))
        with conn.cursor() as cursor:
            cursor.execute(query, bind_params)
            rows = []
            cols = [desc[0] for desc in cursor.description]
            for db_row in cursor:
                row_list = []
                for col in db_row:
                    value = col
                    if isinstance(value, str):
                        # If value contains a non english alphabet
                        value = value.encode('utf-8')
                    else:
                        value = value
                    row_list.append(value)
                rows.append(row_list)
        return Table(columns=cols, data=rows)

    def _format(self, table, format, chart_type='Table'):
        if format:
            if format in ['table', 'json']:
                formatter = SimpleFormatter()
            else:
                formatter = eval(format)()
            return formatter.format(table, chart_type)
        return GoogleChartsFormatter().format(table, chart_type)
