from jinjasql import JinjaSql
from django.db import connections

from squealy.exceptions import ValidationFailedException

jinjasql = JinjaSql()


def run_query(api, params, user, query, err_msg="Validation Failed"):
    query, bind_params = jinjasql.prepare_query(query, {"params": params})
    conn = connections[api.connection_name]
    with conn.cursor() as cursor:
        cursor.execute(query, bind_params)
        data = cursor.fetchall()
        if len(data) > 0:
            raise ValidationFailedException(detail=err_msg)