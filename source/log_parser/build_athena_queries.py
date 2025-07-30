######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import datetime
import json
import re

WHERE_YEAR = "\n\t\tWHERE year = "

def is_valid_identifier(identifier):
    if not identifier:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', identifier))

def escape_sql_string(value):
    if not isinstance(value, str):
        return str(value)
    return value.replace("'", "''")

def sanitize_url_pattern(url):
    if not url:
        return ""
    url = url.replace('--', '')
    url = re.sub(r'/\*.*?\*/', '', url)
    return re.sub(r'[^a-zA-Z0-9_.\-/]', '', url.strip())

def build_bad_bot_athena_query_for_app_access_logs(log, log_type, database_name, table_name,
                                                   end_timestamp, start_timestamp, bad_bot_urls):
    if log_type == 'CLOUDFRONT':
        query_string = build_bad_bot_athena_query_part_one_for_cloudfront_logs(
            log, database_name, table_name)
    else:
        query_string = build_bad_bot_athena_query_part_one_for_alb_logs(
            log, database_name, table_name)

    query_string += build_athena_query_part_two_for_partition(log, start_timestamp, end_timestamp)
    query_string += build_bad_bot_athena_query_part_three_for_logs(log, start_timestamp, bad_bot_urls)

    return query_string

def build_athena_query_for_app_access_logs(
    log, log_type, database_name, table_name, end_timestamp,
        waf_block_period, error_threshold):
    start_timestamp = end_timestamp - datetime.timedelta(seconds=60*waf_block_period)
    
    if log_type == 'CLOUDFRONT':
        query_string = build_athena_query_part_one_for_cloudfront_logs(log, database_name, table_name)
    else:
        query_string = build_athena_query_part_one_for_alb_logs(log, database_name, table_name)
    
    query_string += build_athena_query_part_two_for_partition(log, start_timestamp, end_timestamp)
    query_string += build_athena_query_part_three_for_app_access_logs(log, error_threshold, start_timestamp)

    return query_string

def build_bad_bot_athena_query_for_waf_logs(
        log, database_name, table_name, end_timestamp, start_timestamp, bad_bot_urls):
    query_string = build_bad_bot_athena_query_part_one_for_waf_logs(log, database_name, table_name)
    query_string += build_athena_query_part_two_for_partition(log, start_timestamp, end_timestamp)
    query_string += build_bad_bot_athena_query_part_three_for_logs(log, start_timestamp, bad_bot_urls)
    
    return query_string

def build_athena_query_for_waf_logs(
    log, database_name, table_name, end_timestamp,
        waf_block_period, request_threshold,
        request_threshold_by_country,
        group_by, athena_query_run_schedule):
    start_timestamp = end_timestamp - datetime.timedelta(seconds=60*waf_block_period)
    
    additional_columns_group_one, additional_columns_group_two = build_select_group_by_columns_for_waf_logs(
        log, group_by, request_threshold_by_country)
    
    query_string = build_athena_query_part_one_for_waf_logs(
        log, database_name, table_name, additional_columns_group_one, additional_columns_group_two)
    query_string += build_athena_query_part_two_for_partition(log, start_timestamp, end_timestamp)
    query_string += build_athena_query_part_three_for_waf_logs(
        log, request_threshold, request_threshold_by_country,
        athena_query_run_schedule, additional_columns_group_two, start_timestamp)

    return query_string

def build_bad_bot_athena_query_part_one_for_cloudfront_logs(log, database_name, table_name):
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")

    query_string = f"""
        SELECT DISTINCT bad_bot_ip
        FROM (
            WITH logs_with_concat_data AS (
                SELECT
                    requestip as bad_bot_ip,
                    uri as bad_bot_uri,
                    parse_datetime(
                        concat(
                            concat(format_datetime(date, 'yyyy-MM-dd'), '-'),
                            time
                        ),
                        'yyyy-MM-dd-HH:mm:ss'
                    ) AS datetime
                FROM
                    {database_name}.{table_name}
    """

    log.debug(
        "[build_badbot_athena_query_part_one_for_cloudfront_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string

def build_athena_query_part_one_for_cloudfront_logs(
        log, database_name, table_name):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        Athena query string
    """
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")
        
    query_string = f"""SELECT
\tclient_ip,
\tMAX_BY(counter, counter) as max_counter_per_min
 FROM (
\tWITH logs_with_concat_data AS (
\t\tSELECT
\t\t\trequestip as client_ip,
\t\t\tcast(status as varchar) as status,
\t\t\tparse_datetime( concat( concat( format_datetime(date, 'yyyy-MM-dd'), '-' ), time ), 'yyyy-MM-dd-HH:mm:ss') AS datetime
\t\tFROM
\t\t\t{database_name}.{table_name}"""
    log.debug(
        "[build_athena_query_part_one_for_cloudfront_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_bad_bot_athena_query_part_one_for_alb_logs(log, database_name, table_name):
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")
        
    query_string = f"""
        SELECT DISTINCT
            bad_bot_ip
        FROM (
            WITH logs_with_concat_data AS (
                SELECT
                    client_ip as bad_bot_ip,
                    request_url as bad_bot_uri,
                    parse_datetime(time, 'yyyy-MM-dd''T''HH:mm:ss.SSSSSS''Z') AS datetime
                FROM
                    {database_name}.{table_name}
    """
    log.debug(
        "[build_bad_bot_athena_query_part_one_for_alb_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string

def build_athena_query_part_one_for_alb_logs(
        log, database_name, table_name):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        Athena query string
    """
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")
        
    query_string = f"""SELECT
        client_ip,
        MAX_BY(counter, counter) as max_counter_per_min
    FROM (
        WITH logs_with_concat_data AS (
            SELECT
                client_ip,
                target_status_code AS status,
                parse_datetime(time, 'yyyy-MM-dd''T''HH:mm:ss.SSSSSS''Z') AS datetime
            FROM
                {database_name}.{table_name}"""
    log.debug(
        "[build_athena_query_part_one_for_alb_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_select_group_by_columns_for_waf_logs(
        log, group_by, request_threshold_by_country):
    """
    This function dynamically builds user selected additional columns
    in select and group by statement of the athena query.

    Args:
        log: logging object
        group_by: string. The group by columns (country, uri or both) selected by user

    Returns:
        string of columns
    """
    
    additional_columns_group_one = ''
    additional_columns_group_two = ''

    if group_by.lower() == 'country' or \
        (group_by.lower() == 'none' and len(request_threshold_by_country) > 0) :
        additional_columns_group_one = 'httprequest.country as country,'
        additional_columns_group_two = ', country'
    elif group_by.lower() == 'uri':
        # Add country if threshold by country is configured
        additional_columns_group_one =  \
            'httprequest.uri as uri,'   \
            if len(request_threshold_by_country) == 0   \
            else 'httprequest.country as country, httprequest.uri as uri,'
        additional_columns_group_two =  \
            ', uri' \
            if len(request_threshold_by_country) == 0   \
            else ', country, uri'
    elif group_by.lower() == 'country and uri':
        additional_columns_group_one = 'httprequest.country as country, httprequest.uri as uri,'
        additional_columns_group_two = ', country, uri'

    log.debug(
        "[build_select_group_by_columns_for_waf_logs]  \
         Additional columns group one: %s\nAdditional columns group two: %s"
         %(additional_columns_group_one, additional_columns_group_two))
    return additional_columns_group_one, additional_columns_group_two

def build_bad_bot_athena_query_part_one_for_waf_logs(
        log, database_name, table_name):
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")

    query_string = f"""
        SELECT DISTINCT bad_bot_ip
        FROM (
            WITH logs_with_concat_data AS (
                SELECT
                    httprequest.clientip as bad_bot_ip,
                    httprequest.uri as bad_bot_uri,
                    from_unixtime(timestamp/1000) as datetime
                FROM
                    {database_name}.{table_name}
    """

    log.debug(
        "[build_bad_bot_athena_query_part_one_for_waf_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string

def build_athena_query_part_one_for_waf_logs(
        log, database_name, table_name,
        additional_columns_group_one,
        additional_columns_group_two):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name
        additional_columns_group_one: string. Additional columns for SELECT clause
        additional_columns_group_two: string. Additional columns for GROUP BY clause

    Returns:
        Athena query string
    """
    if not is_valid_identifier(database_name) or not is_valid_identifier(table_name):
        log.error(f"Invalid database or table name: {database_name}.{table_name}")
        raise ValueError(f"Invalid database or table name: {database_name}.{table_name}")
        
    query_string = f"""SELECT
        client_ip{additional_columns_group_two},
        MAX_BY(counter, counter) as max_counter_per_min
    FROM (
        WITH logs_with_concat_data AS (
            SELECT
                httprequest.clientip as client_ip,{additional_columns_group_one}
                from_unixtime(timestamp/1000) as datetime
            FROM
                {database_name}.{table_name}"""
    log.debug(
        "[build_athena_query_part_one_for_waf_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_athena_query_part_two_for_partition(
        log, start_timestamp, end_timestamp):
    """
    This function dynamically builds the second part
    of the athena query, where partition values are added.
    The query will only scan the logs in the partitions
    that are between start_timestamp and end_timestamp.

    Args:
        log: logging object
        start_timestamp: datetime. The start time stamp of the logs being scanned
        end_timestamp: datetime. The end time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    start_year = str(start_timestamp.year)
    start_month = str(start_timestamp.month).zfill(2)
    start_day = str(start_timestamp.day).zfill(2)
    start_hour = str(start_timestamp.hour).zfill(2)
    end_year = str(end_timestamp.year)
    end_month = str(end_timestamp.month).zfill(2)
    end_day = str(end_timestamp.day).zfill(2)
    end_hour = str(end_timestamp.hour).zfill(2)

    # same day query filter!
    if (start_timestamp.date() == end_timestamp.date()):
        log.debug(
            "[build_athena_query_part_two_for_partition] \
            Same day query filter")
        query_string = f"{WHERE_YEAR}{start_year}\n" \
                       f"\t\tAND month = {start_month}\n" \
                       f"\t\tAND day = {start_day}\n" \
                       f"\t\tAND hour between {start_hour} and {end_hour}"
    # different days - cross days query filter!
    elif (start_timestamp.year == end_timestamp.year):
        log.debug(
            "[build_athena_query_part_two_for_partition] \
             Different days - cross days query filter")
        if (start_timestamp.month == end_timestamp.month):  # year and month are the same, but days are different
            query_string = f"{WHERE_YEAR}{start_year}\n" \
                        f"\t\tAND month = {start_month}\n" \
                        f"\t\tAND (\n" \
                        f"\t\t\t(day = {start_day} AND hour >= {start_hour})\n" \
                        f"\t\t\tOR (day = {end_day} AND hour <= {end_hour})\n" \
                        f"\t\t)\n"
        else:  # years are the same, but months and days are different
            query_string = f"{WHERE_YEAR}{start_year}\n" \
                        f"\t\tAND (\n" \
                        f"\t\t\t(month = {start_month} AND day = {start_day} AND hour >= {start_hour})\n" \
                        f"\t\t\tOR (month = {end_month} AND day = {end_day} AND hour <= {end_hour})\n" \
                        f"\t\t)\n"
    else:  # years are different
        log.debug(
            "[build_athena_query_part_two_for_partition] \
             Different years - cross years query filter")
        query_string = f"\n\t\tWHERE (year = {start_year}\n" \
                    f"\t\t\tAND month = {start_month}\n" \
                    f"\t\t\tAND day = {start_day}\n" \
                    f"\t\t\tAND hour >= {start_hour})\n" \
                    f"\t\tOR (year = {end_year}\n" \
                    f"\t\t\tAND month = {end_month}\n" \
                    f"\t\t\tAND day = {end_day}\n" \
                    f"\t\t\tAND hour <= {end_hour})\n"  \

    log.debug(
        "[build_athena_query_part_two_for_partition]  \
         Query string part Two:\n %s"%query_string)
    return query_string

def build_bad_bot_athena_query_part_three_for_logs(log, start_timestamp, bad_bot_urls):
    query_string = f"""
        )
        SELECT
            bad_bot_ip
        FROM
            logs_with_concat_data
        WHERE 
            datetime > TIMESTAMP '{str(start_timestamp)[0:19]}'
            AND {generate_url_conditions(bad_bot_urls)} 
        )
        LIMIT 10000;
    """

    log.debug(
        "[build_bad_bot_athena_query_part_three_for_app_access_logs] "
        f"Query string part Three:\n{query_string}"
    )

    return query_string

def generate_url_conditions(bad_bot_urls):
    if not bad_bot_urls:
        return "FALSE"
        
    urls = bad_bot_urls.split("|")
    sanitized_urls = [sanitize_url_pattern(url) for url in urls]
    conditions = [f"bad_bot_uri LIKE '%/{url}%'" for url in sanitized_urls if url]
    
    return "(" + " OR ".join(conditions) + ")" if conditions else "FALSE"

def build_athena_query_part_three_for_app_access_logs(
        log, error_threshold, start_timestamp):
    """
    This function dynamically builds the third part
    of the athena query.

    Args:
        log: logging object
        error_threshold: int. The maximum acceptable bad requests per minute per IP address
        start_timestamp: datetime. The start time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    formatted_timestamp = str(start_timestamp)[0:19]

    try:
        error_threshold = int(error_threshold)
    except (ValueError, TypeError):
        log.error(f"Invalid error threshold: {error_threshold}, using default value of 10")
        error_threshold = 10
    
    query_string = f"""
\t)
\tSELECT
\t\tclient_ip,
\t\tCOUNT(*) as counter
\tFROM
\t\tlogs_with_concat_data
\tWHERE
\t\tdatetime > TIMESTAMP '{formatted_timestamp}'
\t\tAND status = ANY (VALUES '400', '401', '403', '404', '405')
\tGROUP BY
\t\tclient_ip,
\t\tdate_trunc('minute', datetime)
\tHAVING
\t\tCOUNT(*) >= {error_threshold}
) GROUP BY
\tclient_ip
ORDER BY
\tmax_counter_per_min DESC
LIMIT 10000;"""
    log.debug(
        "[build_athena_query_part_three_for_app_access_logs]  \
        Query string part Three:\n %s"%query_string)
    return query_string


def build_having_clause_for_waf_logs(
        log, default_request_threshold,
        request_threshold_by_country,
        athena_query_run_schedule):
    """
    This function dynamically builds having clause of the athena query.

    Args:
        log: logging object
        default_request_threshold: int. The default request threshold
        request_threshold_by_country: json string. Request thresholds for countries configured by user
        athena_query_run_schedule: int. The Athena query run schedule in minutes

    Returns:
        string of having clause
    """
    request_threshold_calculated = default_request_threshold / athena_query_run_schedule

    having_clause_string = f"\t\tCOUNT(*) >= {request_threshold_calculated}"

    if len(request_threshold_by_country) > 0:
        having_clause_string = ''
        safe_countries = []
        
        try:
            request_threshold_by_country_json = json.loads(request_threshold_by_country)

            country_conditions = []
            for country, threshold in request_threshold_by_country_json.items():
                safe_country = escape_sql_string(country)
                safe_countries.append(safe_country)

                request_threshold_for_country_calculated = threshold / athena_query_run_schedule
                country_condition = f"\t\t(COUNT(*) >= {request_threshold_for_country_calculated} AND country = '{safe_country}') OR \n"
                country_conditions.append(country_condition)

            having_clause_string = ''.join(country_conditions)

            if safe_countries:
                countries_list = ', '.join(f"'{c}'" for c in safe_countries)
                not_in_clause = f"\t\t(COUNT(*) >= {request_threshold_calculated} AND country NOT IN ({countries_list}))"
                having_clause_string += not_in_clause
            else:
                having_clause_string = f"\t\tCOUNT(*) >= {request_threshold_calculated}"
                
        except json.JSONDecodeError:
            log.error(f"Invalid JSON in request_threshold_by_country: {request_threshold_by_country}")
            having_clause_string = f"\t\tCOUNT(*) >= {request_threshold_calculated}"

    log.debug(
        "[build_select_group_by_columns_for_waf_logs]  \
         Having clause: %s"%having_clause_string)
    return having_clause_string

def build_athena_query_part_three_for_waf_logs(
        log, default_request_threshold, request_threshold_by_country,
        athena_query_run_schedule, additional_columns_group_two,
        start_timestamp):
    """
    This function dynamically builds the third part
    of the athena query.

    Args:
        log: logging object
        default_request_threshold: int. The maximum acceptable count of requests per IP address within the scheduled query run interval (default 5 minutes)
        request_threshold_by_country: json string. The maximum acceptable count of requests per IP address per specified country within the scheduled query run interval (default 5 minutes)
        athena_query_run_schedule: int. The Athena query run schedule (in minutes) set in EventBridge events rule
        additional_columns_group_two: string. Additional columns for GROUP BY clause
        start_timestamp: datetime. The start time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    formatted_timestamp = str(start_timestamp)[0:19]

    having_clause = build_having_clause_for_waf_logs(
                        log, default_request_threshold, request_threshold_by_country,
                        athena_query_run_schedule)

    query_string = f"""
    )
    SELECT
        client_ip{additional_columns_group_two},
        COUNT(*) as counter
    FROM
        logs_with_concat_data
    WHERE
        datetime > TIMESTAMP '{formatted_timestamp}'
    GROUP BY
        client_ip{additional_columns_group_two},
        date_trunc('minute', datetime)
    HAVING
        {having_clause}
    ) GROUP BY
        client_ip{additional_columns_group_two}
    ORDER BY
        max_counter_per_min DESC
    LIMIT 10000;"""
    log.debug(
        "[build_athena_query_part_three_for_waf_logs]  \
        Query string part Three:\n %s"%query_string)
    return query_string