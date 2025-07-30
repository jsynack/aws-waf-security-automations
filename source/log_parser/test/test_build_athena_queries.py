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

import logging
import build_athena_queries, add_athena_partitions
from datetime import datetime, timedelta

log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_build_athena_queries')
database_name = 'testdb'
table_name = 'testtable'
end_timestamp = datetime.strptime('May 7 2020  1:33PM', '%b %d %Y %I:%M%p')
waf_block_period = 240
error_threshold = 2000
request_threshold = 50
request_threshold_by_country = '{"TR":30,"CN":100,"SE":150}'
no_request_threshold_by_country = ''
group_by_country = 'country'
group_by_uri = 'uri'
group_by_country_uri = 'country and uri'
no_group_by = 'none'
athena_query_run_schedule = 5
cloudfront_log_type = 'CLOUDFRONT'
alb_log_type = 'ALB'
waf_log_type = 'WAF'
log_bucket = 'LogBucket'


def test_build_athena_queries_for_cloudfront_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, cloudfront_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('./test/test_data/cloudfront_logs_query.txt', 'r') as file:
        cloudfront_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(cloudfront_logs_query)

def test_build_bad_bot_athena_query_for_app_waf_logs():
    database_name = 'testdb'
    table_name = 'testtable'
    end_timestamp = datetime(2020, 5, 7, 13, 33, 0)
    query_schedule = 5
    bad_bot_urls = 'ProdStage|CFDeploymentStage'
    start_timestamp = end_timestamp - \
                      timedelta(seconds=60*query_schedule*2)

    query_string = build_athena_queries.build_bad_bot_athena_query_for_waf_logs(
        log, database_name, table_name,
        end_timestamp, start_timestamp, bad_bot_urls
    )

    with open('./test/test_data/waf_cloudfront_bad_bot_query.txt', 'r') as file:
        expected_query = file.read()

    if normalize_query(query_string) != normalize_query(expected_query):
        print("\nActual query:")
        print(repr(query_string))
        print("\nExpected query:")
        print(repr(expected_query))

    assert isinstance(query_string, str)
    assert normalize_query(query_string) == normalize_query(expected_query)


def test_build_bad_bot_athena_query_for_app_access_logs():
    log_type = 'CLOUDFRONT'
    database_name = 'testdb'
    table_name = 'testtable'
    end_timestamp = datetime(2020, 5, 7, 13, 33, 0)
    query_schedule = 5
    bad_bot_urls = 'ProdStage|CFDeploymentStage'
    start_timestamp = end_timestamp - \
                      timedelta(seconds=60*query_schedule*2)

    query_string = build_athena_queries.build_bad_bot_athena_query_for_app_access_logs(
        log, log_type, database_name, table_name,
        end_timestamp, start_timestamp, bad_bot_urls
    )

    with open('./test/test_data/athena_cloudfront_bad_bot_query.txt', 'r') as file:
        expected_query = file.read()

    if normalize_query(query_string) != normalize_query(expected_query):
        print("\nActual query:")
        print(repr(query_string))
        print("\nExpected query:")
        print(repr(expected_query))

    assert isinstance(query_string, str)
    assert normalize_query(query_string) == normalize_query(expected_query)

def test_build_bad_bot_athena_query_for_app_access_logs_alb():
    log_type = 'ALB'
    database_name = 'testdb'
    table_name = 'testtable'
    end_timestamp = datetime(2020, 5, 7, 13, 33, 0)
    query_schedule = 5
    bad_bot_urls = 'ProdStage|CFDeploymentStage'
    start_timestamp = end_timestamp - \
                  timedelta(seconds=60*query_schedule*2)


    query_string = build_athena_queries.build_bad_bot_athena_query_for_app_access_logs(
        log, log_type, database_name, table_name,
        end_timestamp, start_timestamp, bad_bot_urls
    )

    with open('./test/test_data/athena_alb_bad_bot_query.txt', 'r') as file:
        expected_query = file.read()

    assert isinstance(query_string, str)
    assert normalize_query(query_string) == normalize_query(expected_query)

def test_build_athena_queries_for_alb_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, alb_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('./test/test_data/alb_logs_query.txt', 'r') as file:
        alb_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(alb_logs_query)

def test_build_bad_bot_athena_query_for_app_access_logs_alb_1h():
    log_type = 'ALB'
    database_name = 'testdb'
    table_name = 'testtable'
    end_timestamp = datetime(2020, 5, 7, 12, 33, 0)
    query_schedule = 60  # minutes (1 hour)
    bad_bot_urls = 'ProdStage|CFDeploymentStage'
    start_timestamp = end_timestamp - \
                      timedelta(seconds=60*query_schedule*2)

    query_string = build_athena_queries.build_bad_bot_athena_query_for_app_access_logs(
        log, log_type, database_name, table_name,
        end_timestamp, start_timestamp, bad_bot_urls
    )

    with open('./test/test_data/athena_alb_bad_bot_1h_query.txt', 'r') as file:
        expected_query = file.read()

    assert isinstance(query_string, str)
    assert normalize_query(query_string) == normalize_query(expected_query)

def test_build_athena_queries_for_waf_logs_one():
    # test original waf log query one - no group by; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, no_group_by,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_1.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_two():
    # test waf log query two - group by country; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_country,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_2.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_three():
    # test waf log query three - group by uri; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_3.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_four():
    # test waf log query four - group by country and uri; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_country_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_4.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_five():
    # test waf log query five - no group by; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, no_group_by,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_5.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_six():
    # test waf log query six - group by country; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_country,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_5.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_seven():
    # test waf log query seven - group by uri; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_6.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_build_athena_queries_for_waf_logs_eight():
    # test waf log query eight - group by country and uri; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_country_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_6.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert normalize_query(query_string) == normalize_query(waf_logs_query)

def test_generate_url_conditions():
    # Test case 1: Multiple URLs
    urls = "admin|wp-login.php|wp-admin"
    expected = "(bad_bot_uri LIKE '%/admin%' OR bad_bot_uri LIKE '%/wp-login.php%' OR bad_bot_uri LIKE '%/wp-admin%')"
    result = build_athena_queries.generate_url_conditions(urls)
    assert result == expected

    # Test case 2: Single URL
    urls = "admin"
    expected = "(bad_bot_uri LIKE '%/admin%')"
    result = build_athena_queries.generate_url_conditions(urls)
    assert result == expected

    # Test case 3: Empty input
    urls = ""
    expected = "FALSE"
    result = build_athena_queries.generate_url_conditions(urls)
    assert result == expected

    # Test case 4: Spaces in input
    urls = "admin | wp-login.php"
    expected = "(bad_bot_uri LIKE '%/admin%' OR bad_bot_uri LIKE '%/wp-login.php%')"
    result = build_athena_queries.generate_url_conditions(urls)
    assert result == expected

    # Test case 5: Empty segments
    urls = "admin||wp-login.php"
    expected = "(bad_bot_uri LIKE '%/admin%' OR bad_bot_uri LIKE '%/wp-login.php%')"
    result = build_athena_queries.generate_url_conditions(urls)
    assert result == expected

def test_is_valid_identifier():
    # Valid identifiers
    assert build_athena_queries.is_valid_identifier("valid_name") == True
    assert build_athena_queries.is_valid_identifier("Valid123") == True
    assert build_athena_queries.is_valid_identifier("test-db") == True
    assert build_athena_queries.is_valid_identifier("A1_test-123") == True
    
    # Invalid identifiers (potential SQL injection attempts)
    assert build_athena_queries.is_valid_identifier("test'; DROP TABLE--") == False
    assert build_athena_queries.is_valid_identifier("test OR 1=1") == False
    assert build_athena_queries.is_valid_identifier("test/*comment*/") == False
    assert build_athena_queries.is_valid_identifier("test.table") == False
    assert build_athena_queries.is_valid_identifier("test table") == False
    assert build_athena_queries.is_valid_identifier("test;exec") == False
    assert build_athena_queries.is_valid_identifier("") == False
    assert build_athena_queries.is_valid_identifier(None) == False

def test_escape_sql_string():
    # Basic escaping
    assert build_athena_queries.escape_sql_string("normal_string") == "normal_string"
    assert build_athena_queries.escape_sql_string("test'quote") == "test''quote"
    assert build_athena_queries.escape_sql_string("multiple'quote's") == "multiple''quote''s"
    
    # SQL injection attempts
    assert build_athena_queries.escape_sql_string("'; DROP TABLE users; --") == "''; DROP TABLE users; --"
    assert build_athena_queries.escape_sql_string("' OR '1'='1") == "'' OR ''1''=''1"
    assert build_athena_queries.escape_sql_string("admin' --") == "admin'' --"
    
    # Non-string inputs
    assert build_athena_queries.escape_sql_string(123) == "123"
    assert build_athena_queries.escape_sql_string(None) == "None"
    assert build_athena_queries.escape_sql_string(True) == "True"

def test_sanitize_url_pattern():
    # Clean URLs
    assert build_athena_queries.sanitize_url_pattern("admin") == "admin"
    assert build_athena_queries.sanitize_url_pattern("wp-login.php") == "wp-login.php"
    assert build_athena_queries.sanitize_url_pattern("api/v1/users") == "api/v1/users"
    assert build_athena_queries.sanitize_url_pattern("test_file.html") == "test_file.html"
    
    # URLs with dangerous characters
    assert build_athena_queries.sanitize_url_pattern("admin'; DROP--") == "adminDROP"
    assert build_athena_queries.sanitize_url_pattern("test OR 1=1") == "testOR11"
    assert build_athena_queries.sanitize_url_pattern("admin/*comment*/") == "admin"
    assert build_athena_queries.sanitize_url_pattern("test<script>") == "testscript"
    assert build_athena_queries.sanitize_url_pattern("path with spaces") == "pathwithspaces"
    
    # Edge cases
    assert build_athena_queries.sanitize_url_pattern("") == ""
    assert build_athena_queries.sanitize_url_pattern(None) == ""
    assert build_athena_queries.sanitize_url_pattern("  ") == ""

def test_security_validation_integration():
    import pytest

    with pytest.raises(ValueError, match="Invalid database or table name"):
        build_athena_queries.build_athena_query_part_one_for_cloudfront_logs(
            log, "invalid'; DROP TABLE--", "valid_table")
    
    with pytest.raises(ValueError, match="Invalid database or table name"):
        build_athena_queries.build_athena_query_part_one_for_cloudfront_logs(
            log, "valid_db", "invalid OR 1=1")

    with pytest.raises(ValueError, match="Invalid database or table name"):
        build_athena_queries.build_athena_query_part_one_for_alb_logs(
            log, "test/*comment*/", "valid_table")

    with pytest.raises(ValueError, match="Invalid database or table name"):
        build_athena_queries.build_athena_query_part_one_for_waf_logs(
            log, "valid_db", "test.table", "", "")

    try:
        result = build_athena_queries.build_athena_query_part_one_for_cloudfront_logs(
            log, "valid_db", "valid_table")
        assert isinstance(result, str)
        assert "valid_db" in result
        assert "valid_table" in result
    except Exception as e:
        pytest.fail(f"Valid inputs should not raise exception: {e}")

def test_url_sanitization_in_generate_conditions():
    malicious_urls = "admin'; DROP TABLE users; --|wp-login<script>alert(1)</script>"
    result = build_athena_queries.generate_url_conditions(malicious_urls)

    assert "DROP TABLE" not in result
    assert "<script>" not in result
    assert "adminDROPTABLEusers" in result or "admin" in result  # URL should be sanitized
    assert "bad_bot_uri LIKE" in result
    assert "OR" in result

def normalize_query(q):
    return ' '.join(q.strip().split())