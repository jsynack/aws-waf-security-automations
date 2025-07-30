# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import build_athena_queries

def test_security_functions():

    # Valid cases
    assert build_athena_queries.is_valid_identifier("valid_name") == True
    assert build_athena_queries.is_valid_identifier("Valid123") == True
    assert build_athena_queries.is_valid_identifier("test-db") == True
    
    # Invalid cases (SQL injection attempts)
    assert build_athena_queries.is_valid_identifier("test'; DROP TABLE--") == False
    assert build_athena_queries.is_valid_identifier("test OR 1=1") == False
    assert build_athena_queries.is_valid_identifier("test/*comment*/") == False
    assert build_athena_queries.is_valid_identifier("") == False
    assert build_athena_queries.is_valid_identifier(None) == False

    # Basic escaping
    assert build_athena_queries.escape_sql_string("normal_string") == "normal_string"
    assert build_athena_queries.escape_sql_string("test'quote") == "test''quote"
    
    # SQL injection attempts
    assert build_athena_queries.escape_sql_string("'; DROP TABLE users; --") == "''; DROP TABLE users; --"
    assert build_athena_queries.escape_sql_string("' OR '1'='1") == "'' OR ''1''=''1"
    
    # Non-string inputs
    assert build_athena_queries.escape_sql_string(123) == "123"
    assert build_athena_queries.escape_sql_string(None) == "None"

    # Clean URLs
    assert build_athena_queries.sanitize_url_pattern("admin") == "admin"
    assert build_athena_queries.sanitize_url_pattern("wp-login.php") == "wp-login.php"
    
    # URLs with dangerous characters
    assert build_athena_queries.sanitize_url_pattern("admin'; DROP--") == "adminDROP"
    assert build_athena_queries.sanitize_url_pattern("test OR 1=1") == "testOR11"
    assert build_athena_queries.sanitize_url_pattern("admin/*comment*/") == "admin"
    
    # Edge cases
    assert build_athena_queries.sanitize_url_pattern("") == ""
    assert build_athena_queries.sanitize_url_pattern(None) == ""

    # Multiple URLs
    result = build_athena_queries.generate_url_conditions("admin|wp-login.php")
    expected = "(bad_bot_uri LIKE '%/admin%' OR bad_bot_uri LIKE '%/wp-login.php%')"
    assert result == expected
    
    # Empty input
    assert build_athena_queries.generate_url_conditions("") == "FALSE"
    
    # Malicious input should be sanitized
    result = build_athena_queries.generate_url_conditions("admin'; DROP TABLE users; --|wp-login<script>")
    assert "DROP TABLE" not in result
    assert "<script>" not in result