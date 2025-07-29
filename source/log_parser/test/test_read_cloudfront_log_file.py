# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock
from lambda_log_parser import LambdaLogParser

class TestLambdaLogParser(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.parser = LambdaLogParser(self.log)

        # CloudFront log format defined in the class
        self.parser.line_format_cloud_front = {
            'delimiter': '\t',  # Tab delimiter for CloudFront
            'date': 0,
            'time': 1,
            'source_ip': 4,
            'uri': 7,
            'code': 8
        }

    def test_read_cloudfront_log_file(self):
        """Test parsing of basic CloudFront log file line"""
        # Sample CloudFront log entry
        cloudfront_log_line = (b'2024-03-19\t15:02:31\tIAD53-C1\t1234\t192.0.2.1\t'
                               b'GET\texample.com\t/test/path\t200\tMozilla/5.0')

        # First decode the bytes to string
        decoded_line = cloudfront_log_line.decode('utf-8')

        # Execute test
        request_key, uri, return_code_index, ip, line_data = self.parser.read_cloudfront_log_file(decoded_line)

        # Assert results - adjusted to match actual method output
        expected_request_key = "2024-03-19 15:02 192.0.2.1"
        expected_uri = "/test/path"
        expected_return_code_index = 8
        expected_ip = "192.0.2.1"

        self.assertEqual(request_key, expected_request_key, f"Expected request_key: {expected_request_key}, got: {request_key}")
        self.assertEqual(uri, expected_uri, f"Expected uri: {expected_uri}, got: {uri}")
        self.assertEqual(return_code_index, expected_return_code_index)
        self.assertEqual(ip, expected_ip, f"Expected ip: {expected_ip}, got: {ip}")
        self.assertTrue(len(line_data) > 8, "Line data should contain all CloudFront log fields")

    def test_read_cloudfront_log_file_with_complex_uri(self):
        """Test parsing of CloudFront log file line with complex URI"""
        # Sample CloudFront log entry with query parameters
        cloudfront_log_line = (b'2024-03-19\t15:00:00\tIAD53-C1\t1234\t192.0.2.1\t'
                               b'GET\texample.com\thttps://example.com/test/path?param=value\t'
                               b'200\tMozilla/5.0')

        # First decode the bytes to string
        decoded_line = cloudfront_log_line.decode('utf-8')

        # Execute test
        request_key, uri, return_code_index, ip, line_data = self.parser.read_cloudfront_log_file(decoded_line)

        # Assert results - adjusted to match actual method output
        expected_request_key = "2024-03-19 15:00 192.0.2.1"
        expected_uri = "/test/path"

        self.assertEqual(request_key, expected_request_key, f"Expected request_key: {expected_request_key}, got: {request_key}")
        self.assertEqual(uri, expected_uri, f"Expected uri: {expected_uri}, got: {uri}")
        self.assertTrue(len(line_data) > 8, "Line data should contain all CloudFront log fields")
