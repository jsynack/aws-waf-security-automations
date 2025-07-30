# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock
from lambda_log_parser import LambdaLogParser

class TestLambdaLogParser(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.parser = LambdaLogParser(self.log)
        self.parser.line_format_alb = {
            'delimiter': ' ',
            'timestamp': 1,
            'source_ip': 3,
            'code': 9,
            'uri': 13
        }

    def test_read_alb_log_file(self):
        """Test parsing of ALB log file line"""
        # Sample ALB log entry
        alb_log_line = (b'http 2024-03-19T15:00:00.123456Z app/my-loadbalancer/50dc6c495c0c9188 '
                        b'192.0.2.1:46532 10.0.0.100:80 0.000 0.001 0.000 200 200 34 366 GET '
                        b'https://example.com/test/path HTTP/1.1')

        # First decode the bytes to string
        decoded_line = alb_log_line.decode('utf-8')

        # Execute test
        request_key, uri, return_code_index, ip, line_data = self.parser.read_alb_log_file(decoded_line)

        # Assert results
        expected_request_key = "2024-03-19T15:00 192.0.2.1"
        expected_uri = "/test/path"
        expected_return_code_index = 9
        expected_ip = "192.0.2.1"

        self.assertEqual(request_key, expected_request_key)
        self.assertEqual(uri, expected_uri)
        self.assertEqual(return_code_index, expected_return_code_index)
        self.assertEqual(ip, expected_ip)
        self.assertTrue(len(line_data) > 13, "Line data should contain all ALB log fields")