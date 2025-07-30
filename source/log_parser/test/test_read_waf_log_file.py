# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock
import json
from datetime import datetime
from lambda_log_parser import LambdaLogParser

class TestLambdaLogParser(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.parser = LambdaLogParser(self.log)

    def test_read_waf_log_file(self):
        timestamp = 1616163600000  # Example timestamp: 2021-03-19T15:00:00
        waf_log_entry = {
            "timestamp": timestamp,
            "httpRequest": {
                "clientIp": "192.0.2.1",
                "uri": "https://example.com/test/path"
            }
        }

        log_line = json.dumps(waf_log_entry).encode('utf-8')
        request_key, uri, ip, line_data = self.parser.read_waf_log_file(log_line)
        expected_datetime = datetime.fromtimestamp(int(timestamp) / 1000.0).isoformat(
            sep='T', timespec='minutes')
        expected_request_key = f"{expected_datetime} 192.0.2.1"
        expected_uri = "/test/path"
        expected_ip = "192.0.2.1"

        self.assertEqual(request_key, expected_request_key)
        self.assertEqual(uri, expected_uri)
        self.assertEqual(ip, expected_ip)
        self.assertEqual(line_data, waf_log_entry)