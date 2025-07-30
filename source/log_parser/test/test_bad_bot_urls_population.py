# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch, Mock
from lambda_log_parser import LambdaLogParser

class TestBadBotUrlsPopulation(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.parser = LambdaLogParser(self.log)

    @patch.dict('os.environ', {'BAD_BOT_URLS': 'admin|wp-login|.env', 'BAD_BOT_LAMBDA_WAF_ENABLED': 'true'})
    def test_bad_bot_urls_population_matching_url(self):
        """Test when URI matches bad bot URL pattern and IP is added to list"""
        # Test data
        uri = "/admin"
        ip = "192.0.2.1"
        bad_bot_ips = []

        # Execute
        self.parser.bad_bot_urls_population(uri, ip, bad_bot_ips, 'waf')

        # Assert
        self.assertEqual(len(bad_bot_ips), 1)
        self.assertEqual(bad_bot_ips[0], "192.0.2.1")
        self.assertIn(ip, bad_bot_ips)

    @patch.dict('os.environ', {'BAD_BOT_URLS': 'admin|wp-login|.env', 'BAD_BOT_LAMBDA_WAF_ENABLED': 'true'})
    def test_bad_bot_urls_population_non_matching_url(self):
        """Test when URI doesn't match any bad bot URL pattern"""
        # Test data
        uri = "/legitimate-path"
        ip = "192.0.2.1"
        bad_bot_ips = []

        # Execute
        self.parser.bad_bot_urls_population(uri, ip, bad_bot_ips, 'waf')

        # Assert
        self.assertEqual(len(bad_bot_ips), 0)
        self.assertNotIn(ip, bad_bot_ips)

    @patch.dict('os.environ', {'BAD_BOT_URLS': 'admin|wp-login|.env', 'BAD_BOT_LAMBDA_WAF_ENABLED': 'true'})
    def test_bad_bot_urls_population_multiple_ips(self):
        """Test multiple IPs are added for matching URLs"""
        # Test data
        uri = "/admin"
        ip1 = "192.0.2.1"
        ip2 = "192.0.2.2"
        bad_bot_ips = []

        # Execute multiple calls
        self.parser.bad_bot_urls_population(uri, ip1, bad_bot_ips, 'waf')
        self.parser.bad_bot_urls_population(uri, ip2, bad_bot_ips, 'waf')

        # Assert
        self.assertEqual(len(bad_bot_ips), 2)
        self.assertIn(ip1, bad_bot_ips)
        self.assertIn(ip2, bad_bot_ips)
        self.assertEqual(bad_bot_ips, ["192.0.2.1", "192.0.2.2"])

    @patch.dict('os.environ', {'BAD_BOT_URLS': 'admin|wp-login|.env', 'BAD_BOT_LAMBDA_ACCESS_LOG_ENABLED': 'true'})
    def test_bad_bot_urls_population_multiple_access_ips(self):
        """Test multiple IPs are added for matching URLs"""
        # Test data
        uri = "/admin"
        ip1 = "192.0.2.1"
        ip2 = "192.0.2.2"
        bad_bot_ips = []

        # Execute multiple calls
        self.parser.bad_bot_urls_population(uri, ip1, bad_bot_ips, 'cloudfront')
        self.parser.bad_bot_urls_population(uri, ip2, bad_bot_ips, 'alb')

        # Assert
        self.assertEqual(len(bad_bot_ips), 2)
        self.assertIn(ip1, bad_bot_ips)
        self.assertIn(ip2, bad_bot_ips)
        self.assertEqual(bad_bot_ips, ["192.0.2.1", "192.0.2.2"])