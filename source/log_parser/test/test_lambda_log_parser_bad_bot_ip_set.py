#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock, patch
import os
from lambda_log_parser import LambdaLogParser

class TestLambdaLogParser(unittest.TestCase):

    def setUp(self):
        self.log = Mock()
        self.parser = LambdaLogParser(self.log)
        self.parser.waflib = Mock()
        self.parser.delay_between_updates = 0  # Set to 0 for testing

    @patch.dict(os.environ, {
        'IP_SET_NAME_BAD_BOTV4': 'BadBotIPSetV4',
        'IP_SET_NAME_BAD_BOTV6': 'BadBotIPSetV6',
        'LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION': '10000',
        'IP_SET_ID_BAD_BOTV4': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV4/abcdef12-3456-7890-abcd-ef1234567890',
        'IP_SET_ID_BAD_BOTV6': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV6/abcdef12-3456-7890-abcd-ef1234567890'
    })
    def test_bad_bot_ips_to_ip_set_mixed_ips(self):
        ips = ['192.0.2.1', '2001:db8::1']
        self.parser.waflib.which_ip_version.side_effect = lambda _, ip: 'IPV4' if '.' in ip else 'IPV6'
        self.parser.waflib.set_ip_cidr.side_effect = lambda _, ip: ip + '/32' if '.' in ip else ip + '/128'

        self.parser.bad_bot_ips_to_ip_set(ips)

        self.parser.waflib.patch_ip_set.assert_any_call(
            self.log, self.parser.scope, 'BadBotIPSetV4',
            'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV4/abcdef12-3456-7890-abcd-ef1234567890',
            ['192.0.2.1/32'], 10000
        )
        self.parser.waflib.patch_ip_set.assert_any_call(
            self.log, self.parser.scope, 'BadBotIPSetV6',
            'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV6/abcdef12-3456-7890-abcd-ef1234567890',
            ['2001:db8::1/128'], 10000
        )

    @patch.dict(os.environ, {
        'IP_SET_NAME_BAD_BOTV4': 'BadBotIPSetV4',
        'LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION': '10000',
        'IP_SET_ID_BAD_BOTV4': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV4/abcdef12-3456-7890-abcd-ef1234567890'
    })
    def test_bad_bot_ips_to_ip_set_ipv4_only(self):
        ips = ['192.0.2.1', '203.0.113.1']
        self.parser.waflib.which_ip_version.return_value = 'IPV4'
        self.parser.waflib.set_ip_cidr.side_effect = lambda _, ip: ip + '/32'

        self.parser.bad_bot_ips_to_ip_set(ips)

        self.parser.waflib.patch_ip_set.assert_called_once_with(
            self.log, self.parser.scope, 'BadBotIPSetV4',
            'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV4/abcdef12-3456-7890-abcd-ef1234567890',
            ['192.0.2.1/32', '203.0.113.1/32'], 10000
        )

    @patch.dict(os.environ, {
        'IP_SET_NAME_BAD_BOTV4': 'BadBotIPSetV4',
        'IP_SET_NAME_BAD_BOTV6': 'BadBotIPSetV6',
        'LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION': '10000',
        'IP_SET_ID_BAD_BOTV4': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV4/abcdef12-3456-7890-abcd-ef1234567890',
        'IP_SET_ID_BAD_BOTV6': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadBotIPSetV6/abcdef12-3456-7890-abcd-ef1234567890'
    })
    def test_bad_bot_ips_to_ip_set_empty_list(self):
        ips = []

        self.parser.bad_bot_ips_to_ip_set(ips)

        self.parser.waflib.patch_ip_set.assert_not_called()