#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch, Mock
from athena_log_parser import AthenaLogParser

class TestAthenaLogParser(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.parser = AthenaLogParser(self.log)
        self.athena_client = Mock()
        self.parser.execute_athena_query = Mock()

        self.event = {
            'accessLogBucket': 'test-bucket',
            'glueAccessLogsDatabase': 'test-database',
            'glueAppAccessLogsTable': 'test-table',
            'glueWafAccessLogsTable': 'waf-table',
            'athenaWorkGroup': 'primary'
        }

    @patch.dict('os.environ', {
        'BAD_BOT_ATHENA_ACCESS_LOG_ENABLED': 'true',
        'BAD_BOT_ATHENA_WAF_ENABLED': 'false',
        'LOG_TYPE': 'CLOUDFRONT',
        'BAD_BOT_URLS': '/test1,/test2',
        'ATHENA_QUERY_RUN_SCHEDULE': '5'
    })
    def test_bad_bot_athena_with_access_logs(self):
        self.event['resourceType'] = 'LambdaAthenaAppLogParser'
        self.parser.process_athena_scheduler_event(self.event)
        self.parser.execute_athena_query.assert_called_once_with(
            'CLOUDFRONT',
            self.event,
            unittest.mock.ANY
        )
        self.log.debug.assert_any_call("[athena_log_parser: execute_bad_bot_athena_query] Start")

    @patch.dict('os.environ', {
        'BAD_BOT_ATHENA_WAF_ENABLED': 'true',
        'LOG_TYPE': 'WAF',
        'BAD_BOT_URLS': '/test1,/test2',
        'ATHENA_QUERY_RUN_SCHEDULE': '5'
    })
    def test_bad_bot_athena_with_waf_logs(self):
        self.event['resourceType'] = 'LambdaAthenaWAFLogParser'
        self.parser.process_athena_scheduler_event(self.event)
        self.parser.execute_athena_query.assert_called_once_with(
            'WAF',
            self.event,
            unittest.mock.ANY
        )
        self.log.debug.assert_any_call("[athena_log_parser: execute_bad_bot_athena_query] Start")

    @patch.dict('os.environ', {
        'BAD_BOT_ATHENA_ACCESS_LOG_ENABLED': 'false',
        'BAD_BOT_ATHENA_WAF_ENABLED' : 'false',
        'LOG_TYPE': 'CLOUDFRONT',
        'BAD_BOT_URLS': '/test1,/test2',
        'ATHENA_QUERY_RUN_SCHEDULE': '5'
    })
    def test_bad_bot_athena_disabled(self):
        self.event['resourceType'] = 'LambdaAthenaAppLogParser'
        self.parser.process_athena_scheduler_event(self.event)
        self.parser.execute_athena_query.assert_called_once_with(
            'CLOUDFRONT',
            self.event,
            unittest.mock.ANY
        )
        self.assertFalse(any("execute_bad_bot_athena_query" in str(call)
                             for call in self.log.debug.call_args_list))

    def tearDown(self):
        patch.stopall()