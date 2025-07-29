#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch, mock_open
from io import StringIO
from athena_log_parser import AthenaLogParser

class TestAthenaLogParser(unittest.TestCase):
    def setUp(self):
        self.log = unittest.mock.Mock()
        self.parser = AthenaLogParser(self.log)

    @patch('datetime.datetime')
    @patch('athena_log_parser.open', new_callable=mock_open)
    @patch('athena_log_parser.remove')
    def test_read_athena_result_file_flood_or_scanner(self, mock_remove, mock_file, mock_datetime):
        mock_datetime.now.return_value.strftime.return_value = "2025-03-20 10:00:00 UTC+0000"
        csv_content = "client_ip,max_counter_per_min\n192.0.2.1,5\n2001:db8:3333:4444:5555:6666:7777:8888,3\n"
        mock_file.return_value.__enter__.return_value = StringIO(csv_content)

        result, bad_bot_ips = self.parser.read_athena_result_file('dummy_path')

        expected_result = {
            'general': {
                '192.0.2.1': {'max_counter_per_min': '5', 'updated_at': "2025-03-20 10:00:00 UTC+0000"},
                '2001:db8:3333:4444:5555:6666:7777:8888': {'max_counter_per_min': '3', 'updated_at': "2025-03-20 10:00:00 UTC+0000"}
            },
            'uriList': {}
        }

        self.assertEqual(result, expected_result)
        self.assertEqual(bad_bot_ips, [])
        mock_remove.assert_called_once_with('dummy_path')

    @patch('datetime.datetime')
    @patch('athena_log_parser.open', new_callable=mock_open)
    @patch('athena_log_parser.remove')
    def test_read_athena_result_file_bad_bot(self, mock_remove, mock_file, mock_datetime):
        mock_datetime.now.return_value.strftime.return_value = "2025-03-20 10:00:00 UTC+0000"
        csv_content = "bad_bot_ip\n2001:db8:3333:4444:5555:6666:7777:8888\n203.0.113.2\n"
        mock_file.return_value.__enter__.return_value = StringIO(csv_content)

        result, bad_bot_ips = self.parser.read_athena_result_file('dummy_path')

        expected_result = {
            'general': {},
            'uriList': {}
        }

        self.assertEqual(result, expected_result)
        self.assertEqual(bad_bot_ips, ['2001:db8:3333:4444:5555:6666:7777:8888', '203.0.113.2'])
        mock_remove.assert_called_once_with('dummy_path')