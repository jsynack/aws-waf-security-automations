# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch
import datetime
from add_athena_partitions import build_athena_query

class TestAddAthenaPartitions(unittest.TestCase):
    def setUp(self):
        self.database_name = "testdb"
        self.table_name = "testtable"
        # Define fixed datetime (equivalent to "2020-05-08 02:21:34", tz_offset=-4)
        self.fixed_datetime = datetime.datetime(2020, 5, 8, 2, 21, 34,
                                              tzinfo=datetime.timezone(datetime.timedelta(hours=-4)))

    @patch('datetime.datetime')
    def test_add_athena_partitions_build_query_string(self, mock_datetime):
        mock_datetime.now.return_value = self.fixed_datetime
        mock_datetime.UTC = datetime.UTC
        mock_datetime.timedelta = datetime.timedelta

        query_string = build_athena_query(self.database_name, self.table_name)
        query_string = query_string
        with open('./test/test_data/athena_partitions_query.txt', 'r') as file:
            expected_query = file.read()

        self.assertIsInstance(query_string, str)
        self.assertEqual(query_string, expected_query)