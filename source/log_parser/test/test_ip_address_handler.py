# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock
from lib.waflibv2 import WAFLIBv2

class TestIPAddressHandler(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.handler = WAFLIBv2()

    def test_merge_addresses_within_limit(self):
        addresses = ["192.0.2.1/32", "192.0.2.2/32"]
        current_list = ["192.0.2.3/32", "192.0.2.4/32"]

        result = self.handler.merge_and_truncate_addresses(self.log, addresses, current_list, 10)

        self.assertEqual(len(result), 4)
        for addr in addresses:
            self.assertIn(addr, result, f"Address {addr} should be in result")

    def test_merge_addresses_exceeds_limit(self):
        addresses = [f"192.0.2.{i}/32" for i in range(4)]
        current_list = [f"192.0.2.{i}/32" for i in range(8, 15)]

        result = self.handler.merge_and_truncate_addresses(self.log, addresses, current_list, 4)

        self.assertEqual(len(result), 4)
        # Verify all new addresses are included
        for addr in addresses:
            self.assertIn(addr, result, f"Address {addr} should be in result")

    def test_merge_addresses_all_new_addresses(self):
        addresses = [f"192.0.2.{i}/32" for i in range(100)]
        current_list = [f"192.0.2.{i}/32" for i in range(10, 15)]

        result = self.handler.merge_and_truncate_addresses(self.log, addresses, current_list, 100)

        self.assertEqual(len(result), 100)
        # Verify all new addresses are included
        for addr in addresses:
            self.assertIn(addr, result, f"Address {addr} should be in result")

    def test_merge_addresses_with_duplicates(self):
        addresses = ["192.0.2.1/32", "192.0.2.2/32", "192.0.2.1/32"]
        current_list = ["192.0.2.2/32", "192.0.2.3/32"]

        result = self.handler.merge_and_truncate_addresses(self.log, addresses, current_list, 100)

        self.assertEqual(len(result), 3)
        # Verify all unique new addresses are included
        unique_addresses = list(set(addresses))
        for addr in unique_addresses:
            self.assertIn(addr, result, f"Address {addr} should be in result")
