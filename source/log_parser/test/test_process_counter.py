# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import Mock
from lambda_log_parser import LambdaLogParser

class TestCounterEmpty(unittest.TestCase):
    def setUp(self):

        self.log = Mock()
        self.parser = LambdaLogParser(self.log)

        self.empty_counter = {
            'general': {},
            'uriList': {}
        }

        self.non_empty_general = {
            'general': {'192.0.2.1': 1},
            'uriList': {}
        }

        self.non_empty_uriList = {
            'general': {},
            'uriList': {'/test': 1}
        }

    def test_empty_counter(self):
        """Test when counter is completely empty"""
        self.assertTrue(self.parser.is_empty_counter(self.empty_counter))

    def test_non_empty_general(self):
        """Test when general has entries"""
        self.assertFalse(self.parser.is_empty_counter(self.non_empty_general))

    def test_non_empty_uriList(self):
        """Test when uriList has entries"""
        self.assertFalse(self.parser.is_empty_counter(self.non_empty_uriList))

    def test_both_non_empty(self):
        """Test when both general and uriList have entries"""
        counter = {
            'general': {'192.0.2.1': 1},
            'uriList': {'/test': 1}
        }
        self.assertFalse(self.parser.is_empty_counter(counter))
