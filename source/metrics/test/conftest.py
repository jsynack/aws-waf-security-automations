#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import Mock

@pytest.fixture
def lambda_context():
    """
    Create a mock Lambda context with standard attributes.
    """
    context = Mock()
    context.function_name = "metrics-function"
    context.function_version = "$LATEST"
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:metrics-function"
    context.memory_limit_in_mb = 128
    context.aws_request_id = "test-request-id-12345"
    context.log_group_name = "/aws/lambda/metrics-function"
    context.log_stream_name = "2024/01/01/[$LATEST]abcdef123456"
    context.get_remaining_time_in_millis.return_value = 300000  # 5 minutes
    return context

@pytest.fixture
def lambda_event():
    """
    Create a sample Lambda event.
    Can be extended based on specific event patterns needed.
    """
    return {
        "version": "0",
        "id": "test-event-id",
        "detail-type": "Scheduled Event",
        "source": "aws.events",
        "account": "123456789012",
        "time": "2024-01-01T00:00:00Z",
        "region": "us-east-1",
        "resources": [
            "arn:aws:events:us-east-1:123456789012:rule/metrics-rule"
        ],
        "detail": {}
    }

@pytest.fixture
def mock_env_setup_metrics_enabled(monkeypatch):
    """
    Setup default environment variables for all tests.
    """
    monkeypatch.setenv('METRICS_NAME_PREFIX', 'testprefix'),
    monkeypatch.setenv('RULE_NAMES', 'BadBotRule, HttpFloodRateBasedRule, HttpFloodRegularRule, ScannersProbesRule, IPReputationListsRule, SqlInjectionRule, XssRule, BlacklistRule'),
    monkeypatch.setenv('SEND_ANONYMIZED_USAGE_DATA', 'Yes'),
    monkeypatch.setenv('WEB_ACL_NAME', 'test-web-acl'),
    monkeypatch.setenv('AWS_REGION', 'us-east-1'),
    monkeypatch.setenv('METRICS_URL', 'https://metrics.awssolutionsbuilder.com/generic'),
    monkeypatch.setenv('UUID', 'test_uuid'),
    monkeypatch.setenv('LOG_LEVEL', 'INFO'),
    monkeypatch.setenv('SOLUTION_ID', 'test_solution_id'),
    monkeypatch.setenv('SOLUTION_VERSION', 'v1.0.0'),
    monkeypatch.setenv('USER_AGENT_STRING', 'Solution/test_version'),
    monkeypatch.setenv('METRICS_FREQUENCY_HOURS', '24'),
    monkeypatch.setenv('WAF_ENDPOINT_TYPE', 'ALB')

@pytest.fixture
def mock_env_setup_metrics_disabled(monkeypatch):
    """
    Setup default environment variables for all tests.
    """
    monkeypatch.setenv('METRICS_NAME_PREFIX', 'test-prefix'),
    monkeypatch.setenv('RULE_NAMES', 'BadBotRule, HttpFloodRateBasedRule, HttpFloodRegularRule, ScannersProbesRule, IPReputationListsRule, SqlInjectionRule, XssRule, BlacklistRule'),
    monkeypatch.setenv('SEND_ANONYMIZED_USAGE_DATA', 'No'),
    monkeypatch.setenv('WEB_ACL_NAME', 'test-web-acl'),
    monkeypatch.setenv('AWS_REGION', 'us-east-1'),
    monkeypatch.setenv('METRICS_URL', 'https://metrics.awssolutionsbuilder.com/generic'),
    monkeypatch.setenv('UUID', 'test_uuid'),
    monkeypatch.setenv('LOG_LEVEL', 'INFO'),
    monkeypatch.setenv('SOLUTION_ID', 'test_solution_id'),
    monkeypatch.setenv('SOLUTION_VERSION', 'v1.0.0'),
    monkeypatch.setenv('USER_AGENT_STRING', 'Solution/test_version'),
    monkeypatch.setenv('METRICS_FREQUENCY_HOURS', '24'),
    monkeypatch.setenv('WAF_ENDPOINT_TYPE', 'ALB')

@pytest.fixture(autouse=True)
def mock_get_metric_data_return_value():
    return {
    "MetricDataResults": [
        {
            "Id": "rule0",
            "Label": "BadBotRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [10.0, 15.0],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule1",
            "Label": "HttpFloodRateBasedRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z"
            ],
            "Values": [200.0, 400.0],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule2",
            "Label": "HttpFloodRegularRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule3",
            "Label": "ScannersProbesRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule4",
            "Label": "IPReputationListsRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule5",
            "Label": "SqlInjectionRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule6",
            "Label": "XssRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        },
        {
            "Id": "rule7",
            "Label": "BlacklistRuleBlockedRequests",
            "Timestamps": [
                "2025-04-10T00:00:00Z",
                "2025-04-10T01:00:00Z"
            ],
            "Values": [],
            "StatusCode": "Complete",
            "Messages": []
        }
    ],
    "Messages": [],
    "ResponseMetadata": {
        "RequestId": "abcd1234-5678-efgh-ijkl-9876543210ab",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "x-amzn-requestid": "abcd1234-5678-efgh-ijkl-9876543210ab"
        },
        "RetryAttempts": 0
    }
}

@pytest.fixture(autouse=True)
def blocked_requests__data():
    return {
        'BadBotRuleBlockedRequests': 25, 
        'HttpFloodRateBasedRuleBlockedRequests': 600, 
        'HttpFloodRegularRuleBlockedRequests': 0, 
        'ScannersProbesRuleBlockedRequests': 0, 
        'IPReputationListsRuleBlockedRequests': 0, 
        'SqlInjectionRuleBlockedRequests': 0,
        'XssRuleBlockedRequests': 0,
        'BlacklistRuleBlockedRequests': 0,
        'WAFResourceType': 'ALB'
    }

@pytest.fixture()
def mock_metric_queries():
    return [
      {
        "Id": "rule0",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixBadBotRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "BadBotRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule1",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixHttpFloodRateBasedRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "HttpFloodRateBasedRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule2",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixHttpFloodRegularRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "HttpFloodRegularRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule3",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixScannersProbesRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "ScannersProbesRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule4",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixIPReputationListsRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "IPReputationListsRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule5",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixSqlInjectionRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "SqlInjectionRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule6",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixXssRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "XssRuleBlockedRequests",
        "ReturnData": True
      },
      {
        "Id": "rule7",
        "MetricStat": {
          "Metric": {
            "Namespace": "AWS/WAFV2",
            "MetricName": "BlockedRequests",
            "Dimensions": [
              {
                "Name": "Rule",
                "Value": "testprefixBlacklistRule"
              },
              {
                "Name": "Region",
                "Value": "us-east-1"
              },
              {
                "Name": "WebACL",
                "Value": "test-web-acl"
              }
            ]
          },
          "Period": 3600,
          "Stat": "Sum"
        },
        "Label": "BlacklistRuleBlockedRequests",
        "ReturnData": True
      }
    ]
    