#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import patch
from urllib.parse import unquote
from botocore.exceptions import ClientError
from metrics.metrics import handler, load_config
from metrics.waf_metrics import build_metric_queries
import pytest

@patch("urllib.request.urlopen")
@patch("cloudwatch_operations.cloudwatch_client.get_metric_data")
def test_handler_report_metrics_enabled(
    mock_get_metric_data,
    mock_url_open,
    mock_env_setup_metrics_enabled, 
    lambda_event, 
    lambda_context, 
    mock_get_metric_data_return_value,
    blocked_requests__data
    ):

    mock_get_metric_data.return_value = mock_get_metric_data_return_value

    handler(lambda_event, lambda_context)

    mock_get_metric_data.assert_called_once()
    mock_url_open.assert_called_once()

    req_arg = mock_url_open.call_args[0][0]
    url_decoded_data = unquote(req_arg.data.decode('utf-8'))
    metrics_data = json.loads(url_decoded_data)

    assert req_arg.full_url == "https://metrics.awssolutionsbuilder.com/generic"
    assert metrics_data.get("Data") == blocked_requests__data

@patch("urllib.request.urlopen")
@patch("cloudwatch_operations.cloudwatch_client.get_metric_data")
def test_handler_report_metrics_diabled(
    mock_get_metric_data,
    mock_url_open,
    mock_env_setup_metrics_disabled, 
    lambda_event, 
    lambda_context, 
    mock_get_metric_data_return_value
    ):

    mock_get_metric_data.return_value = mock_get_metric_data_return_value
    mock_url_open.return_value = "success"

    handler(lambda_event, lambda_context)

    mock_get_metric_data.assert_not_called()
    mock_url_open.assert_not_called()

@patch("urllib.request.urlopen")
@patch("cloudwatch_operations.cloudwatch_client.get_metric_data")
def test_handler_report_metrics_exception(
    mock_get_metric_data,
    mock_url_open,
    mock_env_setup_metrics_enabled, 
    lambda_event, 
    lambda_context, 
    ):

    mock_get_metric_data.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "ThrottlingException",
                "Message": "Rate exceeded"
            }
        },
        operation_name="GetMetricData"
    )

    with pytest.raises(RuntimeError) as e:
        handler(lambda_event, lambda_context)
        assert "CloudWatch GetMetricData failed" in str(e)
        mock_url_open.assert_not_called()


def test_handler_build_metrics_queries(
    mock_env_setup_metrics_enabled,
    mock_metric_queries
):

    data_config = load_config()
    metric_queries = build_metric_queries(data_config)
    assert metric_queries == mock_metric_queries

    