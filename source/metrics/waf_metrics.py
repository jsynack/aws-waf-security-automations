#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

import os
from json import dumps
from html import escape
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from aws_lambda_powertools import Logger
from cloudwatch_operations import get_blocked_requests_batch
from botocore.exceptions import ClientError
from config import Config

logger = Logger(level=os.getenv('LOG_LEVEL'))

def get_waf_blocked_requests(config: Config) -> Dict[str, int]:
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=config.metrics_frequency_hours)

    logger.info(f"Querying WAF metrics from {escape(start_time.isoformat())} to {escape(end_time.isoformat())}")
    logger.info(f"Target rules: {[escape(str(key)) for key in config.rules.keys()]}")
    metric_queries = build_metric_queries(config)
    try:
        response = get_blocked_requests_batch(metric_queries, start_time, end_time)

    except ClientError as e:
        logger.exception("Failed to fetch metric data from CloudWatch")
        raise RuntimeError("Failed to fetch metric data from CloudWatch") from e

    metric_results = response.get("MetricDataResults", [])
    blocked_requests_metrics = extract_blocked_request_totals(metric_results)
    return blocked_requests_metrics


def build_metric_queries(config: Config) -> List[Dict[str, Any]]:
    return [
        {
            "Id": f"rule{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/WAFV2",
                    "MetricName": "BlockedRequests",
                    "Dimensions": [
                        {"Name": "Rule", "Value": rule_id},
                        {"Name": "Region", "Value": config.region},
                        {"Name": "WebACL", "Value": config.web_acl}
                    ]
                },
                "Period": 3600,
                "Stat": "Sum"
            },
            "Label": f"{rule_name}BlockedRequests",
            "ReturnData": True
        }
        for i, (rule_name, rule_id) in enumerate(config.rules.items())
    ]


def extract_blocked_request_totals(
    metric_results: List[Dict[str, Any]],
) -> Dict[str, int]:
    
    totals: Dict[str, int] = {}
    logger.info(f"Supplied {dumps(metric_results, default=str)} metric results")
    
    for result in metric_results:
        logger.debug(f"Processing metric result: {dumps(result, default=str)}")
        label = result["Label"]
        values = result.get("Values", [])
        totals[label] = int(sum(values))
        logger.info(f"{label}: {totals[label]} blocked requests")
    
    logger.info(f"totals are: {dumps(totals)}")  # Sanitize input
    return totals

def create_metrics_response_object(config: Config, metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **metrics,
        "WAFResourceType": config.waf_endpoint_type
    }

        