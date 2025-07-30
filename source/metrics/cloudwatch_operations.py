#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

import os
from aws_lambda_powertools import Logger
from datetime import datetime
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from lib.boto3_util import create_client

logger = Logger(level=os.getenv('LOG_LEVEL'))
cloudwatch_client = create_client('cloudwatch')

def get_blocked_requests_batch(
    metric_queries: List[Dict[str, Any]],
    start: datetime,
    end: datetime
) -> Dict[str, Any]:
    try:
        logger.info(f"Sending CloudWatch GetMetricData request for {len(metric_queries)} queries")
        response = cloudwatch_client.get_metric_data(
            MetricDataQueries=metric_queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending"
        )
        logger.info("Received metric data from CloudWatch")
        return response
    except ClientError as e:
        logger.exception("Error querying CloudWatch GetMetricData")
        raise RuntimeError("CloudWatch GetMetricData failed") from e
