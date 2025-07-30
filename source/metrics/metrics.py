#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

import os
from aws_lambda_powertools import Logger, Tracer
from botocore.exceptions import ClientError
from config import load_config
from waf_metrics import get_waf_blocked_requests, create_metrics_response_object
from lib.solution_metrics import send_metrics

logger = Logger(level=os.getenv('LOG_LEVEL'))
tracer = Tracer()

@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def handler(event, context):
    try:
        logger.info("Loading config...")
        config = load_config()
        if config.enable_metrics:
            logger.info("Collecting WAF metrics...")
            blocked_request_metrics = get_waf_blocked_requests(config)
            metrics = create_metrics_response_object(config, blocked_request_metrics)
            logger.info("Sending metrics...")
            send_metrics(metrics, url=config.metrics_url)
            logger.info("Lambda completed successfully")
    except ClientError as e:
        logger.exception("Lambda failed during execution")
        raise RuntimeError("CloudWatch metrics retrieval failed") from e
