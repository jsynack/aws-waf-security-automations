#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import os
from os import environ
from urllib.parse import unquote_plus
from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics
from lib.cw_metrics_util import WAFCloudWatchMetrics
from lambda_log_parser import LambdaLogParser
from athena_log_parser import AthenaLogParser
from aws_lambda_powertools import Logger, Tracer

logger = Logger(
    level=os.getenv('LOG_LEVEL')
)
tracer = Tracer()

scope = os.getenv('SCOPE')
scanners = 1
flood = 2


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, _):
    logger.info('[lambda_handler] Start')

    result = {}
    try:
        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        athena_log_parser = AthenaLogParser(logger)

        if "resourceType" in event:
            athena_log_parser.process_athena_scheduler_event(event)
            result['message'] = "[lambda_handler] Athena scheduler event processed."
            logger.info(result['message'])

        elif 'Records' in event:
            lambda_log_parser = LambdaLogParser(logger)
            for record in event['Records']:
                process_record(record, logger, result, athena_log_parser, lambda_log_parser)

        else:
            result['message'] = "[lambda_handler] undefined handler for this type of event"
            logger.info(result['message'])

    except Exception as error:
        logger.error(str(error))
        raise

    logger.info('[lambda_handler] End')
    return result


def process_record(r, log, result, athena_log_parser, lambda_log_parser):
    bucket_name = r['s3']['bucket']['name']
    key_name = unquote_plus(r['s3']['object']['key'])

    if 'APP_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('APP_ACCESS_LOG_BUCKET'):
        if key_name.startswith('athena_results/'):
            athena_log_parser.process_athena_result(bucket_name, key_name, scanners)
            result['message'] = "[lambda_handler] Athena app log query result processed."
            log.info(result['message'])

        else:
            conf_filename = os.getenv('STACK_NAME') + '-app_log_conf.json'
            output_filename = os.getenv('STACK_NAME') + '-app_log_out.json'
            log_type = os.getenv('LOG_TYPE')
            lambda_log_parser.process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, scanners)
            result['message'] = "[lambda_handler] App access log file processed."
            log.info(result['message'])

    elif 'WAF_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('WAF_ACCESS_LOG_BUCKET'):
        if key_name.startswith('athena_results/'):
            athena_log_parser.process_athena_result(bucket_name, key_name, flood)
            result['message'] = "[lambda_handler] Athena AWS WAF log query result processed."
            log.info(result['message'])

        else:
            conf_filename = os.getenv('STACK_NAME') + '-waf_log_conf.json'
            output_filename = os.getenv('STACK_NAME') + '-waf_log_out.json'
            log_type = 'waf'
            lambda_log_parser.process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, flood)
            result['message'] = "[lambda_handler] AWS WAF access log file processed."
            log.info(result['message'])

    else:
        result['message'] = "[lambda_handler] undefined handler for bucket %s" % bucket_name
        log.info(result['message'])
