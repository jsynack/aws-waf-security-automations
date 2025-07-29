#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import json
from os import getenv

from lib.cfn_response import send_response
from operations import (
    operation_types,
    set_log_group_retention,
    config_app_access_log_bucket,
    config_waf_log_bucket,
    config_web_acl,
    config_aws_waf_logs,
    generate_app_log_parser_conf,
    generate_waf_log_parser_conf,
    add_athena_partitions
)
from operations.operation_types import RESOURCE_TYPE
from aws_lambda_powertools import Logger, Tracer

logger = Logger(
    level=getenv('LOG_LEVEL')
)
tracer = Tracer()

operations_dictionary = {
    operation_types.SET_CLOUDWATCH_LOGGROUP_RETENTION: set_log_group_retention.execute,
    operation_types.CONFIG_AWS_WAF_LOGS: config_aws_waf_logs.execute,
    operation_types.CONFIG_APP_ACCESS_LOG_BUCKET: config_app_access_log_bucket.execute,
    operation_types.CONFIG_WAF_LOG_BUCKET: config_waf_log_bucket.execute,
    operation_types.CONFIG_WEB_ACL: config_web_acl.execute,
    operation_types.GENERATE_APP_LOG_PARSER_CONF_FILE: generate_app_log_parser_conf.execute,
    operation_types.GENERATE_WAF_LOG_PARSER_CONF_FILE: generate_waf_log_parser_conf.execute,
    operation_types.ADD_ATHENA_PARTITIONS: add_athena_partitions.execute
}

class UnSupportedOperationTypeException(Exception):
    pass

def get_function_for_resource(resource, log):
    try:
        return operations_dictionary[resource]
    except KeyError as key_error:
        log.error(key_error)
        raise UnSupportedOperationTypeException(f"The operation {resource} is not supported")


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    resource_id = event.get('PhysicalResourceId', event['LogicalResourceId'])
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    try:
        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        request_type = event.get('RequestType', "").upper()
        logger.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        operation = get_function_for_resource(event[RESOURCE_TYPE], logger)
        if operation:
            operation(event, context, logger)

    except Exception as error:
        logger.error(error)
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(logger, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result) #NOSONAR needed to send a response of the result
