#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

######################################################################################################################
######################################################################################################################

import time
import os
import json
from lib.cfn_response import send_response
from aws_lambda_powertools import Logger, Tracer

logger = Logger(
    level=os.getenv('LOG_LEVEL')
)
tracer = Tracer()
# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    logger.info('[lambda_handler] Start')

    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    try:
        count = 3
        SECONDS = os.getenv('SECONDS')
        if (SECONDS != None):
            count = int(SECONDS)
        time.sleep(count)
        logger.info(count)
    except Exception as error:
        logger.error(str(error))
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }
    finally:
        logger.info('[lambda_handler] End')
        if 'ResponseURL' in event:
            resource_id = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
            logger.info("ResourceId %s", resource_id)
            send_response(logger, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result) #NOSONAR needed to send a response of the result
