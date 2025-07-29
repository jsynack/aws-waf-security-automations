#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import json
from os import getenv

from stack_requirements import StackRequirements
from lib.cfn_response import send_response
from aws_lambda_powertools import Logger, Tracer
    

logger = Logger(
    level=getenv('LOG_LEVEL')
)
tracer = Tracer()

# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    resource_id = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    stack_requirements = StackRequirements(logger)

    logger.info(f'context: {context}')
    try:
        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        logger.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        if event['ResourceType'] == "Custom::CheckRequirements" and request_type in {'CREATE', 'UPDATE'}:
            stack_requirements.verify_requirements_and_dependencies(event)

        elif event['ResourceType'] == "Custom::CreateUUID" and request_type == 'CREATE':
            stack_requirements.create_uuid(response_data)

        elif event['ResourceType'] == "Custom::CreateDeliveryStreamName" and request_type == 'CREATE':
            stack_requirements.create_delivery_stream_name(event, response_data)

        elif event['ResourceType'] == "Custom::CreateGlueDatabaseName" and request_type == 'CREATE':
            stack_requirements.create_db_name(event, response_data)

    except Exception as error:
        logger.error(error)
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(logger, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result) #NOSONAR needed to send a response of the result
