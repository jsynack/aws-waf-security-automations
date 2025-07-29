# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import urllib.request
import urllib.error


def get_cloudwatch_logs_url(context):
    region = context.invoked_function_arn.split(':')[3]
    return f"https://console.aws.amazon.com/cloudwatch/home?region={region}#logEventViewer:group={context.log_group_name};stream={context.log_stream_name}"


def build_response_body(event, context, response_status, response_data, resource_id, reason=None):
    cw_logs_url = get_cloudwatch_logs_url(context)   
    return {
        'Status': response_status,
        'Reason': reason or f'See the details in CloudWatch Logs: {cw_logs_url}',
        'PhysicalResourceId': resource_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': False,
        'Data': response_data
    }


def send_http_request(log, response_url, json_body):
    log.info(f"[send_http_request] Sending cfn response to URL: {response_url}")
    headers = {
        'Content-Type': '',
        'Content-Length': str(len(json_body))
    }
    try:
        req = urllib.request.Request(
            url=response_url,
            data=json_body.encode('utf-8'),
            method='PUT'
        )

        for key, value in headers.items():
            req.add_header(key, value)
            
        with urllib.request.urlopen(req, timeout=10) as response:
            log.info(f"[send_http_request] Response status code: {response.status}, reason: {response.reason}")
    except urllib.error.URLError as error:
        log.error("[send_http_request] Failed executing urllib request")
        log.error(str(error))
    except Exception as error:
        log.error("[send_http_request] Unexpected error")
        log.error(str(error))


def send_response(log, event, context, response_status, response_data, resource_id, reason=None):
    """
    Send a response to an AWS CloudFormation custom resource.
    
    Parameters:
       log: Logger object for logging messages
       event: The fields in a custom resource request
       context: Lambda execution context
       response_status: Whether the function successfully completed - SUCCESS or FAILED
       response_data: The Data field of a custom resource response object
       resource_id: The id of the custom resource that invoked the function
       reason: The error message if the function fails
    """

    log.debug("[send_response] Start")
    response_url = event['ResponseURL']
    response_body = build_response_body(event, context, response_status, response_data, resource_id, reason)
    json_body = json.dumps(response_body)
    log.debug(f"Response body:\n{json_body}")
    send_http_request(log, response_url, json_body)
    log.debug("[send_response] End")
