#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

from urllib import error, request
from os import getenv
from urllib.parse import quote, urlparse
from json import dumps
from datetime import datetime, timezone
from aws_lambda_powertools import Logger

logger = Logger(level=getenv('LOG_LEVEL'))

def send_metrics(data,
                 uuid=getenv('UUID'),
                 solution_id=getenv('SOLUTION_ID'),
                 url=getenv('METRICS_URL'),
                 version=getenv('SOLUTION_VERSION')):
    """Sends anonymized customer metrics to s3 via API gateway owned and
        managed by the Solutions Builder team.

    Args:
        data - anonymized customer metrics to be sent
        uuid - uuid of the solution
        solution_id: unique id of the solution
        url: url for API Gateway via which data is sent
        version: version of the solution

    Return: status code returned by https post request
    """
    try:
        metrics_data = {
            "Solution": solution_id,
            "UUID": uuid,
            "TimeStamp": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", ""),
            "Data": data,
            "Version": version
        }

        # Use quote to handle string literals
        url_encoded_request_data = quote(dumps(metrics_data))

        # Convert string to bytes
        data = url_encoded_request_data.encode('utf-8')
        
        # Validate the url is for https only
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("https",):
            raise ValueError("Only https:// URLs are allowed")
        
        # Create request object
        req = request.Request(
            url,
            data=data,
            headers={'content-type': 'application/json'},
            method='POST'
        )
        
        with request.urlopen(req, timeout=10) as response:  # nosec B310: This is a trusted https endpoint for solution metrics.
            logger.info("Successfully sent solution metrics.")
            return response.status      
    except (error.URLError, error.HTTPError) as e:
        logger.error("[solution_metrics:send_metrics] Failed to send solution metrics.")
        logger.error(str(e))
