#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

import datetime
from os import getenv

from lib.boto3_util import create_client
from aws_lambda_powertools import Logger

logger = Logger(
    level=getenv('LOG_LEVEL')
)

@logger.inject_lambda_context
def lambda_handler(event, _):
    """
    This function adds a new hourly partition to athena table.
    It runs every hour, triggered by a CloudWatch event rule.
    """
    logger.debug('[add-athena-partition lambda_handler] Start')
    try:
        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        athena_client = create_client('athena')
        database_name = event['glueAccessLogsDatabase']
        access_log_bucket = event['accessLogBucket']
        waf_log_bucket = event['wafLogBucket']
        athena_work_group = event['athenaWorkGroup']

        try:
            # Add athena partition for cloudfront or alb logs
            if len(access_log_bucket) > 0:
                execute_athena_query(access_log_bucket, database_name, event['glueAppAccessLogsTable'], athena_client,
                                     athena_work_group)
        except Exception as error:
            logger.error('[add-athena-partition lambda_handler] App access log Athena query execution failed: %s'%str(error))

        try:
            # Add athena partition for waf logs
            if len(waf_log_bucket) > 0:
                execute_athena_query(waf_log_bucket, database_name, event['glueWafAccessLogsTable'], athena_client,
                                     athena_work_group)
        except Exception as error:
            logger.error('[add-athena-partition lambda_handler] WAF access log Athena query execution failed: %s'%str(error))

    except Exception as error:
        logger.error(str(error))
        raise

    logger.debug('[add-athena-partition lambda_handler] End')


def build_athena_query(database_name, table_name):
    """
    This function dynamically builds the alter table athena query
    to add partition to athena table.

    Args:
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        string. Athena query string
    """

    current_timestamp = datetime.datetime.now(datetime.UTC)
    year = current_timestamp.year
    month = current_timestamp.month
    day = current_timestamp.day
    hour = current_timestamp.hour

    query_string = "ALTER TABLE " \
        + database_name + "." + table_name  \
        + "\nADD IF NOT EXISTS\n"  \
        "PARTITION (\n"  \
            "\tyear = " + str(year) + ",\n"  \
            "\tmonth = " + str(month).zfill(2) + ",\n"  \
            "\tday = " + str(day).zfill(2) + ",\n"  \
            "\thour = " + str(hour).zfill(2) + ");"

    logger.debug(
        "[build_athena_query] Query string:\n%s\n"
        %query_string)

    return query_string


def execute_athena_query(log_bucket, database_name, table_name, athena_client, athena_work_group):
    """
    This function executes the alter table athena query to
    add partition to athena table.

    Args:
        log_bucket: s3 bucket for logs(cloudfront, alb or waf logs)
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name
        athena_client: object. Athena client object

    Returns:
        None
    """

    s3_output = "s3://%s/athena_results/"%log_bucket

    query_string = build_athena_query(database_name, table_name)

    logger.info("[execute_athena_query] Query string:\n%s  \
              \nAthena S3 Output Bucket: %s\n" % (query_string, s3_output))

    response = athena_client.start_query_execution(
        QueryString=query_string,
        QueryExecutionContext={'Database': database_name},
        ResultConfiguration={'OutputLocation': s3_output,
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_S3'
                }
            },
        WorkGroup=athena_work_group
    )

    logger.info("[execute_athena_query] Query execution response:\n%s" % response)
