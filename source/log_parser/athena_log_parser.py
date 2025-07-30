######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import csv
import datetime
import tempfile
import os
from os import environ, remove
from build_athena_queries import build_athena_query_for_app_access_logs, \
    build_athena_query_for_waf_logs, build_bad_bot_athena_query_for_app_access_logs, \
    build_bad_bot_athena_query_for_waf_logs
from lib.boto3_util import create_client
from lib.s3_util import S3
from lambda_log_parser import LambdaLogParser


class AthenaLogParser(object):
    """
    This class includes functions to process WAF and App access logs using Athena parser
    """

    def __init__(self, log):
        self.log = log
        self.s3_util = S3(log)
        self.lambda_log_parser = LambdaLogParser(log)


    def process_athena_scheduler_event(self, event):
        self.log.debug("[athena_log_parser: process_athena_scheduler_event] Start")

        log_type = str(environ['LOG_TYPE'].upper())

        athena_client = create_client('athena')

        # Execute athena query for CloudFront or ALB logs
        is_access_logs = event['resourceType'] == 'LambdaAthenaAppLogParser' \
                       and (log_type == 'CLOUDFRONT' or log_type == 'ALB')

        if is_access_logs:
            self.execute_athena_query(log_type, event, athena_client)

        # Execute athena query for WAF logs
        is_waf_log = event['resourceType'] == 'LambdaAthenaWAFLogParser'

        if is_waf_log:
            log_type = 'WAF'
            self.execute_athena_query('WAF', event, athena_client)

        self.log.debug("[athena_log_parser: process_athena_scheduler_event] End")

        if (self.bad_bot_waf_athena_enabled() and is_waf_log) or (self.bad_bot_access_log_athena_enabled() and is_access_logs):
            self.execute_bad_bot_athena_query(log_type, event, athena_client)

    @staticmethod
    def bad_bot_waf_athena_enabled():
        try:
            return environ['BAD_BOT_ATHENA_WAF_ENABLED'] == 'true'
        except KeyError:
            return False

    @staticmethod
    def bad_bot_access_log_athena_enabled():
        try:
            return environ['BAD_BOT_ATHENA_ACCESS_LOG_ENABLED'] == 'true'
        except KeyError:
            return False

    def execute_bad_bot_athena_query(self, log_type, event, athena_client):
        self.log.debug("[athena_log_parser: execute_bad_bot_athena_query] Start")

        s3_output = "s3://%s/athena_results/" % event['accessLogBucket']
        database_name = event['glueAccessLogsDatabase']
        query_schedule = int(environ['ATHENA_QUERY_RUN_SCHEDULE'])
        bad_bot_urls = environ['BAD_BOT_URLS']
        end_timestamp = datetime.datetime.now(datetime.UTC)
        start_timestamp = end_timestamp - \
                          datetime.timedelta(seconds=60*query_schedule*3)

        self.log.info("[athena_log_parser: execute_bad_bot_athena_query] \
            end time: %s; start time: %s"
                         %(end_timestamp, start_timestamp))

        query_string = ""

        if log_type == 'CLOUDFRONT' or log_type == 'ALB':
            query_string = build_bad_bot_athena_query_for_app_access_logs(
                self.log,
                log_type,
                database_name,
                event['glueAppAccessLogsTable'],
                end_timestamp,
                start_timestamp,
                bad_bot_urls
            )
        else:
            query_string = build_bad_bot_athena_query_for_waf_logs(
                self.log,
                database_name,
                event['glueWafAccessLogsTable'],
                end_timestamp,
                start_timestamp,
                bad_bot_urls
            )

        response = athena_client.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={'Database': database_name},
            ResultConfiguration={
                'OutputLocation': s3_output,
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_S3'
                }
            },
            WorkGroup=event['athenaWorkGroup']
        )

        self.log.info("[athena_log_parser: execute_bad_bot_athena_query] Query Execution Response: {}".format(response))
        self.log.debug("[athena_log_parser: execute_bad_bot_athena_query] End")

    def execute_athena_query(self, log_type, event, athena_client):
        self.log.debug("[athena_log_parser: execute_athena_query] Start")


        s3_output = "s3://%s/athena_results/" % event['accessLogBucket']
        database_name = event['glueAccessLogsDatabase']

        # Dynamically build query string using partition
        # for CloudFront or ALB logs
        if log_type == 'CLOUDFRONT' or log_type == 'ALB':
            query_string = build_athena_query_for_app_access_logs(
                self.log,
                log_type,
                event['glueAccessLogsDatabase'],
                event['glueAppAccessLogsTable'],
                datetime.datetime.now(datetime.UTC),
                int(environ['WAF_BLOCK_PERIOD']),
                int(environ['ERROR_THRESHOLD'])
            )
        else:  # Dynamically build query string using partition for WAF logs
            query_string = build_athena_query_for_waf_logs(
                self.log,
                event['glueAccessLogsDatabase'],
                event['glueWafAccessLogsTable'],
                datetime.datetime.now(datetime.UTC),
                int(environ['WAF_BLOCK_PERIOD']),
                int(environ['REQUEST_THRESHOLD']),
                environ['REQUEST_THRESHOLD_BY_COUNTRY'],
                environ['HTTP_FLOOD_ATHENA_GROUP_BY'],
                int(environ['ATHENA_QUERY_RUN_SCHEDULE'])
            )

        response = athena_client.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={'Database': database_name},
            ResultConfiguration={
                'OutputLocation': s3_output,
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_S3'
                }
            },
            WorkGroup=event['athenaWorkGroup']
        )

        self.log.info("[athena_log_parser: execute_athena_query] Query Execution Response: {}".format(response))
        self.log.info("[athena_log_parser: execute_athena_query] End")


    def read_athena_result_file(self, local_file_path): 
        self.log.debug("[athena_log_parser: read_athena_result_file] Start")

        outstanding_requesters = {
            'general': {},
            'uriList': {}
        }

        bad_bot_ips = []

        utc_now_timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        with open(local_file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)

            is_flood_or_scanner_header = 'client_ip' in reader.fieldnames and 'max_counter_per_min' in reader.fieldnames
            if is_flood_or_scanner_header:
                for row in reader:
                    # max_counter_per_min is set as 1 just to reuse lambda log parser data structure
                    # and reuse update_ip_set.
                    outstanding_requesters['general'][row['client_ip']] = {
                        "max_counter_per_min": row['max_counter_per_min'],
                        "updated_at": utc_now_timestamp_str
                    }
            is_bad_bot_header = 'bad_bot_ip' in reader.fieldnames
            if is_bad_bot_header:
                for row in reader:
                    bad_bot_ips.append(row['bad_bot_ip'])

        remove(local_file_path)

        self.log.debug("[athena_log_parser: read_athena_result_file] local_file_path: %s",
                       local_file_path)
        self.log.debug("[athena_log_parser: read_athena_result_file] End")

        return outstanding_requesters, bad_bot_ips


    def process_athena_result(self, bucket_name, key_name, ip_set_type):
        self.log.debug("[athena_log_parser: process_athena_result] Start")

        # Use with statement to ensure proper resource management
        with tempfile.NamedTemporaryFile(delete=False, suffix='-' + key_name.split('/')[-1]) as temp_file:
            local_file_path = temp_file.name

        try:
            # Set restrictive file permissions (600 - owner read/write only)
            os.chmod(local_file_path, 0o600)
            
            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Download file from S3")
            # --------------------------------------------------------------------------------------------------------------
            self.s3_util.download_file_from_s3(bucket_name, key_name, local_file_path)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Read file content")
            # --------------------------------------------------------------------------------------------------------------
            outstanding_requesters, bad_bot_ips = self.read_athena_result_file(local_file_path)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Update WAF IP Sets")
            # --------------------------------------------------------------------------------------------------------------
            self.lambda_log_parser.update_ip_set(ip_set_type, outstanding_requesters)

            if bad_bot_ips:
                # --------------------------------------------------------------------------------------------------------------
                self.log.info("[athena_log_parser: process_athena_result] Update WAF IP BadBot Sets")
                # --------------------------------------------------------------------------------------------------------------
                self.lambda_log_parser.bad_bot_ips_to_ip_set(bad_bot_ips)

        except Exception as e:
            self.log.error("[athena_log_parser: process_athena_result] Error to read input file")
            self.log.error(e)
            
        finally:
            # Ensure cleanup even if exceptions occur
            try:
                os.unlink(local_file_path)
            except OSError:
                pass  # File may already be deleted

        self.log.debug("[athena_log_parser: process_athena_result] End")
