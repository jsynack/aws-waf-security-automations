#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

######################################################################################################################
######################################################################################################################

from os import environ, getenv
from calendar import timegm
from datetime import datetime, timedelta, UTC
from lib.dynamodb_util import DDB
from aws_lambda_powertools import Logger, Tracer

logger = Logger(
    level=getenv('LOG_LEVEL')
)
tracer = Tracer()
class SetIPRetention(object):
    """
    This class contains functions to put ip retention info into ddb table
    """

    def __init__(self, event, log):
        """
        Class init function
        """

        self.event = event
        self.log = log
        self.log.debug(self.__class__.__name__ + " Class Event:\n{}".format(event))
        
    def is_none(self, value):
        """
        Return None (string type) if the value is NoneType
        """

        if value is None:
            return 'None'
        else:
            return value
       
    def get_expiration_time(self, time, ip_retention_period_minute):
        """
        Get ip expiration time which is the TTL used by ddb table to delete ip upon expiration
        """

        utc_start_time = datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ")
        utc_end_time = utc_start_time + timedelta(seconds=60*ip_retention_period_minute)
        epoch_time = timegm(utc_end_time.utctimetuple())
        return epoch_time

    def make_item(self, event):
        """
        Extract ip retention info from event to make ddb item
        """

        item = {}
        request_parameters = self.is_none(event.get('requestParameters', {}))
        
        ip_retention_period = int(environ.get('IP_RETENTION_PERIOD_ALLOWED_MINUTE')) \
                              if self.is_none(str(request_parameters.get('name')).find('Whitelist')) != -1 \
                              else int(environ.get('IP_RETENTION_PERIOD_DENIED_MINUTE'))

        # If retention period is not set, stop and return
        if ip_retention_period == -1:
            self.log.info("[set_ip_retention: make_item] IP retention is not set on {}. Stop processing." \
                        .format(self.is_none(str(request_parameters.get('name')))))
            return item

        # Set a minimum 15-minute retention period
        ip_retention_period = 15 if ip_retention_period in range(0, 15) else ip_retention_period
        
        item = {
            "IPSetId": self.is_none(str(request_parameters.get('id'))),
            "IPSetName": self.is_none(str(request_parameters.get('name'))),
            "Scope": self.is_none(str(request_parameters.get('scope'))),
            "IPAdressList": self.is_none(request_parameters.get('addresses',[])),
            "LockToken": self.is_none(str(request_parameters.get('lockToken'))),
            "IPRetentionPeriodMinute": ip_retention_period,
            "CreationTime": timegm(datetime.now(UTC).utctimetuple()),
            "ExpirationTime": self.get_expiration_time(event.get('eventTime'), ip_retention_period),
            "CreatedByUser": environ.get('STACK_NAME')
        }
        return item
   
    def put_item(self, table_name):
        """
        Write item into ddb table
        """
        try:
            self.log.info("[set_ip_retention: put_item] Start")

            ddb = DDB(self.log, table_name)
            
            item = self.make_item(self.event)
            
            response = {}

            # put item if it is not empty
            if bool(item):
                response = ddb.put_item(item)
            
                self.log.info("[set_ip_retention: put_item] item: \n{}".format(item))
                self.log.info("[set_ip_retention: put_item] put_item response: \n{}:".format(response))

        except Exception as error:
            self.log.error(str(error))
            raise 
        
        self.log.info("[set_ip_retention:put_item] End")

        return response



@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, _):
    """
    Invoke functions to put ip retention info into ddb table. 
    It is triggered by a CloudWatch events rule.
    """
    try:
        logger.info('[set_ip_retention: lambda_handler] Start')
        logger.info("Lambda Handler Event: \n{}".format(event))
        
        event_detail = event.get('detail',{})
        event_user_arn = event_detail.get('userIdentity',{}).get('arn')
        response = {}
        
        # If event for UpdateIPSet api call is not created by the RemoveExpiredIP lambda, continue to put item into DDB
        if event_user_arn.find(environ.get('REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME')) == -1:
            sipr = SetIPRetention(event_detail, logger)
            response = sipr.put_item(environ.get('TABLE_NAME'))
        else:
            message = "The event for UpdateIPSet API call was made by RemoveExpiredIP lambda instead of user. Skip."
            logger.info(message)
            response = {"Message": message}
    except Exception as error:
        logger.error(str(error))
        raise
    
    logger.info('[set_ip_retention: lambda_handler] End')
    return response
