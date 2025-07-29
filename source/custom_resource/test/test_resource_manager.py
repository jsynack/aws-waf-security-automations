######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
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

import logging
import json
import pytest
from resource_manager import ResourceManager
from unittest.mock import patch, MagicMock

log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_resource_manager')

resource_manager = ResourceManager(log)


def test_get_params_waf_event():
    event = {
        'ResourceProperties': {
            'WafLogBucket': 'WafLogBucket',
            'LogParser': 'LogParser',
            'HttpFloodLambdaLogParser': 'no',
            'HttpFloodAthenaLogParser': 'yes',
            'BadBotLambdaLogParser': 'no'
        }
    }
    expected = {
        'bucket_name': 'WafLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': None,
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_prefix': 'AWSLogs/'
    }
    res = resource_manager.get_params_waf_event(event)
    assert expected == res

def test_get_params_waf_event():
    event = {   
        'LogicalResourceId': 'ConfigureWafLogBucket',
        'RequestId': 'XXXXXXXXXXXX',
        'RequestType': 'Create',
        'ResourceProperties': {   
            'HttpFloodAthenaLogParser': 'yes',
            'HttpFloodLambdaLogParser': 'no',
            'BadBotLambdaLogParser': 'no',
            'LogParser': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan419115-LogParser-zouewUuDjyQU',
            'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan419115-CustomResource-VPiXt5B9MPb3',
            'WafLogBucket': 'wafmilan419115-waflogbucket-9qpon138lt2l'
        },
        'ResourceType': 'Custom::ConfigureWafLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-eusouth1.s3.eu-south-1.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan419115-CustomResource-VPiXt5B9MPb3',
        'StackId': 'arn:aws:cloudformation:eu-south-1:XXXXXXXXXXXX:stack/wafmilan419115/0adf74c0-deef-11ed-9c16-0e4abbb1ce6a'
    }
    expected = {
        'bucket_name': 'wafmilan419115-waflogbucket-9qpon138lt2l',
        'lambda_function_arn': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan419115-LogParser-zouewUuDjyQU',
        'lambda_log_partition_function_arn': None,
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_prefix': 'AWSLogs/'
    }
    res = resource_manager.get_params_waf_event(event)
    assert res == expected

def test_get_params_app_access_update():
    event = {
        'ResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
            'AppAccessLogBucketPrefix': 'prefix/'
        }
    }
    expected = {
        'bucket_name': 'AppAccessLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition',
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_prefix': 'prefix/'
    }
    res = resource_manager.get_params_app_access_update(event)
    assert res == expected

def test_get_params_app_access_update_prefix_match():
    event = {
        'ResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
            'AppAccessLogBucketPrefix': 'AWSLogs/'
        }
    }
    expected = {
        'bucket_name': 'AppAccessLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition',
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_prefix': 'AWSLogs/'
    }
    res = resource_manager.get_params_app_access_update(event)
    assert res == expected
    

def test_get_params_app_access_create_event():
    event = {
        'ResourceProperties': {
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'AppAccessLogBucketPrefix': 'prefix/'
        }
    }
    expected = {
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition',
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_name': 'AppAccessLogBucket',
        'bucket_prefix': 'prefix/'
    }
    res = resource_manager.get_params_app_access_create_event(event)
    assert res == expected

def test_get_params_app_access_create_event_prefix_match():
    event = {
        'ResourceProperties': {
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'AppAccessLogBucketPrefix': 'AWSLogs/'
        }
    }
    expected = {
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition',
        'bucket_name': 'AppAccessLogBucket',
        'lambda_parser': False,
        'athena_parser': True,
        'bucket_prefix': 'AWSLogs/'
    }
    res = resource_manager.get_params_app_access_create_event(event)
    assert expected == res

def test_contains_old_app_access_resources():
    event = {
        'ResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
            'AppAccessLogBucketPrefix': 'prefix/'
        },
        'OldResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition',
            'ScannersProbesLambdaLogParser': 'no',
            'ScannersProbesAthenaLogParser': 'yes',
        }
    }
    expected = True
    res = resource_manager.contains_old_app_access_resources(event)
    assert res == expected
    

def test_waf_has_old_resources():
    event = {
        'ResourceProperties': {
            'LogParser': 'LogParser',
            'HttpFloodLambdaLogParser': 'no',
            'HttpFloodAthenaLogParser': 'yes',
            'BadBotLambdaLogParser': 'no',
            'WafLogBucket': 'WafLogBucket'
        },
        'OldResourceProperties': {
            'LogParser': 'LogParser',
            'HttpFloodLambdaLogParser': 'no',
            'HttpFloodAthenaLogParser': 'yes',
            'BadBotLambdaLogParser': 'no',
            'WafLogBucket': 'WafLogBucket'
        }
    }
    expected = False
    res = resource_manager.waf_has_old_resources(event)
    assert res == expected

def test_get_params_bucket_lambda_delete_event():
    event = {
        'ResourceProperties': {
            'WafLogBucket': 'WafLogBucket',
            'LogParser': 'LogParser',
        }
    }
    expected = {
        'bucket_name': 'WafLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': None
    }
    res = resource_manager.get_params_bucket_lambda_delete_event(event)
    assert res == expected

def test_get_params_bucket_lambda_update_event():
    event = {
        'OldResourceProperties': {
            'WafLogBucket': 'WafLogBucket',
            'LogParser': 'LogParser'
        }
    }
    expected = {
        'bucket_name': 'WafLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': None
    }
    res = resource_manager.get_params_bucket_lambda_update_event(event)
    assert res == expected

def test_get_params_app_access_delete_event():
    event = {
        'ResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition'
        }
    }
    expected = {
        'bucket_name': 'AppAccessLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition'
    }
    res = resource_manager.get_params_app_access_delete_event(event)
    assert res == expected

def test_get_params_app_access_update_event():
    event = {
        'OldResourceProperties': {
            'AppAccessLogBucket': 'AppAccessLogBucket',
            'LogParser': 'LogParser',
            'MoveS3LogsForPartition': 'MoveS3LogsForPartition'
        }
    }
    expected = {
        'bucket_name': 'AppAccessLogBucket',
        'lambda_function_arn': 'LogParser',
        'lambda_log_partition_function_arn': 'MoveS3LogsForPartition'
    }
    res = resource_manager.get_params_app_access_update_event(event)
    assert res == expected

def test_update_lambda_config():
    toModify = {'LambdaFunctionConfigurations': []}
    resource_manager.update_lambda_config(
        notification_conf={
            'LambdaFunctionConfigurations': [
                {'LambdaFunctionArn': 'LambdaFunctionArn'},
                {'LambdaFunctionArn': 'NoMatch'}
            ]
            },
        new_conf=toModify,
        lambda_function_arn='LambdaFunctionArn',
        lambda_log_partition_function_arn=''
    )
    expected = {'LambdaFunctionConfigurations': [{'LambdaFunctionArn': 'NoMatch'}]}
    assert toModify == expected

@pytest.fixture
def resource_manager_magicmock():
    return ResourceManager(MagicMock())

@patch('resource_manager.create_client')
def test_add_athena_partitions(mock_create_client, resource_manager_magicmock):
    """
    Test add_athena_partitions method with valid payload and items
    """
    mock_lambda_client = MagicMock()
    mock_create_client.return_value = mock_lambda_client
    
    # Create the response with proper JSON payload
    mock_response = {
        'StatusCode': 200,
        'Payload': MagicMock()
    }
    # Set the read() return value as encoded JSON bytes
    mock_response['Payload'].read.return_value = json.dumps({
        "status": "success",
        "message": "Partitions added successfully"
    }).encode('utf-8')
    
    mock_lambda_client.invoke.return_value = mock_response

    event = {
        'ResourceProperties': {
            'AddAthenaPartitionsLambda': 'arn:aws:lambda:region:account:function:test-function:1',
            'ResourceType': 'Custom::AddAthenaPartitions',
            'GlueAccessLogsDatabase': 'test-database',
            'AppAccessLogBucket': 'XXXXXXXXXXX',
            'GlueAppAccessLogsTable': 'test-app-table',
            'GlueWafAccessLogsTable': 'test-waf-table',
            'WafLogBucket': 'XXXXXXXXXXXXXXX',
            'AthenaWorkGroup': 'test-workgroup'
        }
    }

    resource_manager.add_athena_partitions(event)

    mock_create_client.assert_called_once_with('lambda')
    mock_lambda_client.invoke.assert_called_once()

@patch('resource_manager.create_client')
def test_add_athena_partitions_with_empty_payload(mock_create_client, resource_manager_magicmock):
    """
    Test add_athena_partitions method with empty payload
    """
    mock_lambda_client = MagicMock()
    mock_create_client.return_value = mock_lambda_client
    
    # Create a mock response with minimal valid JSON payload
    mock_response = {
        'StatusCode': 200,
        'Payload': MagicMock()
    }
    
    # Configure the mock payload to return a null payload
    mock_response['Payload'].read.return_value = b'{}'
    
    mock_lambda_client.invoke.return_value = mock_response

    event = {
        'ResourceProperties': {
            'AddAthenaPartitionsLambda': 'arn:aws:lambda:region:account:function:test-function:1',
            'ResourceType': 'Custom::AddAthenaPartitions',
            'GlueAccessLogsDatabase': 'test-database',
            'AppAccessLogBucket': 'XXXXXXXXXXX',
            'GlueAppAccessLogsTable': 'test-app-table',
            'GlueWafAccessLogsTable': 'test-waf-table',
            'WafLogBucket': 'XXXXXXXXXXXXXXX',
            'AthenaWorkGroup': 'test-workgroup'
        }
    }

    resource_manager.add_athena_partitions(event)

    mock_create_client.assert_called_once_with('lambda')
    mock_lambda_client.invoke.assert_called_once()

    

def test_add_athena_partitions_empty_input():
    """Test add_athena_partitions with empty input"""
    with pytest.raises(KeyError):
        resource_manager.add_athena_partitions({})


def test_add_athena_partitions_invalid_json_response():
    """Test add_athena_partitions when Lambda returns invalid JSON"""
    event = {
        'ResourceProperties': {
            'ResourceType': 'CREATE',
            'AddAthenaPartitionsLambda': 'arn:aws:lambda:us-west-2:123456789012:function:test-function',
            'GlueAccessLogsDatabase': 'test-database',
            'AppAccessLogBucket': 'XXXXXXXXXXX',
            'GlueAppAccessLogsTable': 'test-table',
            'GlueWafAccessLogsTable': 'test-waf-table',
            'WafLogBucket': 'XXXXXXXXXXXXXXX',
            'AthenaWorkGroup': 'test-workgroup'
        }
    }
    with patch('resource_manager.create_client') as mock_create_client:
        mock_lambda = MagicMock()
        mock_create_client.return_value = mock_lambda
        mock_lambda.invoke.return_value = {
            'StatusCode': 200,
            'Payload': MagicMock(read=lambda: 'Invalid JSON'.encode('utf-8'))
        }
        with pytest.raises(json.JSONDecodeError):
            resource_manager.add_athena_partitions(event)