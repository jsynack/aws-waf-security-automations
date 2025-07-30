// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnCondition,
  CfnMapping,
  CfnOutput,
  CfnParameter,
  Fn,
} from "aws-cdk-lib";
import { CfnDeliveryStream } from "aws-cdk-lib/aws-kinesisfirehose";
import { CfnRole } from "aws-cdk-lib/aws-iam";
import Utils from "../../../mappings/utils";
import { manifest } from "../../../constants/waf-constants";

interface FirehoseWAFLogsDeliveryProps {
  httpFloodProtectionLogParserActivated: CfnCondition;
  httpFloodLambdaLogParser: CfnCondition;
  wafLogBucket: CfnParameter;
  wafLogBucketArn: CfnParameter;
  deliveryStreamName: CfnParameter;
  rateLimitMap: CfnMapping;
  timeWindowThreshold: CfnParameter;
}

export class FirehoseWAFLogsDelivery extends Construct {
  public static readonly ID = "FirehoseWAFLogsDeliveryStream";
  public static readonly OUTPUT_ID = "FirehoseWAFLogsDeliveryStreamArn";
  public static readonly ROLE_ID = "FirehoseWAFLogsDeliveryStreamRole";

  public readonly deliveryStreamArnOutput: CfnOutput;

  constructor(
    scope: Construct,
    id: string,
    props: FirehoseWAFLogsDeliveryProps,
  ) {
    super(scope, id);

    const role = new CfnRole(this, FirehoseWAFLogsDelivery.ROLE_ID, {
      assumeRolePolicyDocument: {
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: "firehose.amazonaws.com",
            },
            Action: "sts:AssumeRole",
            Condition: {
              StringEquals: {
                "sts:ExternalId": Fn.ref("AWS::AccountId"),
              },
            },
          },
        ],
      },
      policies: [
        {
          policyName: "S3Access",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "s3:AbortMultipartUpload",
                  "s3:GetBucketLocation",
                  "s3:GetObject",
                  "s3:ListBucket",
                  "s3:ListBucketMultipartUploads",
                  "s3:PutObject",
                ],
                Resource: [
                  Fn.sub(
                    `arn:\${AWS::Partition}:s3:::\${${props.wafLogBucket.logicalId}}`,
                  ),
                  Fn.sub(
                    `arn:\${AWS::Partition}:s3:::\${${props.wafLogBucket.logicalId}}/*`,
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "KinesisAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "kinesis:DescribeStream",
                  "kinesis:GetShardIterator",
                  "kinesis:GetRecords",
                ],
                Resource: [
                  Fn.sub(
                    `arn:\${AWS::Partition}:kinesis:\${AWS::Region}:\${AWS::AccountId}:stream/\${${props.deliveryStreamName.logicalId}}`,
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "CloudWatchAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["logs:PutLogEvents"],
                Resource: [
                  Fn.sub(
                    `arn:\${AWS::Partition}:logs:\${AWS::Region}:\${AWS::AccountId}:log-group:/aws/kinesisfirehose/\${${props.deliveryStreamName.logicalId}}:*`,
                  ),
                ],
              },
            ],
          },
        },
      ],
    });
    role.cfnOptions.condition = props.httpFloodProtectionLogParserActivated;
    role.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "S3Access restricted to WafLogBucket and CloudWatchAccess to DeliveryStreamName.",
          },
        ],
      },
    };

    role.overrideLogicalId(FirehoseWAFLogsDelivery.ROLE_ID);

    const timeRangeThreshold = props.rateLimitMap.findInMap(
      Fn.ref(props.timeWindowThreshold.logicalId),
      "seconds",
    );

    const deliveryStream = new CfnDeliveryStream(
      this,
      FirehoseWAFLogsDelivery.ID,
      {
        deliveryStreamName: Fn.ref(props.deliveryStreamName.logicalId),
        deliveryStreamType: "DirectPut",
        deliveryStreamEncryptionConfigurationInput: {
          keyType: "AWS_OWNED_CMK",
        },
        extendedS3DestinationConfiguration: {
          bucketArn: Fn.ref(props.wafLogBucketArn.logicalId),
          bufferingHints: {
            intervalInSeconds: Utils.safeNumberValue(
              Fn.conditionIf(
                props.httpFloodLambdaLogParser.logicalId,
                timeRangeThreshold,
                manifest.wafSecurityAutomations.firehoseWAFLogs
                  .timeWindowThresholdSeconds,
              ),
              manifest.wafSecurityAutomations.firehoseWAFLogs
                .timeWindowThresholdSeconds,
            ),
            sizeInMBs: 5,
          },
          compressionFormat: "GZIP",
          prefix:
            "AWSLogs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/",
          errorOutputPrefix:
            "AWSErrorLogs/result=!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/",
          roleArn: role.attrArn,
        },
      },
    );
    deliveryStream.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivated;
    deliveryStream.overrideLogicalId(FirehoseWAFLogsDelivery.ID);
    deliveryStream.addMetadata("guard", {
      SuppressedRules: [
        "KINESIS_FIREHOSE_REDSHIFT_DESTINATION_CONFIGURATION_NO_PLAINTEXT_PASSWORD",
        "KINESIS_FIREHOSE_SPLUNK_DESTINATION_CONFIGURATION_NO_PLAINTEXT_PASSWORD",
      ],
    });
    this.deliveryStreamArnOutput = new CfnOutput(
      this,
      FirehoseWAFLogsDelivery.OUTPUT_ID,
      {
        value: deliveryStream.attrArn,
        condition: props.httpFloodProtectionLogParserActivated,
      },
    );
    this.deliveryStreamArnOutput.overrideLogicalId(
      FirehoseWAFLogsDelivery.OUTPUT_ID,
    );
  }
}
