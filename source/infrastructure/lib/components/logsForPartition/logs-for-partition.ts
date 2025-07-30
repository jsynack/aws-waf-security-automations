// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnFunction,
  CfnPermission,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { SolutionMapping } from "../../mappings/solution";
import { Aws, CfnCondition, Duration, Fn } from "aws-cdk-lib";
import { CfnRole, Role } from "aws-cdk-lib/aws-iam";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { Bucket } from "aws-cdk-lib/aws-s3";

interface LogsForPartitionProps {
  appAccessLogBucket: string;
  scannersProbesAthenaLogParserCondition: CfnCondition;
  solutionMapping: SolutionMapping;
  sourceCodeMapping: SourceCodeMapping;
  keepDataInOriginalS3Location: string;
  endpointType: string;
}

export class LogsForPartition extends Construct {
  public static readonly ID = "LogsForPartitionResource";
  private static readonly ROLE_ID = "LambdaRolePartitionS3Logs";
  private static readonly FUNCTION_ID = "MoveS3LogsForPartition";
  private static readonly FUNCTION_PERMISSION_ID =
    "LambdaInvokePermissionMoveS3LogsForPartition";

  private readonly lambdaFunction: Function;

  constructor(scope: Construct, id: string, props: LogsForPartitionProps) {
    super(scope, id);

    const lambdaRole = new CfnRole(this, LogsForPartition.ROLE_ID, {
      assumeRolePolicyDocument: {
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: ["lambda.amazonaws.com"],
            },
            Action: ["sts:AssumeRole"],
          },
        ],
      },
      path: "/",
      policies: [
        Fn.conditionIf(
          props.scannersProbesAthenaLogParserCondition.logicalId,
          {
            PolicyName: "PartitionS3LogsAccess",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["s3:GetObject", "s3:DeleteObject", "s3:PutObject"],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/*",
                    ),
                  ],
                },
              ],
            },
          },
          Aws.NO_VALUE,
        ),
        {
          policyName: "LogsAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents",
                ],
                Resource: [
                  Fn.sub(
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*MoveS3LogsForPartition*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "XRayAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                Resource: ["*"],
              },
            ],
          },
        },
      ],
    });
    lambdaRole.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "LogsAccess - permission restricted to account, region and log group name substring (MoveS3LogsForPartition)",
          },
        ],
      },
    };
    lambdaRole.cfnOptions.condition =
      props.scannersProbesAthenaLogParserCondition;
    lambdaRole.overrideLogicalId(LogsForPartition.ROLE_ID);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "log_parser.zip",
    ]);

    this.lambdaFunction = new Function(this, LogsForPartition.FUNCTION_ID, {
      description:
        "This function is triggered by S3 event to move log files(upon their arrival in s3) from their original location to a partitioned folder structure created per timestamps in file names, hence allowing the usage of partitioning within AWS Athena.",
      handler: "partition_s3_logs.lambda_handler",
      role: Role.fromRoleArn(
        this,
        LogsForPartition.ROLE_ID + "ID",
        lambdaRole.attrArn,
        { mutable: false },
      ),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      runtime: Runtime.PYTHON_3_12,
      memorySize: 512,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        KEEP_ORIGINAL_DATA: props.keepDataInOriginalS3Location,
        ENDPOINT: props.endpointType,
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        POWERTOOLS_SERVICE_NAME: LogsForPartition.FUNCTION_ID,
      },
      tracing: Tracing.ACTIVE,
    });

    const cfnFunction = this.lambdaFunction.node.defaultChild as CfnFunction;
    cfnFunction.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W58",
          reason:
            "Log permissions are defined in the LambdaRolePartitionS3Logs policies",
        },
      ],
    });
    cfnFunction.cfnOptions.condition =
      props.scannersProbesAthenaLogParserCondition;
    cfnFunction.overrideLogicalId(LogsForPartition.FUNCTION_ID);

    const lambdaPermission = new CfnPermission(
      this,
      LogsForPartition.FUNCTION_PERMISSION_ID,
      {
        action: "lambda:InvokeFunction",
        functionName: this.lambdaFunction.functionArn,
        principal: "s3.amazonaws.com",
        sourceAccount: Aws.ACCOUNT_ID,
      },
    );
    lambdaPermission.cfnOptions.condition =
      props.scannersProbesAthenaLogParserCondition;
    lambdaPermission.overrideLogicalId(LogsForPartition.FUNCTION_PERMISSION_ID);
  }

  public getLambdaFunction(): Function {
    return this.lambdaFunction;
  }
}
