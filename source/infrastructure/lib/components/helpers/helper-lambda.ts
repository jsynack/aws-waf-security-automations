// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnFunction,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { CfnRole, Role } from "aws-cdk-lib/aws-iam";
import { Aws, CfnCondition, Duration, Fn } from "aws-cdk-lib";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { SolutionMapping } from "../../mappings/solution";
import Utils from "../../mappings/utils";

export interface HelperLambdaProps {
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  albEndpoint: CfnCondition;
}

export class HelperLambda extends Construct {
  public static readonly ID = "Helper";
  private static readonly ROLE_ID = "LambdaRoleHelper";

  private readonly function: Function;

  constructor(scope: Construct, id: string, props: HelperLambdaProps) {
    super(scope, id);

    const cfnRole = new CfnRole(this, HelperLambda.ROLE_ID, {
      assumeRolePolicyDocument: {
        Version: "2012-10-17",
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
        {
          policyName: "S3Access",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "s3:GetBucketLocation",
                  "s3:GetObject",
                  "s3:ListBucket",
                ],
                Resource: [
                  Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                ],
              },
            ],
          },
        },
        {
          policyName: "WAFAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["wafv2:ListWebACLs"],
                Resource: [
                  Fn.sub(
                    "arn:${AWS::Partition}:wafv2:${AWS::Region}:${AWS::AccountId}:regional/webacl/*",
                  ),
                  Fn.sub(
                    "arn:${AWS::Partition}:wafv2:${AWS::Region}:${AWS::AccountId}:global/webacl/*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "LogsAccess",
          policyDocument: {
            Version: "2012-10-17",
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
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*Helper*",
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
    cfnRole.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W11",
          reason:
            "LogsAccess permission restricted to account, region and log group name substring (Helper).",
        },
        {
          id: "W76",
          reason:
            "The policy is long as it is scoped down to all the IP set ARNs and function ARNs.",
        },
      ],
    });
    cfnRole.overrideLogicalId(HelperLambda.ROLE_ID);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "helper.zip",
    ]);

    this.function = new Function(this, id, {
      description:
        "This lambda function verifies the main project's dependencies, requirements and implement auxiliary functions.",
      handler: "helper.lambda_handler",
      role: Role.fromRoleArn(this, "HelperRole", cfnRole.attrArn, {
        mutable: false,
      }),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      runtime: Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        SCOPE: Utils.getRegionScope(props.albEndpoint.logicalId),
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        POWERTOOLS_SERVICE_NAME: id,
      },
      tracing: Tracing.ACTIVE,
    });

    const cfnFunction = this.function.node.defaultChild as CfnFunction;
    cfnFunction.overrideLogicalId(HelperLambda.ID);
  }

  public getHelperFunction() {
    return this.function;
  }
}
