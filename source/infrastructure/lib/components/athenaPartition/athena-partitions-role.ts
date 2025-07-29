// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { Aws, CfnCondition, Fn } from "aws-cdk-lib";
import { CfnRole } from "aws-cdk-lib/aws-iam";

interface LambdaRoleAddAthenaPartitionsProps {
  scannersProbesAthenaLogParserCondition: CfnCondition;
  httpFloodAthenaLogParserCondition: CfnCondition;
  athenaLogParser: CfnCondition;
}

export class LambdaRoleAddAthenaPartitions extends Construct {
  public static readonly ID = "LambdaRoleAddAthenaPartitions";

  private readonly role: CfnRole;

  constructor(
    scope: Construct,
    id: string,
    props: LambdaRoleAddAthenaPartitionsProps,
  ) {
    super(scope, id);

    this.role = new CfnRole(this, LambdaRoleAddAthenaPartitions.ID, {
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
            PolicyName: "AddAthenaPartitionsForAppAccessLog",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/athena_results/*",
                    ),
                    Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["athena:StartQueryExecution"],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:athena:${AWS::Region}:${AWS::AccountId}:workgroup/WAF*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: [
                    "glue:GetTable",
                    "glue:GetDatabase",
                    "glue:UpdateDatabase",
                    "glue:CreateDatabase",
                    "glue:BatchCreatePartition",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/default",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${WebACLStack.Outputs.GlueAccessLogsDatabase}",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/${WebACLStack.Outputs.GlueAccessLogsDatabase}/${WebACLStack.Outputs.GlueAppAccessLogsTable}",
                    ),
                  ],
                },
              ],
            },
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.httpFloodAthenaLogParserCondition.logicalId,
          {
            PolicyName: "AddAthenaPartitionsForWAFLog",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${WafLogBucket}/athena_results/*",
                    ),
                    Fn.sub("arn:${AWS::Partition}:s3:::${WafLogBucket}"),
                    Fn.sub("arn:${AWS::Partition}:s3:::${WafLogBucket}/*"),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["athena:StartQueryExecution"],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:athena:${AWS::Region}:${AWS::AccountId}:workgroup/WAF*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: [
                    "glue:GetTable",
                    "glue:GetDatabase",
                    "glue:UpdateDatabase",
                    "glue:CreateDatabase",
                    "glue:BatchCreatePartition",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/default",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${WebACLStack.Outputs.GlueAccessLogsDatabase}",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/${WebACLStack.Outputs.GlueAccessLogsDatabase}/${WebACLStack.Outputs.GlueWafAccessLogsTable}",
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
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*AddAthenaPartitions*",
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
    this.role.cfnOptions.condition = props.athenaLogParser;
    this.role.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W11",
          reason:
            "LogsAccess - permission restricted to account, region and log group name substring (AddAthenaPartitions)",
        },
      ],
    });
    this.role.overrideLogicalId(LambdaRoleAddAthenaPartitions.ID);
  }

  public getRole() {
    return this.role;
  }
}
