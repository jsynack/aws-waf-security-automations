// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { CfnRole } from "aws-cdk-lib/aws-iam";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";

interface LambdaRoleCustomResourceProps {
  webAclStack: WebaclNestedstack;
  httpFloodProtectionLogParserActivated: CfnCondition;
  scannersProbesLambdaLogParser: CfnCondition;
  httpFloodLambdaLogParser: CfnCondition;
  customResourceLambdaAccess: CfnCondition;
  scannersProbesProtectionActivated: CfnCondition;
}

export class LambdaRoleCustomResource extends Construct {
  public static readonly ID = "LambdaRoleCustomResource";

  private readonly role: CfnRole;

  constructor(
    scope: Construct,
    id: string,
    props: LambdaRoleCustomResourceProps,
  ) {
    super(scope, id);

    this.role = new CfnRole(this, LambdaRoleCustomResource.ID, {
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
        {
          policyName: "S3AccessGeneralAppAccessLog",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "s3:CreateBucket",
                  "s3:GetBucketNotification",
                  "s3:PutBucketNotification",
                  "s3:PutEncryptionConfiguration",
                  "s3:PutBucketPublicAccessBlock",
                ],
                Resource: [
                  Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                ],
              },
            ],
          },
        },
        Fn.conditionIf(
          props.httpFloodProtectionLogParserActivated.logicalId,
          {
            PolicyName: "S3AccessGeneralWafLog",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: [
                    "s3:CreateBucket",
                    "s3:GetBucketNotification",
                    "s3:PutBucketNotification",
                  ],
                  Resource: [
                    Fn.sub("arn:${AWS::Partition}:s3:::${WafLogBucket}"),
                  ],
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
        {
          policyName: "S3Access",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "s3:GetBucketLocation",
                  "s3:GetObject",
                  "s3:ListBucket",
                  "s3:PutBucketPolicy",
                ],
                Resource: [
                  Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                ],
              },
            ],
          },
        },
        Fn.conditionIf(
          props.scannersProbesLambdaLogParser.logicalId,
          {
            PolicyName: "S3AppAccessPut",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "s3:PutObject",
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/${AWS::StackName}-app_log_conf.json",
                    ),
                  ],
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
        Fn.conditionIf(
          props.httpFloodLambdaLogParser.logicalId,
          {
            PolicyName: "S3WafAccessPut",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "s3:PutObject",
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${WafLogBucket}/${AWS::StackName}-waf_log_conf.json",
                    ),
                  ],
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
        Fn.conditionIf(
          props.customResourceLambdaAccess.logicalId,
          {
            PolicyName: "LambdaAccess",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "lambda:InvokeFunction",
                  Resource: [
                    {
                      "Fn::Sub":
                        "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:*AddAthenaPartitions*",
                    },
                    {
                      "Fn::Sub":
                        "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:*ReputationListsParser*",
                    },
                  ],
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
        {
          policyName: "WAFAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "wafv2:GetWebACL",
                  "wafv2:UpdateWebACL",
                  "wafv2:DeleteLoggingConfiguration",
                ],
                Resource: [
                  Fn.getAtt(
                    props.webAclStack.nestedStackResource!.logicalId,
                    "Outputs." + WebaclNestedstack.WAFWebACLArn_OUTPUT,
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "IPSetAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["wafv2:GetIPSet", "wafv2:DeleteIPSet"],
                Resource: [
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:wafv2:${AWS::Region}:${AWS::AccountId}:regional/ipset/${AWS::StackName}*",
                  },
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:wafv2:${AWS::Region}:${AWS::AccountId}:global/ipset/${AWS::StackName}*",
                  },
                ],
              },
            ],
          },
        },
        Fn.conditionIf(
          props.httpFloodProtectionLogParserActivated.logicalId,
          {
            PolicyName: "WAFLogsAccess",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["wafv2:PutLoggingConfiguration"],
                  Resource: [
                    Fn.getAtt(
                      props.webAclStack.nestedStackResource!.logicalId,
                      "Outputs." + WebaclNestedstack.WAFWebACLArn_OUTPUT,
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: "iam:CreateServiceLinkedRole",
                  Resource: [
                    {
                      "Fn::Sub":
                        "arn:${AWS::Partition}:iam::*:role/aws-service-role/wafv2.amazonaws.com/AWSServiceRoleForWAFV2Logging",
                    },
                  ],
                  Condition: {
                    StringLike: {
                      "iam:AWSServiceName": "wafv2.amazonaws.com",
                    },
                  },
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
        {
          policyName: "CloudFormationAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: "cloudformation:DescribeStacks",
                Resource: [
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*",
                  },
                ],
              },
            ],
          },
        },
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
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*CustomResource*",
                  },
                ],
              },
            ],
          },
        },
        {
          policyName: "LogsGroupAccess",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["logs:DescribeLogGroups"],
                Resource: [
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:*",
                  },
                ],
              },
            ],
          },
        },
        {
          policyName: "LogsGroupRetentionAccess",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["logs:PutRetentionPolicy"],
                Resource: [
                  {
                    "Fn::Sub":
                      "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*",
                  },
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
        Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          {
            PolicyName: "S3BucketLoggingAccess",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["s3:GetBucketLogging", "s3:PutBucketLogging"],
                  Resource: [
                    Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                  ],
                },
              ],
            },
          },
          { Ref: "AWS::NoValue" },
        ),
      ],
    });
    this.role.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "WAFAccess, WAFRuleAccess, WAFIPSetAccess and WAFRateBasedRuleAccess - restricted to WafArnPrefix/AccountId; CloudFormationAccess - account, region and stack name; LogsAccess - permission restricted to account, region and log group name substring (CustomResource);",
          },
          {
            id: "W76",
            reason:
              "The policy is long as it is scoped down to all the IP set ARNs and function ARNs.",
          },
        ],
      },
    };
    this.role.overrideLogicalId(LambdaRoleCustomResource.ID);
  }

  public getRole() {
    return this.role;
  }
}
