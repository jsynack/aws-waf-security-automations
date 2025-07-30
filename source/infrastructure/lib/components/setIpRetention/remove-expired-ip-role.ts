// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";
import { CfnTable } from "aws-cdk-lib/aws-dynamodb";
import { CfnRole } from "aws-cdk-lib/aws-iam";

interface LambdaRoleRemoveExpiredIPProps {
  ipRetentionPeriodCondition: CfnCondition;
  webACLStack: WebaclNestedstack;
  ipRetentionDDBTable: CfnTable;
}

export class LambdaRoleRemoveExpiredIP extends Construct {
  public static readonly ID = "LambdaRoleRemoveExpiredIP";

  private readonly role: CfnRole;

  constructor(
    scope: Construct,
    id: string,
    props: LambdaRoleRemoveExpiredIPProps,
  ) {
    super(scope, id);

    this.role = new CfnRole(this, LambdaRoleRemoveExpiredIP.ID, {
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
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*RemoveExpiredIP*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "WAFAccess",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                Resource: [
                  Fn.getAtt(
                    props.webACLStack.nestedStackResource!.logicalId,
                    "Outputs." + WebaclNestedstack.WAFWhitelistSetV4Arn_OUTPUT,
                  ),
                  Fn.getAtt(
                    props.webACLStack.nestedStackResource!.logicalId,
                    "Outputs." + WebaclNestedstack.WAFBlacklistSetV4Arn_OUTPUT,
                  ),
                  Fn.getAtt(
                    props.webACLStack.nestedStackResource!.logicalId,
                    "Outputs." + WebaclNestedstack.WAFWhitelistSetV6Arn_OUTPUT,
                  ),
                  Fn.getAtt(
                    props.webACLStack.nestedStackResource!.logicalId,
                    "Outputs." + WebaclNestedstack.WAFBlacklistSetV6Arn_OUTPUT,
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "DDBStreamAccess",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "dynamodb:GetShardIterator",
                  "dynamodb:DescribeStream",
                  "dynamodb:GetRecords",
                  "dynamodb:ListStreams",
                ],
                Resource: [props.ipRetentionDDBTable.attrStreamArn],
              },
            ],
          },
        },
        {
          policyName: "InvokeLambda",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["lambda:InvokeFunction"],
                Resource: [props.ipRetentionDDBTable.attrStreamArn],
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
    this.role.cfnOptions.condition = props.ipRetentionPeriodCondition;

    this.role.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "LogsAccess permission restricted to account, region and log group name substring (RemoveExpiredIP).",
          },
        ],
      },
    };

    this.role.overrideLogicalId(LambdaRoleRemoveExpiredIP.ID);
  }

  public getRole() {
    return this.role;
  }
}
