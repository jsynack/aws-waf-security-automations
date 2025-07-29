// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { CfnTable } from "aws-cdk-lib/aws-dynamodb";
import { CfnRole } from "aws-cdk-lib/aws-iam";

interface LambdaRoleSetIPRetentionProps {
  ipRetentionPeriodCondition: CfnCondition;
  ipRetentionDDBTable: CfnTable;
}

export class LambdaRoleSetIPRetention extends Construct {
  public static readonly ID = "LambdaRoleSetIPRetention";

  public readonly role: CfnRole;

  constructor(
    scope: Construct,
    id: string,
    props: LambdaRoleSetIPRetentionProps,
  ) {
    super(scope, id);

    this.role = new CfnRole(this, LambdaRoleSetIPRetention.ID, {
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
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*SetIPRetention*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "DDBAccess",
          policyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["dynamodb:PutItem"],
                Resource: [props.ipRetentionDDBTable.attrArn],
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
    this.role.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W11",
          reason:
            "LogsAccess permission restricted to account, region and log group name substring (SetIPRetention).",
        },
      ],
    });
    this.role.overrideLogicalId(LambdaRoleSetIPRetention.ID);
  }

  public getRole() {
    return this.role;
  }
}
