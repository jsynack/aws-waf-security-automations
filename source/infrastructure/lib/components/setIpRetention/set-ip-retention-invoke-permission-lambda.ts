// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition } from "aws-cdk-lib";
import { CfnPermission, IFunction } from "aws-cdk-lib/aws-lambda";
import { Rule } from "aws-cdk-lib/aws-events";

interface LambdaInvokePermissionSetIPRetentionProps {
  ipRetentionPeriodCondition: CfnCondition;
  setIPRetentionLambda: IFunction;
  setIPRetentionEventsRule: Rule;
}

export class LambdaInvokePermissionSetIPRetention extends Construct {
  public static readonly ID = "LambdaInvokePermissionSetIPRetention";

  constructor(
    scope: Construct,
    id: string,
    props: LambdaInvokePermissionSetIPRetentionProps,
  ) {
    super(scope, id);

    const lambdaPermission = new CfnPermission(
      this,
      LambdaInvokePermissionSetIPRetention.ID,
      {
        functionName: props.setIPRetentionLambda.functionName,
        action: "lambda:InvokeFunction",
        principal: "events.amazonaws.com",
        sourceArn: props.setIPRetentionEventsRule.ruleArn,
      },
    );

    lambdaPermission.cfnOptions.condition = props.ipRetentionPeriodCondition;
    lambdaPermission.overrideLogicalId(LambdaInvokePermissionSetIPRetention.ID);
  }
}
