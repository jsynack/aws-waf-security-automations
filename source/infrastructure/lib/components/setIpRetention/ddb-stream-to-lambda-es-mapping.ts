// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition } from "aws-cdk-lib";
import {
  CfnEventSourceMapping,
  IFunction,
  StartingPosition,
} from "aws-cdk-lib/aws-lambda";
import { CfnTable } from "aws-cdk-lib/aws-dynamodb";

interface DDBStreamToLambdaESMappingProps {
  ipRetentionPeriodCondition: CfnCondition;
  ipRetentionDDBTable: CfnTable;
  removeExpiredIPLambda: IFunction;
}

export class DDBStreamToLambdaESMapping extends Construct {
  public static readonly ID = "DDBStreamToLambdaESMapping";

  constructor(
    scope: Construct,
    id: string,
    props: DDBStreamToLambdaESMappingProps,
  ) {
    super(scope, id);

    const eventSourceMapping = new CfnEventSourceMapping(
      this,
      DDBStreamToLambdaESMapping.ID,
      {
        enabled: true,
        eventSourceArn: props.ipRetentionDDBTable.attrStreamArn,
        functionName: props.removeExpiredIPLambda.functionArn,
        startingPosition: StartingPosition.LATEST,
      },
    );

    eventSourceMapping.cfnOptions.condition = props.ipRetentionPeriodCondition;
    eventSourceMapping.overrideLogicalId(DDBStreamToLambdaESMapping.ID);
  }
}
