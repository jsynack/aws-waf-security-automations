// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnFunction, Function } from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";
import {
  Aws,
  CfnCondition,
  CfnResource,
  CustomResource,
  Fn,
} from "aws-cdk-lib";
import { CfnBucket } from "aws-cdk-lib/aws-s3";

interface ConfigureWafLogBucketProps {
  badBotLambdaLogParserActivated: CfnCondition;
  httpFloodProtectionLogParserActivatedCondition: CfnCondition;
  customResourceLambda: Function;
  wafLogBucket: CfnBucket;
  logParserCondition: CfnCondition;
  logParserLambda: CfnFunction;
  httpFloodLambdaLogParserCondition: CfnCondition;
  httpFloodAthenaLogParserCondition: CfnCondition;
}

export class ConfigureWafLogBucket extends Construct {
  public static readonly ID = "ConfigureWafLogBucket";

  constructor(scope: Construct, id: string, props: ConfigureWafLogBucketProps) {
    super(scope, id);

    const configureWafLogBucket = new CustomResource(
      this,
      ConfigureWafLogBucket.ID,
      {
        serviceToken: props.customResourceLambda.functionArn,
        resourceType: "Custom::" + ConfigureWafLogBucket.ID,
        properties: {
          WafLogBucket: props.wafLogBucket.ref,
          LogParser: Fn.conditionIf(
            props.logParserCondition.logicalId,
            props.logParserLambda.attrArn,
            Aws.NO_VALUE,
          ),
          HttpFloodLambdaLogParser: Fn.conditionIf(
            props.httpFloodLambdaLogParserCondition.logicalId,
            "yes",
            "no",
          ),
          BadBotLambdaLogParser: Fn.conditionIf(
            props.badBotLambdaLogParserActivated.logicalId,
            "yes",
            "no",
          ),
          HttpFloodAthenaLogParser: Fn.conditionIf(
            props.httpFloodAthenaLogParserCondition.logicalId,
            "yes",
            "no",
          ),
        },
      },
    );

    const cfnCustomResource = configureWafLogBucket.node
      .defaultChild as CfnResource;
    cfnCustomResource.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivatedCondition;
    cfnCustomResource.addOverride("UpdateReplacePolicy", undefined);
    cfnCustomResource.addOverride("DeletionPolicy", undefined);
    cfnCustomResource.overrideLogicalId(ConfigureWafLogBucket.ID);
  }
}
