// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnCondition,
  CfnParameter,
  CfnResource,
  CustomResource,
  Fn,
  Stack,
} from "aws-cdk-lib";
import { IFunction } from "aws-cdk-lib/aws-lambda";

export interface CheckRequirementsProps {
  helperFunction: IFunction;
  athenaLogParser: CfnCondition;
  httpFloodProtectionRateBasedRuleActivated: CfnCondition;
  httpFloodProtectionLogParserActivated: CfnCondition;
  scannersProbesProtectionActivated: CfnCondition;
  appAccessLogBucket: CfnParameter;
  endpointType: CfnParameter;
  requestThreshold: CfnParameter;
}

export class CheckRequirements extends Construct {
  public readonly resource: CustomResource;
  public static readonly ID = "CheckRequirements";
  public static readonly TYPE = "Custom::CheckRequirements";

  constructor(scope: Construct, id: string, props: CheckRequirementsProps) {
    super(scope, id);

    this.resource = new CustomResource(this, "Resource", {
      resourceType: CheckRequirements.TYPE,
      serviceToken: props.helperFunction.functionArn,
      properties: {
        AthenaLogParser: Fn.conditionIf(
          props.athenaLogParser.logicalId,
          "yes",
          "no",
        ).toString(),
        HttpFloodProtectionRateBasedRuleActivated: Fn.conditionIf(
          props.httpFloodProtectionRateBasedRuleActivated.logicalId,
          "yes",
          "no",
        ).toString(),
        HttpFloodProtectionLogParserActivated: Fn.conditionIf(
          props.httpFloodProtectionLogParserActivated.logicalId,
          "yes",
          "no",
        ).toString(),
        ProtectionActivatedScannersProbes: Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          "yes",
          "no",
        ).toString(),
        AppAccessLogBucket: props.appAccessLogBucket.valueAsString,
        Region: Stack.of(this).region,
        EndpointType: props.endpointType.valueAsString,
        RequestThreshold: props.requestThreshold.valueAsString,
      },
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.addOverride("Type", CheckRequirements.TYPE);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);
    cfnResource.overrideLogicalId(CheckRequirements.ID);
  }
}
