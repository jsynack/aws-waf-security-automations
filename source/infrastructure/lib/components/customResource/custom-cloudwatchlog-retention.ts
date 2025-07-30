// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnCondition,
  CfnOutput,
  CfnResource,
  CfnParameter,
  CustomResource,
  Fn,
} from "aws-cdk-lib";
import { IFunction } from "aws-cdk-lib/aws-lambda";

import { CheckRequirements } from "../customs/check-requirements";
import { distVersion } from "../../constants/waf-constants";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";

interface CloudWatchLogRetentionProps {
  customResource: IFunction;
  parameters: { [key: string]: CfnParameter | string };
  webaclOutputs: { [key: string]: CfnOutput };
  logParserName?: string;
  helperName: string;
  moveS3LogsForPartitionName?: string;
  addAthenaPartitionsName?: string;
  setIPRetentionName?: string;
  removeExpiredIPName?: string;
  reputationListsParserName?: string;
  logGroupRetentionEnabled: CfnCondition;
  athenaLogParser: CfnCondition;
  badBotProtectionActivated: CfnCondition;
  scannersProbesAthenaLogParser: CfnCondition;
  reputationListsProtectionActivated: CfnCondition;
  logParser: CfnCondition;
  ipRetentionPeriod: CfnCondition;
  checkRequirements: CheckRequirements;
  webACLStack: WebaclNestedstack;
}

export class CloudWatchLogRetention extends Construct {
  public static readonly ID = "SetCloudWatchLogGroupRetention";
  public static readonly TYPE = "Custom::SetCloudWatchLogGroupRetention";

  constructor(
    scope: Construct,
    id: string,
    props: CloudWatchLogRetentionProps,
  ) {
    super(scope, id);

    const setCloudWatchLogGroupRetention = new CustomResource(
      this,
      CloudWatchLogRetention.ID,
      {
        serviceToken: props.customResource.functionArn,
        resourceType: CloudWatchLogRetention.TYPE,
        properties: {
          StackName: Fn.ref("AWS::StackName"),
          SolutionVersion: distVersion,
          LogGroupRetention: props.parameters.logGroupRetention,
          LogParserLambdaName: Fn.conditionIf(
            props.logParser.logicalId,
            props.logParserName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          HelperLambdaName: props.helperName,
          MoveS3LogsForPartitionLambdaName: Fn.conditionIf(
            props.scannersProbesAthenaLogParser.logicalId,
            props.moveS3LogsForPartitionName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          AddAthenaPartitionsLambdaName: Fn.conditionIf(
            props.athenaLogParser.logicalId,
            props.addAthenaPartitionsName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          SetIPRetentionLambdaName: Fn.conditionIf(
            props.ipRetentionPeriod.logicalId,
            props.setIPRetentionName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          RemoveExpiredIPLambdaName: Fn.conditionIf(
            props.ipRetentionPeriod.logicalId,
            props.removeExpiredIPName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          ReputationListsParserLambdaName: Fn.conditionIf(
            props.reputationListsProtectionActivated.logicalId,
            props.reputationListsParserName,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          CustomResourceLambdaName: props.customResource.functionName,
          CustomTimerLambdaName: Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.CustomTimerFunctionName_OUTPUT,
          ).toString(),
        },
      },
    );

    const cfnSetCloudWatchLogGroupRetention = setCloudWatchLogGroupRetention
      .node.defaultChild as CfnResource;
    cfnSetCloudWatchLogGroupRetention.addOverride(
      "DependsOn",
      props.checkRequirements.node.id,
    );
    cfnSetCloudWatchLogGroupRetention.addOverride("DeletionPolicy", undefined);
    cfnSetCloudWatchLogGroupRetention.cfnOptions.condition =
      props.logGroupRetentionEnabled;
    cfnSetCloudWatchLogGroupRetention.addOverride(
      "UpdateReplacePolicy",
      undefined,
    );
    cfnSetCloudWatchLogGroupRetention.overrideLogicalId(
      CloudWatchLogRetention.ID,
    );
  }
}
