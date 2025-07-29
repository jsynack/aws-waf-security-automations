// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnResource, CustomResource, Fn } from "aws-cdk-lib";
import { IFunction } from "aws-cdk-lib/aws-lambda";
import { distVersion, manifest } from "../../constants/waf-constants";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";
import { FirehoseAthenaNestedStack } from "../../nestedstacks/firehose-athena/firehose-athena-nestedstack";
import { FirehoseWAFLogsDelivery } from "../../nestedstacks/firehose-athena/components/firehose-logs-delivery";

export interface ConfigureAWSWAFLogsProps {
  httpFloodProtectionLogParserActivated: CfnCondition;
  badBotLambdaLogParserActivated: CfnCondition;
  helperFunction: IFunction;
  webACLStack: WebaclNestedstack;
  firehoseAthenaNestedStack: FirehoseAthenaNestedStack;
}

export class ConfigureAWSWAFLogs extends Construct {
  public readonly resource: CustomResource;
  public static readonly ID = "ConfigureAWSWAFLogs";
  public static readonly TYPE = "Custom::ConfigureAWSWAFLogs";

  constructor(scope: Construct, id: string, props: ConfigureAWSWAFLogsProps) {
    super(scope, id);

    const badBotWafLogLabel = Fn.sub(
      "awswaf:${AWS::AccountId}:webacl:${webAclId}:" +
        manifest.wafSecurityAutomations.batBot.ruleLabel,
      {
        webAclId: Fn.select(
          0,
          Fn.split(
            "|",
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFWebACL_OUTPUT,
            ).toString(),
          ),
        ),
      },
    );

    this.resource = new CustomResource(this, ConfigureAWSWAFLogs.ID, {
      serviceToken: props.helperFunction.functionArn,
      properties: {
        SolutionVersion: distVersion,
        WAFWebACLArn: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFWebACLArn_OUTPUT,
        ),
        DeliveryStreamArn: Fn.getAtt(
          props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
          "Outputs." + FirehoseWAFLogsDelivery.OUTPUT_ID,
        ),
        IsBadBotOnlyWAFLogs: Fn.conditionIf(
          props.badBotLambdaLogParserActivated.logicalId,
          "true",
          "false",
        ).toString(),
        BadBotWafLogLabel: badBotWafLogLabel,
      },
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.addOverride("Type", ConfigureAWSWAFLogs.TYPE);
    cfnResource.overrideLogicalId(ConfigureAWSWAFLogs.ID);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);
    cfnResource.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivated;
  }
}
