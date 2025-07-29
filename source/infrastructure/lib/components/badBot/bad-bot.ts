// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnOutput, Fn } from "aws-cdk-lib";
import { manifest } from "../../constants/waf-constants";

export interface BadBotProps {
  badBotProtectionActivated: CfnCondition;
}

export class BadBot extends Construct {
  constructor(scope: Construct, id: string, props: BadBotProps) {
    super(scope, id);

    const cfnOutputBadBotHoneypotEndpoint = new CfnOutput(
      this,
      "CfnOutputBadBotHoneypotEndpoint",
      {
        key: "BadBotHoneypotEndpoint",
        description: "Bad Bot Honeypot Endpoint",
        exportName: Fn.sub("${AWS::StackName}-BadBotHoneypotEndpoint"),
        value: "/" + manifest.wafSecurityAutomations.batBot.prodStageName,
      },
    );
    cfnOutputBadBotHoneypotEndpoint.condition = props.badBotProtectionActivated;
  }
}
