// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { CfnRule, IRuleTarget, Rule } from "aws-cdk-lib/aws-events";
import { SetIPRetention } from "./set-ip-retention";

interface SetIPRetentionEventsRuleProps {
  ipRetentionPeriodCondition: CfnCondition;
  setIPRetention: SetIPRetention;
  webACLStack: WebaclNestedstack;
}

export class SetIPRetentionEventsRule extends Construct {
  public static readonly ID = "SetIPRetentionEventsRule";

  private readonly rule: Rule;

  constructor(
    scope: Construct,
    id: string,
    props: SetIPRetentionEventsRuleProps,
  ) {
    super(scope, id);

    this.rule = new Rule(this, SetIPRetentionEventsRule.ID, {
      description:
        "Security Automations for AWS WAF - Events rule for setting IP retention",
      eventPattern: {
        source: ["aws.wafv2"],
        detailType: ["AWS API Call via CloudTrail"],
        detail: {
          eventSource: ["wafv2.amazonaws.com"],
          eventName: ["UpdateIPSet"],
          requestParameters: {
            name: [
              Fn.getAtt(
                props.webACLStack.nestedStackResource!.logicalId,
                "Outputs." + WebaclNestedstack.NameWAFWhitelistSetV4_OUTPUT,
              ),
              Fn.getAtt(
                props.webACLStack.nestedStackResource!.logicalId,
                "Outputs." + WebaclNestedstack.NameWAFBlacklistSetV4_OUTPUT,
              ),
              Fn.getAtt(
                props.webACLStack.nestedStackResource!.logicalId,
                "Outputs." + WebaclNestedstack.NameWAFWhitelistSetV6_OUTPUT,
              ),
              Fn.getAtt(
                props.webACLStack.nestedStackResource!.logicalId,
                "Outputs." + WebaclNestedstack.NameWAFBlacklistSetV6_OUTPUT,
              ),
            ],
          },
        },
      },
      enabled: true,
    });

    const lambdaTarget: IRuleTarget = {
      bind: () => ({
        arn: props.setIPRetention.getFunction().functionArn,
        id: "SetIPRetentionLambda",
      }),
    };
    this.rule.addTarget(lambdaTarget);

    const cfnRule = this.rule.node.defaultChild as CfnRule;
    cfnRule.cfnOptions.condition = props.ipRetentionPeriodCondition;
    cfnRule.overrideLogicalId(SetIPRetentionEventsRule.ID);
  }

  public getRule(): Rule {
    return this.rule;
  }
}
