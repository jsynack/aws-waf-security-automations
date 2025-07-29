// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnOutput, CfnParameter, Fn } from "aws-cdk-lib";
import { CfnWorkGroup } from "aws-cdk-lib/aws-athena";

interface WAFLogAthenaQueryWorkGroupProps {
  httpFloodAthenaLogParser: CfnCondition;
  uuid: CfnParameter;
}

export class WAFLogAthenaQueryWorkGroup extends Construct {
  public static readonly ID = "WAFLogAthenaQueryWorkGroup";
  private readonly workGroupOutput: CfnOutput;

  constructor(
    scope: Construct,
    id: string,
    props: WAFLogAthenaQueryWorkGroupProps,
  ) {
    super(scope, id);

    const workGroup = new CfnWorkGroup(this, WAFLogAthenaQueryWorkGroup.ID, {
      name: Fn.join("-", [
        WAFLogAthenaQueryWorkGroup.ID,
        props.uuid.valueAsString,
      ]),
      description:
        "Athena WorkGroup for WAF log queries used by Security Automations for AWS WAF Solution",
      state: "ENABLED",
      recursiveDeleteOption: true,
      workGroupConfiguration: {
        publishCloudWatchMetricsEnabled: true,
        resultConfiguration: {
          encryptionConfiguration: {
            encryptionOption: "SSE_S3",
          },
        },
      },
    });
    workGroup.overrideLogicalId(WAFLogAthenaQueryWorkGroup.ID);
    workGroup.cfnOptions.condition = props.httpFloodAthenaLogParser;

    this.workGroupOutput = new CfnOutput(
      this,
      WAFLogAthenaQueryWorkGroup.ID + "CfnOutput",
      {
        description:
          "Athena WorkGroup for WAF log queries used by Security Automations for AWS WAF Solution",
        value: workGroup.ref,
        condition: props.httpFloodAthenaLogParser,
      },
    );
    this.workGroupOutput.overrideLogicalId(WAFLogAthenaQueryWorkGroup.ID);
  }
}
