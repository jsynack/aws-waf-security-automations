// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnOutput, CfnParameter, Fn } from "aws-cdk-lib";
import { CfnWorkGroup } from "aws-cdk-lib/aws-athena";

interface WAFAppAccessLogAthenaQueryWorkGroupProps {
  scannersProbesAthenaLogParser: CfnCondition;
  uuid: CfnParameter;
}

export class WAFAppAccessLogAthenaQueryWorkGroup extends Construct {
  public static readonly ID = "WAFAppAccessLogAthenaQueryWorkGroup";

  public readonly workGroupOutput: CfnOutput;

  constructor(
    scope: Construct,
    id: string,
    props: WAFAppAccessLogAthenaQueryWorkGroupProps,
  ) {
    super(scope, id);

    // Create the Athena WorkGroup
    const workGroup = new CfnWorkGroup(
      this,
      WAFAppAccessLogAthenaQueryWorkGroup.ID,
      {
        name: Fn.join("-", [
          WAFAppAccessLogAthenaQueryWorkGroup.ID,
          props.uuid.valueAsString,
        ]),
        description:
          "Athena WorkGroup for CloudFront or ALB application access log queries used by Security Automations for AWS WAF Solution",
        state: "ENABLED",
        recursiveDeleteOption: true,
        workGroupConfiguration: {
          publishCloudWatchMetricsEnabled: true,
          resultConfiguration: {
            encryptionConfiguration: {
              encryptionOption: "SSE_S3", // Use SSE-S3 encryption for query results
            },
          },
        },
      },
    );
    workGroup.overrideLogicalId(WAFAppAccessLogAthenaQueryWorkGroup.ID);
    workGroup.cfnOptions.condition = props.scannersProbesAthenaLogParser;

    // Create the output
    this.workGroupOutput = new CfnOutput(
      this,
      WAFAppAccessLogAthenaQueryWorkGroup.ID + "Output",
      {
        description:
          "Athena WorkGroup for CloudFront or ALB application access log queries used by Security Automations for AWS WAF Solution",
        value: workGroup.ref,
        condition: props.scannersProbesAthenaLogParser,
      },
    );
    this.workGroupOutput.overrideLogicalId(
      WAFAppAccessLogAthenaQueryWorkGroup.ID,
    );
  }
}
