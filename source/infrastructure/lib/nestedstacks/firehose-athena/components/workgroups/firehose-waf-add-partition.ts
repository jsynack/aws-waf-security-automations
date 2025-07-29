// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnParameter, Fn } from "aws-cdk-lib";
import { CfnWorkGroup } from "aws-cdk-lib/aws-athena";

interface WAFAddPartitionAthenaQueryWorkGroupProps {
  athenaLogParser: CfnCondition;
  uuid: CfnParameter;
}

export class WAFAddPartitionAthenaQueryWorkGroup extends Construct {
  public static readonly ID = "WAFAddPartitionAthenaQueryWorkGroup";

  private readonly workGroup: CfnWorkGroup;

  constructor(
    scope: Construct,
    id: string,
    props: WAFAddPartitionAthenaQueryWorkGroupProps,
  ) {
    super(scope, id);

    this.workGroup = new CfnWorkGroup(
      this,
      WAFAddPartitionAthenaQueryWorkGroup.ID,
      {
        name: Fn.join("-", [
          WAFAddPartitionAthenaQueryWorkGroup.ID,
          props.uuid.valueAsString,
        ]),
        description:
          "Athena WorkGroup for adding Athena partition queries used by Security Automations for AWS WAF Solution",
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
      },
    );

    this.workGroup.overrideLogicalId(WAFAddPartitionAthenaQueryWorkGroup.ID);
    this.workGroup.cfnOptions.condition = props.athenaLogParser;
  }

  public getWorkGroup() {
    return this.workGroup;
  }
}
