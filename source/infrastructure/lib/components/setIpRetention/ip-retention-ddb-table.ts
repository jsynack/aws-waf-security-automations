// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition } from "aws-cdk-lib";
import { CfnTable } from "aws-cdk-lib/aws-dynamodb";

interface IPRetentionDDBTableProps {
  ipRetentionPeriodCondition: CfnCondition;
}

export class IPRetentionDDBTable extends Construct {
  public static readonly ID = "IPRetentionDDBTable";
  private readonly table: CfnTable;

  constructor(scope: Construct, id: string, props: IPRetentionDDBTableProps) {
    super(scope, id);

    this.table = new CfnTable(this, IPRetentionDDBTable.ID, {
      attributeDefinitions: [
        {
          attributeName: "IPSetId",
          attributeType: "S",
        },
        {
          attributeName: "ExpirationTime",
          attributeType: "N",
        },
      ],
      billingMode: "PAY_PER_REQUEST",
      keySchema: [
        {
          attributeName: "IPSetId",
          keyType: "HASH",
        },
        {
          attributeName: "ExpirationTime",
          keyType: "RANGE",
        },
      ],
      sseSpecification: {
        sseEnabled: true,
        sseType: "KMS",
      },
      streamSpecification: {
        streamViewType: "OLD_IMAGE",
      },
      timeToLiveSpecification: {
        attributeName: "ExpirationTime",
        enabled: true,
      },
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
    });
    this.table.cfnOptions.condition = props.ipRetentionPeriodCondition;
    this.table.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W78",
            reason:
              "This DynamoDB table constains transactional ip retention data that will be expired by DynamoDB TTL. The data doesn't need to be retained after its lifecycle ends.",
          },
        ],
      },
      guard: {
        SuppressedRules: ["DYNAMODB_TABLE_ENCRYPTED_KMS"],
        Reason: "DynamoDB Table encrypted using AWS Managed encryption",
      },
    };
    this.table.overrideLogicalId(IPRetentionDDBTable.ID);
  }

  public getTable() {
    return this.table;
  }
}
