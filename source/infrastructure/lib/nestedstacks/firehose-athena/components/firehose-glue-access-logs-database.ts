// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnDatabase } from "aws-cdk-lib/aws-glue";
import { CfnCondition, CfnParameter, Fn } from "aws-cdk-lib";

interface GlueAccessLogsDatabaseProps {
  athenaLogParser: CfnCondition;
  deliveryStreamName: CfnParameter;
  parentStackName: CfnParameter;
}

export class GlueAccessLogsDatabase extends Construct {
  public static readonly ID = "GlueAccessLogsDatabase";
  private readonly database: CfnDatabase;

  constructor(
    scope: Construct,
    id: string,
    props: GlueAccessLogsDatabaseProps,
  ) {
    super(scope, id);

    this.database = new CfnDatabase(this, GlueAccessLogsDatabase.ID, {
      catalogId: Fn.ref("AWS::AccountId"),
      databaseInput: {
        name: props.deliveryStreamName.valueAsString,
        description: Fn.sub(
          `\${${props.parentStackName.logicalId}} - Access Logs`,
        ),
      },
    });
    this.database.overrideLogicalId(GlueAccessLogsDatabase.ID);
    this.database.cfnOptions.condition = props.athenaLogParser;
  }

  public getDatabase(): CfnDatabase {
    return this.database;
  }
}
