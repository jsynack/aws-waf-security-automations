// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnParameter, Fn } from "aws-cdk-lib";
import { CfnTable } from "aws-cdk-lib/aws-glue";
import { GlueAccessLogsDatabase } from "../firehose-glue-access-logs-database";

interface GlueWafAccessLogsTableProps {
  httpFloodAthenaLogParser: CfnCondition;
  glueAccessLogsDatabase: GlueAccessLogsDatabase;
  wafLogBucket: CfnParameter;
}

export class GlueWafAccessLogsTable extends Construct {
  public static readonly ID = "GlueWafAccessLogsTable";

  private readonly table: CfnTable;

  constructor(
    scope: Construct,
    id: string,
    props: GlueWafAccessLogsTableProps,
  ) {
    super(scope, id);

    this.table = new CfnTable(this, GlueWafAccessLogsTable.ID, {
      databaseName: props.glueAccessLogsDatabase.getDatabase().ref,
      catalogId: Fn.ref("AWS::AccountId"),
      tableInput: {
        name: "waf_access_logs",
        parameters: {
          EXTERNAL: "TRUE",
        },
        partitionKeys: [
          { name: "year", type: "int" },
          { name: "month", type: "int" },
          { name: "day", type: "int" },
          { name: "hour", type: "int" },
        ],
        storageDescriptor: {
          location: Fn.sub(`s3://\${${props.wafLogBucket.logicalId}}/AWSLogs/`),
          inputFormat: "org.apache.hadoop.mapred.TextInputFormat",
          outputFormat:
            "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
          serdeInfo: {
            parameters: {
              paths:
                "action,formatVersion,httpRequest,httpSourceId,httpSourceName,nonTerminatingMatchingRules,rateBasedRuleList,ruleGroupList,terminatingRuleId,terminatingRuleType,timestamp,webaclId",
            },
            serializationLibrary: "org.openx.data.jsonserde.JsonSerDe",
          },
          compressed: true,
          storedAsSubDirectories: false,
          columns: [
            { name: "timestamp", type: "bigint" },
            { name: "formatversion", type: "int" },
            { name: "webaclid", type: "string" },
            { name: "terminatingruleid", type: "string" },
            { name: "terminatingruletype", type: "string" },
            { name: "action", type: "string" },
            { name: "httpsourcename", type: "string" },
            { name: "httpsourceid", type: "string" },
            { name: "rulegrouplist", type: "array<string>" },
            { name: "ratebasedrulelist", type: "array<string>" },
            { name: "nonterminatingmatchingrules", type: "array<string>" },
            {
              name: "httprequest",
              type: "struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,args:string,httpversion:string,httpmethod:string,requestid:string>",
            },
          ],
        },
      },
    });
    this.table.overrideLogicalId(GlueWafAccessLogsTable.ID);
    this.table.cfnOptions.condition = props.httpFloodAthenaLogParser;
  }

  public getTable(): CfnTable {
    return this.table;
  }
}
