// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnParameter, Fn, NestedStackProps } from "aws-cdk-lib";
import { CfnTable } from "aws-cdk-lib/aws-glue";
import { GlueAccessLogsDatabase } from "../firehose-glue-access-logs-database";

interface GlueAppAccessLogsTablesProps extends NestedStackProps {
  albScannersProbesAthenaLogParser: CfnCondition;
  cloudFrontScannersProbesAthenaLogParser: CfnCondition;
  scannersProbesAthenaLogParser: CfnCondition;
  glueAccessLogsDatabase: GlueAccessLogsDatabase;
  parentStackName: CfnParameter;
  appAccessLogBucket: CfnParameter;
}

export class GlueAppAccessLogsTables extends Construct {
  public static readonly ALB_ID = "ALBGlueAppAccessLogsTable";
  public static readonly CLOUD_FRONT_ID = "CloudFrontGlueAppAccessLogsTable";
  public static readonly GLUE_APP_ACCESS_OUTPUT = "GlueAppAccessLogsTable";

  private readonly albTable: CfnTable;
  private readonly cloudFrontTable: CfnTable;

  constructor(
    scope: Construct,
    id: string,
    props: GlueAppAccessLogsTablesProps,
  ) {
    super(scope, id);

    // ALB Glue App Access Logs Table
    const albRegex =
      '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \\"([^ ]*) (.*) (- |[^ ]*)\\" \\"([^\\"]*)\\" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) \\"([^\\"]*)\\" \\"([^\\"]*)\\" \\"([^\\"]*)\\" ([-.0-9]*) ([^ ]*) \\"([^\\"]*)\\" \\"([^\\"]*)\\" \\"([^ ]*)\\" \\"([^\\\\s]+?)\\" \\"([^\\\\s]+)\\" \\"([^ ]*)\\" \\"([^ ]*)\\" ?([^ ]*)?';

    this.albTable = new CfnTable(this, GlueAppAccessLogsTables.ALB_ID, {
      databaseName: props.glueAccessLogsDatabase.getDatabase().ref,
      catalogId: Fn.ref("AWS::AccountId"),
      tableInput: {
        name: "app_access_logs",
        description: Fn.sub(
          `\${${props.parentStackName.logicalId}} - APP Access Logs`,
        ),
        parameters: { EXTERNAL: "TRUE" },
        tableType: "EXTERNAL_TABLE",
        partitionKeys: [
          { name: "year", type: "int" },
          { name: "month", type: "int" },
          { name: "day", type: "int" },
          { name: "hour", type: "int" },
        ],
        storageDescriptor: {
          location: Fn.sub("s3://${AppAccessLogBucket}/AWSLogs-Partitioned/", {
            AppAccessLogBucket: Fn.ref(props.appAccessLogBucket.logicalId),
          }),
          inputFormat: "org.apache.hadoop.mapred.TextInputFormat",
          outputFormat:
            "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
          serdeInfo: {
            parameters: {
              "serialization.format": "1",
              "input.regex": albRegex,
            },
            serializationLibrary: "org.apache.hadoop.hive.serde2.RegexSerDe",
          },
          compressed: true,
          storedAsSubDirectories: false,
          columns: [
            { name: "type", type: "string" },
            { name: "time", type: "string" },
            { name: "elb", type: "string" },
            { name: "client_ip", type: "string" },
            { name: "client_port", type: "int" },
            { name: "target_ip", type: "string" },
            { name: "target_port", type: "int" },
            { name: "request_processing_time", type: "double" },
            { name: "target_processing_time", type: "double" },
            { name: "response_processing_time", type: "double" },
            { name: "elb_status_code", type: "string" },
            { name: "target_status_code", type: "string" },
            { name: "received_bytes", type: "bigint" },
            { name: "sent_bytes", type: "bigint" },
            { name: "request_verb", type: "string" },
            { name: "request_url", type: "string" },
            { name: "request_proto", type: "string" },
            { name: "user_agent", type: "string" },
            { name: "ssl_cipher", type: "string" },
            { name: "ssl_protocol", type: "string" },
            { name: "target_group_arn", type: "string" },
            { name: "trace_id", type: "string" },
            { name: "domain_name", type: "string" },
            { name: "chosen_cert_arn", type: "string" },
            { name: "matched_rule_priority", type: "string" },
            { name: "request_creation_time", type: "string" },
            { name: "actions_executed", type: "string" },
            { name: "redirect_url", type: "string" },
            { name: "lambda_error_reason", type: "string" },
            { name: "new_field", type: "string" },
          ],
        },
      },
    });
    this.albTable.overrideLogicalId(GlueAppAccessLogsTables.ALB_ID);
    this.albTable.cfnOptions.condition = props.albScannersProbesAthenaLogParser;

    // CloudFront Glue App Access Logs Table
    this.cloudFrontTable = new CfnTable(
      this,
      GlueAppAccessLogsTables.CLOUD_FRONT_ID,
      {
        databaseName: props.glueAccessLogsDatabase.getDatabase().ref,
        catalogId: Fn.ref("AWS::AccountId"),
        tableInput: {
          name: "app_access_logs",
          description: Fn.sub(
            `\${${props.parentStackName.logicalId}} - APP Access Logs`,
          ),
          parameters: {
            "skip.header.line.count": "2",
            EXTERNAL: "TRUE",
          },
          tableType: "EXTERNAL_TABLE",
          partitionKeys: [
            { name: "year", type: "int" },
            { name: "month", type: "int" },
            { name: "day", type: "int" },
            { name: "hour", type: "int" },
          ],
          storageDescriptor: {
            location: Fn.sub(
              "s3://${AppAccessLogBucket}/AWSLogs-Partitioned/",
              {
                AppAccessLogBucket: Fn.ref(props.appAccessLogBucket.logicalId),
              },
            ),
            inputFormat: "org.apache.hadoop.mapred.TextInputFormat",
            outputFormat:
              "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            serdeInfo: {
              parameters: {
                "field.delim": "\t",
                "serialization.format": "\t",
              },
              serializationLibrary:
                "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
            },
            compressed: true,
            storedAsSubDirectories: true,
            columns: [
              { name: "date", type: "date" },
              { name: "time", type: "string" },
              { name: "location", type: "string" },
              { name: "bytes", type: "bigint" },
              { name: "requestip", type: "string" },
              { name: "method", type: "string" },
              { name: "host", type: "string" },
              { name: "uri", type: "string" },
              { name: "status", type: "int" },
              { name: "referrer", type: "string" },
              { name: "useragent", type: "string" },
              { name: "querystring", type: "string" },
              { name: "cookie", type: "string" },
              { name: "resulttype", type: "string" },
              { name: "requestid", type: "string" },
              { name: "hostheader", type: "string" },
              { name: "requestprotocol", type: "string" },
              { name: "requestbytes", type: "bigint" },
              { name: "timetaken", type: "float" },
              { name: "xforwardedfor", type: "string" },
              { name: "sslprotocol", type: "string" },
              { name: "sslcipher", type: "string" },
              { name: "responseresulttype", type: "string" },
              { name: "httpversion", type: "string" },
              { name: "filestatus", type: "string" },
              { name: "encryptedfields", type: "int" },
            ],
          },
        },
      },
    );
    this.cloudFrontTable.overrideLogicalId(
      GlueAppAccessLogsTables.CLOUD_FRONT_ID,
    );
    this.cloudFrontTable.cfnOptions.condition =
      props.cloudFrontScannersProbesAthenaLogParser;
  }

  public getAlbTable(): CfnTable {
    return this.albTable;
  }

  public getCloudFrontTable(): CfnTable {
    return this.cloudFrontTable;
  }
}
