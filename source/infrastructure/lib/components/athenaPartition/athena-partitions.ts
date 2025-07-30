// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CfnFunction,
  CfnPermission,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";
import { CfnRole, Role } from "aws-cdk-lib/aws-iam";
import {
  Aws,
  CfnCondition,
  CfnParameter,
  CfnResource,
  CustomResource,
  Duration,
  Fn,
  Token,
} from "aws-cdk-lib";
import { SolutionMapping } from "../../mappings/solution";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { Bucket, CfnBucket } from "aws-cdk-lib/aws-s3";
import { LambdaRoleAddAthenaPartitions } from "./athena-partitions-role";
import { CfnRule } from "aws-cdk-lib/aws-events";
import { FirehoseAthenaNestedStack } from "../../nestedstacks/firehose-athena/firehose-athena-nestedstack";
import { GlueWafAccessLogsTable } from "../../nestedstacks/firehose-athena/components/tables/firehose-glue-waf-access-logs";
import { GlueAppAccessLogsTables } from "../../nestedstacks/firehose-athena/components/tables/firehose-glue-app-access-logs";
import { WAFAddPartitionAthenaQueryWorkGroup } from "../../nestedstacks/firehose-athena/components/workgroups/firehose-waf-add-partition";
import { GlueAccessLogsDatabase } from "../../nestedstacks/firehose-athena/components/firehose-glue-access-logs-database";
import { CustomResourceLambda } from "../customResource/custom-resource-lambda";

interface AddAthenaPartitionsProps {
  athenaLogParserCondition: CfnCondition;
  lambdaRoleAddAthena: CfnRole;
  solutionMapping: SolutionMapping;
  scannersProbesAthenaLogParserCondition: CfnCondition;
  httpFloodAthenaLogParserCondition: CfnCondition;
  sourceCodeMapping: SourceCodeMapping;
  firehoseAthenaNestedStack: FirehoseAthenaNestedStack;
  appAccessLogBucket: CfnParameter;
  wafLogBucket: CfnBucket;
  customResource: CustomResourceLambda;
}

export class AddAthenaPartitions extends Construct {
  public static readonly ID = "AddAthenaPartitionsResource";
  private static readonly FUNCTION_ID = "AddAthenaPartitions";
  private static readonly RULE_ID = "LambdaAddAthenaPartitionsEventsRule";
  private static readonly CUSTOM_ID = "CustomAddAthenaPartitions";
  private static readonly PERMISSION_ID = "LambdaPermissionAddAthenaPartitions";

  private readonly lambdaFunction: Function;

  constructor(scope: Construct, id: string, props: AddAthenaPartitionsProps) {
    super(scope, id);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "log_parser.zip",
    ]);

    this.lambdaFunction = new Function(this, AddAthenaPartitions.FUNCTION_ID, {
      description:
        "This function adds a new hourly partition to athena table. It runs every hour, triggered by a CloudWatch event.",
      handler: "add_athena_partitions.lambda_handler",
      role: Role.fromRoleArn(
        this,
        LambdaRoleAddAthenaPartitions.ID,
        props.lambdaRoleAddAthena.attrArn,
        { mutable: false },
      ),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      runtime: Runtime.PYTHON_3_12,
      memorySize: 512,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        POWERTOOLS_SERVICE_NAME: AddAthenaPartitions.FUNCTION_ID,
      },
      tracing: Tracing.ACTIVE,
    });

    const cfnFunction = this.lambdaFunction.node.defaultChild as CfnFunction;
    cfnFunction.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W58",
          reason:
            "Log permissions are defined in the LambdaRoleAddAthenaPartitions policies",
        },
      ],
    });
    cfnFunction.cfnOptions.condition = props.athenaLogParserCondition;
    cfnFunction.overrideLogicalId(AddAthenaPartitions.FUNCTION_ID);

    const rule = new CfnRule(this, AddAthenaPartitions.RULE_ID, {
      description: "Security Automations - Add partitions to Athena table",
      scheduleExpression: "cron(0 * * * ? *)",
      state: "ENABLED",
      targets: [
        {
          arn: this.lambdaFunction.functionArn,
          id: "LambdaAddAthenaPartitions",
          input: Fn.sub(
            '{\n  "resourceType": "LambdaAddAthenaPartitionsEventsRule",\n  "glueAccessLogsDatabase": "${GlueAccessLogsDatabase}",\n  "accessLogBucket": "${AppAccessLogBucket}",\n  "glueAppAccessLogsTable": "${GlueAppAccessLogsTable}",\n  "glueWafAccessLogsTable": "${GlueWafAccessLogsTable}",\n  "wafLogBucket": "${WafLogBucket}",\n  "athenaWorkGroup": "${AthenaWorkGroup}"\n}',
            {
              GlueAccessLogsDatabase: Token.asString(
                Fn.getAtt(
                  props.firehoseAthenaNestedStack.nestedStackResource!
                    .logicalId,
                  "Outputs." + GlueAccessLogsDatabase.ID,
                ),
              ),
              AppAccessLogBucket: Fn.conditionIf(
                props.scannersProbesAthenaLogParserCondition.logicalId,
                props.appAccessLogBucket.valueAsString,
                "",
              ).toString(),
              GlueAppAccessLogsTable: Fn.conditionIf(
                props.scannersProbesAthenaLogParserCondition.logicalId,
                Fn.getAtt(
                  props.firehoseAthenaNestedStack.nestedStackResource!
                    .logicalId,
                  "Outputs." + GlueAppAccessLogsTables.GLUE_APP_ACCESS_OUTPUT,
                ),
                "",
              ).toString(),
              GlueWafAccessLogsTable: Fn.conditionIf(
                props.httpFloodAthenaLogParserCondition.logicalId,
                Fn.getAtt(
                  props.firehoseAthenaNestedStack.nestedStackResource!
                    .logicalId,
                  "Outputs." + GlueWafAccessLogsTable.ID,
                ),
                "",
              ).toString(),
              WafLogBucket: Fn.conditionIf(
                props.httpFloodAthenaLogParserCondition.logicalId,
                props.wafLogBucket.ref,
                "",
              ).toString(),
              AthenaWorkGroup: Fn.getAtt(
                props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
                "Outputs." + WAFAddPartitionAthenaQueryWorkGroup.ID,
              ).toString(),
            },
          ),
        },
      ],
    });

    // Add condition
    rule.overrideLogicalId(AddAthenaPartitions.RULE_ID);
    rule.cfnOptions.condition = props.athenaLogParserCondition;

    // LambdaPermissionAddAthenaPartitions permission
    const lambdaPermission = new CfnPermission(
      this,
      AddAthenaPartitions.PERMISSION_ID,
      {
        functionName: this.lambdaFunction.functionArn,
        action: "lambda:InvokeFunction",
        principal: "events.amazonaws.com",
        sourceArn: rule.attrArn,
      },
    );
    lambdaPermission.cfnOptions.condition = props.athenaLogParserCondition;
    lambdaPermission.overrideLogicalId(AddAthenaPartitions.PERMISSION_ID);

    // CustomAddAthenaPartitions custom
    const customResource = new CustomResource(
      this,
      AddAthenaPartitions.CUSTOM_ID,
      {
        serviceToken: props.customResource.getFunction().functionArn,
        resourceType: "Custom::AddAthenaPartitions",
        properties: {
          AddAthenaPartitionsLambda: this.lambdaFunction.functionArn,
          ResourceType: "CustomResource",
          GlueAccessLogsDatabase: Token.asString(
            Fn.getAtt(
              props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
              "Outputs." + GlueAccessLogsDatabase.ID,
            ),
          ),
          AppAccessLogBucket: Fn.conditionIf(
            props.scannersProbesAthenaLogParserCondition.logicalId,
            props.appAccessLogBucket.valueAsString,
            "",
          ).toString(),
          GlueAppAccessLogsTable: Fn.conditionIf(
            props.scannersProbesAthenaLogParserCondition.logicalId,
            Fn.getAtt(
              props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
              "Outputs." + GlueAppAccessLogsTables.GLUE_APP_ACCESS_OUTPUT,
            ),
            "",
          ).toString(),
          GlueWafAccessLogsTable: Fn.conditionIf(
            props.httpFloodAthenaLogParserCondition.logicalId,
            Fn.getAtt(
              props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
              "Outputs." + GlueWafAccessLogsTable.ID,
            ),
            "",
          ).toString(),
          WafLogBucket: Fn.conditionIf(
            props.httpFloodAthenaLogParserCondition.logicalId,
            props.wafLogBucket.ref,
            "",
          ).toString(),
          AthenaWorkGroup: Fn.getAtt(
            props.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
            "Outputs." + WAFAddPartitionAthenaQueryWorkGroup.ID,
          ),
        },
      },
    );

    const cfnCustomResource = customResource.node.defaultChild as CfnResource;
    cfnCustomResource.cfnOptions.condition = props.athenaLogParserCondition;
    cfnCustomResource.overrideLogicalId(AddAthenaPartitions.CUSTOM_ID);
    cfnCustomResource.addOverride("DeletionPolicy", undefined);
    cfnCustomResource.addOverride("UpdateReplacePolicy", undefined);
  }

  public getFunction() {
    return this.lambdaFunction;
  }
}
