// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @description
 * Security Automations for AWS WAF - Firehose Athena Nested Stack
 * @author @aws-solutions
 */
import { Construct } from "constructs";
import {
  CfnCondition,
  CfnMapping,
  CfnOutput,
  CfnParameter,
  CfnStack,
  Fn,
  NestedStack,
  NestedStackProps,
} from "aws-cdk-lib";
import { firehoseAthenaManifest } from "./constants/firehose-constants";
import { CheckRequirements } from "../../components/customs/check-requirements";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { FirehoseWAFLogsDelivery } from "./components/firehose-logs-delivery";
import { GlueAccessLogsDatabase } from "./components/firehose-glue-access-logs-database";
import { GlueWafAccessLogsTable } from "./components/tables/firehose-glue-waf-access-logs";
import { GlueAppAccessLogsTables } from "./components/tables/firehose-glue-app-access-logs";
import { WAFAddPartitionAthenaQueryWorkGroup } from "./components/workgroups/firehose-waf-add-partition";
import { WAFLogAthenaQueryWorkGroup } from "./components/workgroups/firehose-waf-log-athena";
import { WAFAppAccessLogAthenaQueryWorkGroup } from "./components/workgroups/firehose-waf-app-access-log";
import { distVersion } from "../../constants/waf-constants";

interface FirehoseAthenaNestedStackProps extends NestedStackProps {
  createFirehoseAthenaStack: CfnCondition;
  checkRequirements: CheckRequirements;
  sourceCodeMapping: SourceCodeMapping;
}

export class FirehoseAthenaNestedStack extends NestedStack {
  public static readonly ID = "FirehoseAthenaStack";
  public static readonly NAME = "FirehoseAthena";

  public readonly outputs: { [key: string]: CfnOutput } = {};

  public constructor(
    scope: Construct,
    id: string,
    props: FirehoseAthenaNestedStackProps,
  ) {
    super(scope, id, props);

    const firehoseAthenaNestedStackCfnResource = this.node
      .defaultChild as CfnStack;
    firehoseAthenaNestedStackCfnResource.cfnOptions.condition =
      props.createFirehoseAthenaStack;
    firehoseAthenaNestedStackCfnResource.addOverride(
      "DependsOn",
      props.checkRequirements.node.id,
    );
    firehoseAthenaNestedStackCfnResource.addOverride(
      "UpdateReplacePolicy",
      undefined,
    );
    firehoseAthenaNestedStackCfnResource.addOverride(
      "DeletionPolicy",
      undefined,
    );
    firehoseAthenaNestedStackCfnResource.overrideLogicalId(
      FirehoseAthenaNestedStack.ID,
    );
    const templateUrl = `https://\${S3Bucket}.s3.amazonaws.com/\${KeyPrefix}/${firehoseAthenaManifest.wafSecurityAutomations.firehoseAthenaTemplateId}.template`;
    firehoseAthenaNestedStackCfnResource.templateUrl = Fn.sub(templateUrl, {
      S3Bucket: props.sourceCodeMapping.findInMap("General", "TemplateBucket"),
      KeyPrefix: props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
    });

    //=============================================================================================
    // Metadata
    //=============================================================================================
    this.templateOptions.description =
      firehoseAthenaManifest.firehoseAthena.description;
    this.templateOptions.templateFormatVersion =
      firehoseAthenaManifest.awsTemplateFormatVersion;

    //=============================================================================================
    // Parameters
    //=============================================================================================
    const timeWindowThreshold = new CfnParameter(
      this,
      "TimeWindowThresholdParam",
      {
        type: "Number",
      },
    );

    const activateHttpFloodProtectionParam = new CfnParameter(
      this,
      "ActivateHttpFloodProtectionParam",
      {
        type: "String",
      },
    );

    const activateScannersProbesProtection = new CfnParameter(
      this,
      "ActivateScannersProbesProtectionParam",
      {
        type: "String",
      },
    );

    const endpointType = new CfnParameter(this, "EndpointType", {
      type: "String",
    });

    const appAccessLogBucket = new CfnParameter(this, "AppAccessLogBucket", {
      type: "String",
    });

    const parentStackName = new CfnParameter(this, "ParentStackName", {
      type: "String",
    });

    const wafLogBucket = new CfnParameter(this, "WafLogBucket", {
      type: "String",
    });

    const wafLogBucketArn = new CfnParameter(this, "WafLogBucketArn", {
      type: "String",
    });

    // prettier-ignore
    new CfnParameter(this, "RequestThreshold", {//NOSONAR - skip sonar detection useless object instantiation
      type: "String",
    });

    // prettier-ignore
    new CfnParameter(this, "ErrorThreshold", {//NOSONAR - skip sonar detection useless object instantiation
      type: "String",
    });

    // prettier-ignore
    new CfnParameter(this, "WAFBlockPeriod", {//NOSONAR - skip sonar detection useless object instantiation
      type: "String",
    });

    const glueDatabaseName = new CfnParameter(this, "GlueDatabaseName", {
      type: "String",
    });

    const deliveryStreamName = new CfnParameter(this, "DeliveryStreamName", {
      type: "String",
    });

    const uuid = new CfnParameter(this, "UUID", {
      type: "String",
    });

    const activateBadBotProtection = new CfnParameter(
      this,
      "ActivateBadBotProtectionParam",
      {
        type: "String",
      },
    );

    //=============================================================================================
    // Conditions
    //=============================================================================================
    const albEndpoint = new CfnCondition(this, "AlbEndpoint", {
      expression: Fn.conditionEquals(endpointType, "ALB"),
    });

    const cloudFrontEndpoint = new CfnCondition(this, "CloudFrontEndpoint", {
      expression: Fn.conditionNot(albEndpoint),
    });

    const httpFloodLambdaLogParser = new CfnCondition(
      this,
      "HttpFloodLambdaLogParser",
      {
        expression: Fn.conditionEquals(
          activateHttpFloodProtectionParam,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const httpFloodAthenaLogParser = new CfnCondition(
      this,
      "HttpFloodAthenaLogParser",
      {
        expression: Fn.conditionEquals(
          activateHttpFloodProtectionParam,
          "yes - Amazon Athena log parser",
        ),
      },
    );

    const scannersProbesAthenaLogParser = new CfnCondition(
      this,
      "ScannersProbesAthenaLogParser",
      {
        expression: Fn.conditionEquals(
          activateScannersProbesProtection,
          "yes - Amazon Athena log parser",
        ),
      },
    );

    const albScannersProbesAthenaLogParser = new CfnCondition(
      this,
      "ALBScannersProbesAthenaLogParser",
      {
        expression: Fn.conditionAnd(scannersProbesAthenaLogParser, albEndpoint),
      },
    );

    const cloudFrontScannersProbesAthenaLogParser = new CfnCondition(
      this,
      "CloudFrontScannersProbesAthenaLogParser",
      {
        expression: Fn.conditionAnd(
          scannersProbesAthenaLogParser,
          cloudFrontEndpoint,
        ),
      },
    );

    const scannersProbesLambdaLogParser = new CfnCondition(
      this,
      "ScannersProbesLambdaLogParser",
      {
        expression: Fn.conditionEquals(
          activateScannersProbesProtection.valueAsString,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const athenaLogParser = new CfnCondition(this, "AthenaLogParser", {
      expression: Fn.conditionOr(
        httpFloodAthenaLogParser,
        scannersProbesAthenaLogParser,
      ),
    });

    const badBotProtectionActivated = new CfnCondition(
      this,
      "BadBotProtectionActivated",
      {
        expression: Fn.conditionEquals(activateBadBotProtection, "yes"),
      },
    );

    const badBotLambdaLogParserActivated = new CfnCondition(
      this,
      "BadBotLambdaLogParserActivated",
      {
        expression: Fn.conditionAnd(
          Fn.conditionNot(httpFloodLambdaLogParser),
          Fn.conditionNot(scannersProbesLambdaLogParser),
          Fn.conditionNot(httpFloodAthenaLogParser),
          Fn.conditionNot(scannersProbesAthenaLogParser),
          badBotProtectionActivated,
        ),
      },
    );

    const httpFloodProtectionActivated = new CfnCondition(
      this,
      "HttpFloodProtectionActivated",
      {
        expression: Fn.conditionOr(
          httpFloodLambdaLogParser,
          httpFloodAthenaLogParser,
        ),
      },
    );

    const httpFloodProtectionLogParserActivated = new CfnCondition(
      this,
      "HttpFloodProtectionLogParserActivated",
      {
        expression: Fn.conditionOr(
          httpFloodProtectionActivated,
          badBotLambdaLogParserActivated,
        ),
      },
    );

    //=============================================================================================
    // Mappings
    //=============================================================================================
    const rateLimitMap = new CfnMapping(this, "TimeWindowMap", {
      mapping: {
        "1": { seconds: 60 },
        "2": { seconds: 120 },
        "5": { seconds: 300 },
        "10": { seconds: 600 },
      },
    });

    //=============================================================================================
    // Resources
    //=============================================================================================
    // prettier-ignore
    new FirehoseWAFLogsDelivery(this, FirehoseWAFLogsDelivery.ID, { //NOSONAR - skip sonar detection useless object instantiation
      httpFloodProtectionLogParserActivated,
      wafLogBucket,
      wafLogBucketArn,
      deliveryStreamName,
      rateLimitMap,
      timeWindowThreshold,
      httpFloodLambdaLogParser,
    });

    const glueAccessLogsDatabase = new GlueAccessLogsDatabase(
      this,
      GlueAccessLogsDatabase.ID + "Resource",
      {
        athenaLogParser: athenaLogParser,
        deliveryStreamName: glueDatabaseName,
        parentStackName: parentStackName,
      },
    );

    const glueWafAccessLogsTable = new GlueWafAccessLogsTable(
      this,
      GlueWafAccessLogsTable.ID,
      {
        httpFloodAthenaLogParser,
        glueAccessLogsDatabase: glueAccessLogsDatabase,
        wafLogBucket: wafLogBucket,
      },
    );

    const appAccessLogsTable = new GlueAppAccessLogsTables(
      this,
      "GlueAppAccessLogsTables",
      {
        albScannersProbesAthenaLogParser,
        cloudFrontScannersProbesAthenaLogParser,
        scannersProbesAthenaLogParser,
        glueAccessLogsDatabase: glueAccessLogsDatabase,
        parentStackName: parentStackName,
        appAccessLogBucket: appAccessLogBucket,
      },
    );

    const wAFAddPartitionAthenaQueryWorkGroup =
      new WAFAddPartitionAthenaQueryWorkGroup(
        this,
        WAFAddPartitionAthenaQueryWorkGroup.ID,
        {
          athenaLogParser: athenaLogParser,
          uuid: uuid,
        },
      );

    // prettier-ignore
    new WAFLogAthenaQueryWorkGroup(this, WAFLogAthenaQueryWorkGroup.ID, {//NOSONAR - skip sonar detection useless object instantiation
      httpFloodAthenaLogParser: httpFloodAthenaLogParser,
      uuid: uuid,
    });

    // prettier-ignore
    new WAFAppAccessLogAthenaQueryWorkGroup(this, WAFAppAccessLogAthenaQueryWorkGroup.ID, {//NOSONAR - skip sonar detection useless object instantiation
        scannersProbesAthenaLogParser: scannersProbesAthenaLogParser,
        uuid: uuid,
      },
    );

    //=============================================================================================
    // Outputs
    //=============================================================================================

    this.outputs["Version"] = new CfnOutput(this, "Version", {
      value: distVersion,
    });

    const clueWafAccessLogsTableOutput = new CfnOutput(
      this,
      GlueWafAccessLogsTable.ID + "Output",
      {
        value: glueWafAccessLogsTable.getTable().ref,
      },
    );
    clueWafAccessLogsTableOutput.condition = httpFloodAthenaLogParser;
    clueWafAccessLogsTableOutput.overrideLogicalId(GlueWafAccessLogsTable.ID);
    this.outputs[GlueWafAccessLogsTable.ID] = clueWafAccessLogsTableOutput;

    const tableOutput = new CfnOutput(
      this,
      GlueAppAccessLogsTables.GLUE_APP_ACCESS_OUTPUT + "Output",
      {
        value: Fn.conditionIf(
          albEndpoint.logicalId,
          appAccessLogsTable.getAlbTable().ref,
          appAccessLogsTable.getCloudFrontTable().ref,
        ).toString(),
        condition: scannersProbesAthenaLogParser,
      },
    );
    tableOutput.overrideLogicalId(
      GlueAppAccessLogsTables.GLUE_APP_ACCESS_OUTPUT,
    );
    this.outputs[GlueAppAccessLogsTables.GLUE_APP_ACCESS_OUTPUT] = tableOutput;

    const glueAccessLogsDatabaseOutput = new CfnOutput(
      this,
      GlueAccessLogsDatabase.ID + "Output",
      {
        value: glueAccessLogsDatabase.getDatabase().ref,
        condition: athenaLogParser,
      },
    );
    glueAccessLogsDatabaseOutput.overrideLogicalId(GlueAccessLogsDatabase.ID);
    this.outputs[GlueAccessLogsDatabase.ID] = glueAccessLogsDatabaseOutput;

    const workGroupOutput = new CfnOutput(
      this,
      WAFAddPartitionAthenaQueryWorkGroup.ID + "Output",
      {
        description:
          "Athena WorkGroup for adding Athena partition queries used by Security Automations for AWS WAF Solution",
        value: wAFAddPartitionAthenaQueryWorkGroup.getWorkGroup().ref,
        condition: athenaLogParser,
      },
    );
    workGroupOutput.overrideLogicalId(WAFAddPartitionAthenaQueryWorkGroup.ID);
    this.outputs[WAFAddPartitionAthenaQueryWorkGroup.ID] = workGroupOutput;
  }
}
