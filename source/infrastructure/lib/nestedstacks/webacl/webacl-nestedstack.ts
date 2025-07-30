#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @description
 * Security Automations for AWS WAF - WebAcl Nested Stack
 * @author @aws-solutions
 */

import { Construct } from "constructs";
import {
  CfnStack,
  NestedStack,
  NestedStackProps,
  CfnMapping,
  CfnCondition,
  Fn,
} from "aws-cdk-lib";
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { webaclManifest } from "./constants/webacl-constants";
import {
  distOutputBucket,
  distVersion,
  manifest,
  solutionName,
  templateOutputBucket,
  WafRuleKeysType,
} from "../../constants/waf-constants";
import { CheckRequirements } from "../../components/customs/check-requirements";
import WebaclUtils from "./utils/webaclUtils";
import { Tracing } from "aws-cdk-lib/aws-lambda";

export interface WebAclNestedStackProps extends NestedStackProps {
  readonly athenaLogParser: cdk.CfnCondition;
  readonly badBotProtectionActivated: cdk.CfnCondition;
  readonly scannersProbesProtectionActivated: cdk.CfnCondition;
  readonly reputationListsProtectionActivated: cdk.CfnCondition;
  readonly httpFloodProtectionActivated: CfnCondition;
  readonly httpFloodAthenaLogParser: cdk.CfnCondition;
  readonly httpFloodProtectionRateBasedRule: cdk.CfnCondition;
  readonly sourceCodeMapping: SourceCodeMapping;
  readonly checkRequirements: CheckRequirements;
}

export class WebaclNestedstack extends NestedStack {
  public static readonly ID = "WebACLStack";
  public static readonly NAME = "WebACL";
  public static readonly TIMER_ROLE_ID = "LambdaRoleCustomTimer";

  public static readonly NameWAFWhitelistSetV4_OUTPUT = "NameWAFWhitelistSetV4";
  public static readonly NameWAFBlacklistSetV4_OUTPUT = "NameWAFBlacklistSetV4";
  public static readonly NameWAFWhitelistSetV6_OUTPUT = "NameWAFWhitelistSetV6";
  public static readonly NameWAFBlacklistSetV6_OUTPUT = "NameWAFBlacklistSetV6";
  public static readonly WAFWhitelistSetV4Arn_OUTPUT = "WAFWhitelistSetV4Arn";
  public static readonly WAFBlacklistSetV4Arn_OUTPUT = "WAFBlacklistSetV4Arn";
  public static readonly WAFWhitelistSetV6Arn_OUTPUT = "WAFWhitelistSetV6Arn";
  public static readonly WAFBlacklistSetV6Arn_OUTPUT = "WAFBlacklistSetV6Arn";
  public static readonly WAFWebACLArn_OUTPUT = "WAFWebACLArn";
  public static readonly WAFBadBotSetV4Arn_OUTPUT = "WAFBadBotSetV4Arn";
  public static readonly WAFBadBotSetV6Arn_OUTPUT = "WAFBadBotSetV6Arn";
  public static readonly NameBadBotSetV4_OUTPUT = "NameBadBotSetV4";
  public static readonly NameBadBotSetV6_OUTPUT = "NameBadBotSetV6";
  public static readonly WAFBadBotSetV4Id_OUTPUT = "WAFBadBotSetV4Id";
  public static readonly WAFBadBotSetV6Id_OUTPUT = "WAFBadBotSetV6Id";
  public static readonly WAFHttpFloodSetV4Id_OUTPUT = "WAFHttpFloodSetV4Id";
  public static readonly NameHttpFloodSetV4_OUTPUT = "NameHttpFloodSetV4";
  public static readonly NameHttpFloodSetV6_OUTPUT = "NameHttpFloodSetV6";
  public static readonly WAFReputationListsSetV4Id_OUTPUT =
    "WAFReputationListsSetV4Id";
  public static readonly NameReputationListsSetV4_OUTPUT =
    "NameReputationListsSetV4";
  public static readonly WAFReputationListsSetV6Id_OUTPUT =
    "WAFReputationListsSetV6Id";
  public static readonly WAFScannersProbesSetV4Id_OUTPUT =
    "WAFScannersProbesSetV4Id";
  public static readonly NameScannersProbesSetV4_OUTPUT =
    "NameScannersProbesSetV4";
  public static readonly WAFScannersProbesSetV6Id_OUTPUT =
    "WAFScannersProbesSetV6Id";
  public static readonly NameScannersProbesSetV6_OUTPUT =
    "NameScannersProbesSetV6";
  public static readonly WAFWebACL_OUTPUT = "WAFWebACL";
  public static readonly WAFWhitelistSetV4Id_OUTPUT = "WAFWhitelistSetV4Id";
  public static readonly WAFBlacklistSetV4Id_OUTPUT = "WAFBlacklistSetV4Id";
  public static readonly WAFWhitelistSetV6Id_OUTPUT = "WAFWhitelistSetV6Id";
  public static readonly WAFBlacklistSetV6Id_OUTPUT = "WAFBlacklistSetV6Id";
  public static readonly WAFHttpFloodSetV6Id_OUTPUT = "WAFHttpFloodSetV6Id";
  public static readonly NameReputationListsSetV6_OUTPUT =
    "NameReputationListsSetV6";
  public static readonly WAFScannersProbesSetV4Arn_OUTPUT =
    "WAFScannersProbesSetV4Arn";
  public static readonly WAFScannersProbesSetV6Arn_OUTPUT =
    "WAFScannersProbesSetV6Arn";
  public static readonly WAFHttpFloodSetV4Arn_OUTPUT = "WAFHttpFloodSetV4Arn";
  public static readonly WAFHttpFloodSetV6Arn_OUTPUT = "WAFHttpFloodSetV6Arn";
  public static readonly WAFReputationListsSetV4Arn_OUTPUT =
    "WAFReputationListsSetV4Arn";
  public static readonly WAFReputationListsSetV6Arn_OUTPUT =
    "WAFReputationListsSetV6Arn";
  public static readonly IPReputationListsMetricName_OUTPUT =
    "IPReputationListsMetricName";
  public static readonly CustomTimerFunctionName_OUTPUT =
    "CustomTimerFunctionName";

  private readonly customTimer: lambda.Function | undefined;
  public readonly outputs: { [key: string]: cdk.CfnOutput } = {};

  constructor(scope: Construct, id: string, props: WebAclNestedStackProps) {
    super(scope, id, props);

    const webAclNestedStackCfnResource = this.node.defaultChild as CfnStack;
    webAclNestedStackCfnResource.overrideLogicalId(WebaclNestedstack.ID);
    webAclNestedStackCfnResource.addOverride(
      "DependsOn",
      props.checkRequirements.node.id,
    );
    webAclNestedStackCfnResource.addOverride("UpdateReplacePolicy", undefined);
    webAclNestedStackCfnResource.addOverride("DeletionPolicy", undefined);
    const templateUrl = `https://\${S3Bucket}.s3.amazonaws.com/\${KeyPrefix}/${webaclManifest.wafSecurityAutomations.webaclTemplateId}.template`;
    webAclNestedStackCfnResource.templateUrl = cdk.Fn.sub(templateUrl, {
      S3Bucket: props.sourceCodeMapping.findInMap("General", "TemplateBucket"),
      KeyPrefix: props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
    });

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
    // Metadata
    //=============================================================================================
    this.templateOptions.templateFormatVersion =
      webaclManifest.awsTemplateFormatVersion;
    this.templateOptions.description = webaclManifest.webacl.description;

    //=============================================================================================
    // Parameters
    //=============================================================================================
    const activateAWSManagedRules = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedRulesParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedAP = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedAPParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedKBI = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedKBIParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedIPR = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedIPRParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedAIP = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedAIPParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedSQL = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedSQLParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedLinux = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedLinuxParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedPOSIX = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedPOSIXParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedWindows = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedWindowsParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedPHP = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedPHPParam",
      {
        type: "String",
      },
    );

    const activateAWSManagedWP = new cdk.CfnParameter(
      this,
      "ActivateAWSManagedWPParam",
      {
        type: "String",
      },
    );

    const activateSqlInjectionProtection = new cdk.CfnParameter(
      this,
      "ActivateSqlInjectionProtectionParam",
      {
        type: "String",
      },
    );

    const activateCrossSiteScriptingProtection = new cdk.CfnParameter(
      this,
      "ActivateCrossSiteScriptingProtectionParam",
      {
        type: "String",
      },
    );

    const activateHttpFloodProtection = new cdk.CfnParameter(
      this,
      "ActivateHttpFloodProtectionParam",
      {
        type: "String",
      },
    );

    const activateScannersProbesProtection = new cdk.CfnParameter(
      this,
      "ActivateScannersProbesProtectionParam",
      {
        type: "String",
      },
    );

    const activateReputationListsProtection = new cdk.CfnParameter(
      this,
      "ActivateReputationListsProtectionParam",
      {
        type: "String",
      },
    );

    const activateBadBotProtectionParam = new cdk.CfnParameter(
      this,
      "ActivateBadBotProtectionParam",
      {
        type: "String",
      },
    );

    const requestThreshold = new cdk.CfnParameter(this, "RequestThreshold", {
      type: "Number",
    });

    // prettier-ignore
    new cdk.CfnParameter(this, "RegionScope", {//NOSONAR - skip sonar detection useless object instantiation
      type: "String",
    });

    const parentStackName = new cdk.CfnParameter(this, "ParentStackName", {
      type: "String",
    });

    const glueAccessLogsDatabaseParam = new cdk.CfnParameter(
      this,
      "GlueAccessLogsDatabase",
      {
        type: "String",
      },
    );

    const glueAppAccessLogsTableParam = new cdk.CfnParameter(
      this,
      "GlueAppAccessLogsTable",
      {
        type: "String",
      },
    );

    const glueWafAccessLogsTableParam = new cdk.CfnParameter(
      this,
      "GlueWafAccessLogsTable",
      {
        type: "String",
      },
    );

    const logLevel = new cdk.CfnParameter(this, "LogLevel", {
      type: "String",
    });

    const sqlInjectionProtectionSensitivityLevel = new cdk.CfnParameter(
      this,
      "SqlInjectionProtectionSensitivityLevelParam",
      {
        type: "String",
      },
    );

    const wafRuleKeysType = new cdk.CfnParameter(this, "WAFRuleKeysTypeParam", {
      type: "String",
    });

    const customHeaderName = new cdk.CfnParameter(
      this,
      "CustomHeaderNameParam",
      {
        type: "String",
      },
    );

    const timeWindowThreshold = new cdk.CfnParameter(
      this,
      "TimeWindowThresholdParam",
      {
        type: "Number",
      },
    );

    //=============================================================================================
    // Condition
    //=============================================================================================

    const awsManagedCRSActivated = new cdk.CfnCondition(
      this,
      "AWSManagedCRSActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedRules, "yes"),
      },
    );

    const awsManagedAPActivated = new cdk.CfnCondition(
      this,
      "AWSManagedAPActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedAP, "yes"),
      },
    );

    const awsManagedKBIActivated = new cdk.CfnCondition(
      this,
      "AWSManagedKBIActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedKBI, "yes"),
      },
    );

    const awsManagedIPRActivated = new cdk.CfnCondition(
      this,
      "AWSManagedIPRActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedIPR, "yes"),
      },
    );

    const awsManagedAIPActivated = new cdk.CfnCondition(
      this,
      "AWSManagedAIPActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedAIP, "yes"),
      },
    );

    const awsManagedSQLActivated = new cdk.CfnCondition(
      this,
      "AWSManagedSQLActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedSQL, "yes"),
      },
    );

    const awsManagedLinuxActivated = new cdk.CfnCondition(
      this,
      "AWSManagedLinuxActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedLinux, "yes"),
      },
    );

    const awsManagedPOSIXActivated = new cdk.CfnCondition(
      this,
      "AWSManagedPOSIXActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedPOSIX, "yes"),
      },
    );

    const awsManagedWindowsActivated = new cdk.CfnCondition(
      this,
      "AWSManagedWindowsActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedWindows, "yes"),
      },
    );

    const awsManagedPHPActivated = new cdk.CfnCondition(
      this,
      "AWSManagedPHPActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedPHP, "yes"),
      },
    );

    const awsManagedWPActivated = new cdk.CfnCondition(
      this,
      "AWSManagedWPActivated",
      {
        expression: cdk.Fn.conditionEquals(activateAWSManagedWP, "yes"),
      },
    );

    const sqlInjectionProtectionActivated = new cdk.CfnCondition(
      this,
      "SqlInjectionProtectionActivated",
      {
        expression: cdk.Fn.conditionNot(
          cdk.Fn.conditionEquals(activateSqlInjectionProtection, "no"),
        ),
      },
    );

    const sqlInjectionProtectionContinueActivated = new cdk.CfnCondition(
      this,
      "SqlInjectionProtectionContinueActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateSqlInjectionProtection,
          "yes",
        ),
      },
    );

    const sqlInjectionProtectionMatchActivated = new cdk.CfnCondition(
      this,
      "SqlInjectionProtectionMatchActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateSqlInjectionProtection,
          "yes - MATCH",
        ),
      },
    );

    const sqlInjectionProtectionNoMatchActivated = new cdk.CfnCondition(
      this,
      "SqlInjectionProtectionNoMatchActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateSqlInjectionProtection,
          "yes - NO_MATCH",
        ),
      },
    );

    const crossSiteScriptingProtectionActivated = new cdk.CfnCondition(
      this,
      "CrossSiteScriptingProtectionActivated",
      {
        expression: cdk.Fn.conditionNot(
          cdk.Fn.conditionEquals(activateCrossSiteScriptingProtection, "no"),
        ),
      },
    );

    const crossSiteScriptingProtectionContinueActivated = new cdk.CfnCondition(
      this,
      "CrossSiteScriptingProtectionContinueActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateCrossSiteScriptingProtection,
          "yes",
        ),
      },
    );

    const crossSiteScriptingProtectionMatchActivated = new cdk.CfnCondition(
      this,
      "CrossSiteScriptingProtectionMatchActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateCrossSiteScriptingProtection,
          "yes - MATCH",
        ),
      },
    );

    const crossSiteScriptingProtectionNoMatchActivated = new cdk.CfnCondition(
      this,
      "CrossSiteScriptingProtectionNoMatchActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateCrossSiteScriptingProtection,
          "yes - NO_MATCH",
        ),
      },
    );

    const httpFloodLambdaLogParser = new cdk.CfnCondition(
      this,
      "HttpFloodLambdaLogParser",
      {
        expression: cdk.Fn.conditionEquals(
          activateHttpFloodProtection,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const httpFloodAthenaLogParser = new cdk.CfnCondition(
      this,
      "HttpFloodAthenaLogParser",
      {
        expression: cdk.Fn.conditionEquals(
          activateHttpFloodProtection,
          "yes - Amazon Athena log parser",
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

    const httpFloodProtectionRateBasedRuleActivated = new cdk.CfnCondition(
      this,
      "HttpFloodProtectionRateBasedRuleActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateHttpFloodProtection,
          "yes - AWS WAF rate based rule",
        ),
      },
    );

    const scannersProbesAthenaLogParser = new cdk.CfnCondition(
      this,
      "ScannersProbesAthenaLogParser",
      {
        expression: cdk.Fn.conditionEquals(
          activateScannersProbesProtection,
          "yes - Amazon Athena log parser",
        ),
      },
    );

    const scannersProbesLambdaLogParser = new cdk.CfnCondition(
      this,
      "ScannersProbesLambdaLogParser",
      {
        expression: cdk.Fn.conditionEquals(
          activateScannersProbesProtection,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const scannersProbesProtectionActivated = new cdk.CfnCondition(
      this,
      "ScannersProbesProtectionActivated",
      {
        expression: cdk.Fn.conditionOr(
          scannersProbesLambdaLogParser,
          scannersProbesAthenaLogParser,
        ),
      },
    );

    const reputationListsProtectionActivated = new cdk.CfnCondition(
      this,
      "ReputationListsProtectionActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateReputationListsProtection,
          "yes",
        ),
      },
    );

    const badBotProtectionActivated = new cdk.CfnCondition(
      this,
      "BadBotProtectionActivated",
      {
        expression: cdk.Fn.conditionEquals(
          activateBadBotProtectionParam,
          "yes",
        ),
      },
    );

    const isDefaultIP = new cdk.CfnCondition(this, "IsDefaultIP", {
      expression: cdk.Fn.conditionEquals(
        wafRuleKeysType.valueAsString,
        WafRuleKeysType.IP,
      ),
    });

    const isCustomHeaderSelected = new cdk.CfnCondition(
      this,
      "IsCustomHeaderSelected",
      {
        expression: cdk.Fn.conditionEquals(
          wafRuleKeysType.valueAsString,
          WafRuleKeysType.IP_CUSTOM_HEADER,
        ),
      },
    );

    const isUriPathSelected = new cdk.CfnCondition(this, "IsUriPathSelected", {
      expression: cdk.Fn.conditionEquals(
        wafRuleKeysType.valueAsString,
        WafRuleKeysType.IP_URI,
      ),
    });

    const isHttpMethodSelected = new cdk.CfnCondition(
      this,
      "IsHttpMethodSelected",
      {
        expression: cdk.Fn.conditionEquals(
          wafRuleKeysType.valueAsString,
          WafRuleKeysType.IP_HTTP_METHOD,
        ),
      },
    );

    //=============================================================================================
    // Mapping
    //=============================================================================================
    const sourceCodeMapping = new SourceCodeMapping(this, "SourceCode", {
      templateBucket: templateOutputBucket,
      sourceBucket: distOutputBucket,
      keyPrefix: `${solutionName}/${distVersion}`,
    });

    //=============================================================================================
    // Resources
    //=============================================================================================
    const lambdaRoleCustomTimer = new iam.Role(
      this,
      WebaclNestedstack.TIMER_ROLE_ID,
      {
        assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
        inlinePolicies: {
          CloudWatchLogs: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents",
                ],
                resources: [
                  cdk.Fn.sub(
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*CustomTimer*",
                  ),
                ],
              }),
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources: ["*"],
              }),
            ],
          }),
        },
      },
    );

    const cfnLambdaRoleCustomTimer = lambdaRoleCustomTimer.node
      .defaultChild as cdk.CfnResource;
    cfnLambdaRoleCustomTimer.overrideLogicalId(WebaclNestedstack.TIMER_ROLE_ID);
    cfnLambdaRoleCustomTimer.addMetadata("guard", {
      SuppressedRules: [
        "IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE",
        "IAM_NO_INLINE_POLICY_CHECK",
      ],
    });

    const s3Bucket = cdk.Fn.join("-", [
      sourceCodeMapping.findInMap("General", "SourceBucket"),
      cdk.Aws.REGION,
    ]);

    const s3Key = cdk.Fn.join("/", [
      sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "timer.zip",
    ]);
    this.customTimer = new lambda.Function(this, "CustomTimer", {
      description:
        "This lambda function counts X seconds and can be used to slow down component creation in CloudFormation",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "timer.lambda_handler",
      role: lambdaRoleCustomTimer.withoutPolicyUpdates(),
      code: lambda.Code.fromBucket(
        cdk.aws_s3.Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      memorySize: 128,
      timeout: cdk.Duration.seconds(300),
      environment: {
        SECONDS: "2",
        LOG_LEVEL: cdk.Fn.ref(logLevel.logicalId),
        POWERTOOLS_SERVICE_NAME: "CustomTimer",
      },
      tracing: Tracing.ACTIVE,
    });
    const cfnFunction = this.customTimer.node
      .defaultChild as lambda.CfnFunction;
    cfnFunction.addDependency(cfnLambdaRoleCustomTimer);
    (this.customTimer.node.defaultChild as cdk.CfnResource).overrideLogicalId(
      "CustomTimer",
    );

    const timerWhiteV4 = new cdk.CustomResource(this, "TimerWhiteV4", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerWhitev4 = timerWhiteV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerWhitev4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerWhitev4.addOverride("UpdateReplacePolicy", undefined);

    const timerBlackV4 = new cdk.CustomResource(this, "TimerBlackV4", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerBlackV4 = timerBlackV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerBlackV4.addOverride("DependsOn", timerWhiteV4.node.id);
    cfnResourceTimerBlackV4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerBlackV4.addOverride("UpdateReplacePolicy", undefined);

    const timerHttpFloodV4 = new cdk.CustomResource(this, "TimerHttpFloodV4", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerHttpFloodV4 = timerHttpFloodV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerHttpFloodV4.addOverride("DependsOn", timerBlackV4.node.id);
    cfnResourceTimerHttpFloodV4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerHttpFloodV4.addOverride("UpdateReplacePolicy", undefined);

    const timerScannersV4 = new cdk.CustomResource(this, "TimerScannersV4", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerScannersV4 = timerScannersV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerScannersV4.addOverride(
      "DependsOn",
      timerHttpFloodV4.node.id,
    );
    cfnResourceTimerScannersV4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerScannersV4.addOverride("UpdateReplacePolicy", undefined);

    const timerReputationV4 = new cdk.CustomResource(
      this,
      "TimerReputationV4",
      {
        serviceToken: this.customTimer.functionArn,
        resourceType: "Custom::Timer",
      },
    );
    const cfnResourceTimerReputationV4 = timerReputationV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerReputationV4.addOverride(
      "DependsOn",
      timerScannersV4.node.id,
    );
    cfnResourceTimerReputationV4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerReputationV4.addOverride("UpdateReplacePolicy", undefined);

    const timerBadBotV4 = new cdk.CustomResource(this, "TimerBadBotV4", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerBadBotV4 = timerBadBotV4.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerBadBotV4.addOverride(
      "DependsOn",
      timerReputationV4.node.id,
    );
    cfnResourceTimerBadBotV4.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerBadBotV4.addOverride("UpdateReplacePolicy", undefined);

    const timerWhiteV6 = new cdk.CustomResource(this, "TimerWhiteV6", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerWhiteV6 = timerWhiteV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerWhiteV6.addOverride("DependsOn", timerBadBotV4.node.id);
    cfnResourceTimerWhiteV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerWhiteV6.addOverride("UpdateReplacePolicy", undefined);

    const timerBlackV6 = new cdk.CustomResource(this, "TimerBlackV6", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerBlackV6 = timerBlackV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerBlackV6.addOverride("DependsOn", timerWhiteV6.node.id);
    cfnResourceTimerBlackV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerBlackV6.addOverride("UpdateReplacePolicy", undefined);

    const timerHttpFloodV6 = new cdk.CustomResource(this, "TimerHttpFloodV6", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerHttpFloodV6 = timerHttpFloodV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerHttpFloodV6.addOverride("DependsOn", timerBlackV6.node.id);
    cfnResourceTimerHttpFloodV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerHttpFloodV6.addOverride("UpdateReplacePolicy", undefined);

    const timerScannersV6 = new cdk.CustomResource(this, "TimerScannersV6", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerScannersV6 = timerScannersV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerScannersV6.addOverride(
      "DependsOn",
      timerHttpFloodV6.node.id,
    );
    cfnResourceTimerScannersV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerScannersV6.addOverride("UpdateReplacePolicy", undefined);

    const timerReputationV6 = new cdk.CustomResource(
      this,
      "TimerReputationV6",
      {
        serviceToken: this.customTimer.functionArn,
        resourceType: "Custom::Timer",
      },
    );
    const cfnResourceTimerReputationV6 = timerReputationV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerReputationV6.addOverride(
      "DependsOn",
      timerScannersV6.node.id,
    );
    cfnResourceTimerReputationV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerReputationV6.addOverride("UpdateReplacePolicy", undefined);

    const timerBadBotV6 = new cdk.CustomResource(this, "TimerBadBotV6", {
      serviceToken: this.customTimer.functionArn,
      resourceType: "Custom::Timer",
    });
    const cfnResourceTimerBadBotV6 = timerBadBotV6.node
      .defaultChild as cdk.CfnResource;
    cfnResourceTimerBadBotV6.addOverride(
      "DependsOn",
      timerReputationV6.node.id,
    );
    cfnResourceTimerBadBotV6.addOverride("DeletionPolicy", undefined);
    cfnResourceTimerBadBotV6.addOverride("UpdateReplacePolicy", undefined);

    const wafWhitelistSetV4 = new wafv2.CfnIPSet(this, "WAFWhitelistSetV4", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV4",
      name: cdk.Fn.sub("${ParentStackName}WhitelistSetIPV4"),
      description: "Allow List for IPV4 addresses",
      addresses: [],
    });
    wafWhitelistSetV4.addOverride("DependsOn", timerWhiteV4.node.id);

    const wafBlacklistSetV4 = new wafv2.CfnIPSet(this, "WAFBlacklistSetV4", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV4",
      name: cdk.Fn.sub("${ParentStackName}BlacklistSetIPV4"),
      description: "Block Denied List for IPV4 addresses",
      addresses: [],
    });
    wafBlacklistSetV4.addOverride("DependsOn", timerBlackV4.node.id);

    const wafHttpFloodSetV4 = new wafv2.CfnIPSet(this, "WAFHttpFloodSetV4", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV4",
      name: cdk.Fn.sub("${ParentStackName}HTTPFloodSetIPV4"),
      description: "Block HTTP Flood IPV4 addresses",
      addresses: [],
    });
    wafHttpFloodSetV4.cfnOptions.condition = httpFloodProtectionActivated;
    wafHttpFloodSetV4.addOverride("DependsOn", timerHttpFloodV4.node.id);

    const wafScannersProbesSetV4 = new wafv2.CfnIPSet(
      this,
      "WAFScannersProbesSetV4",
      {
        scope: cdk.Fn.sub("${RegionScope}"),
        ipAddressVersion: "IPV4",
        name: cdk.Fn.sub("${ParentStackName}ScannersProbesSetIPV4"),
        description: "Block Scanners/Probes IPV4 addresses",
        addresses: [],
      },
    );
    wafScannersProbesSetV4.cfnOptions.condition =
      scannersProbesProtectionActivated;
    wafScannersProbesSetV4.addOverride("DependsOn", timerScannersV4.node.id);

    const wafReputationListsSetV4 = new wafv2.CfnIPSet(
      this,
      "WAFReputationListsSetV4",
      {
        scope: cdk.Fn.sub("${RegionScope}"),
        ipAddressVersion: "IPV4",
        name: cdk.Fn.sub("${ParentStackName}IPReputationListsSetIPV4"),
        description: "Block Reputation List IPV4 addresses",
        addresses: [],
      },
    );
    wafReputationListsSetV4.cfnOptions.condition =
      reputationListsProtectionActivated;
    wafReputationListsSetV4.addOverride("DependsOn", timerReputationV4.node.id);

    const wafBadBotSetV4 = new wafv2.CfnIPSet(this, "WAFBadBotSetV4", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV4",
      name: cdk.Fn.sub("${ParentStackName}IPBadBotSetIPV4"),
      description: "Block Bad Bot IPV4 addresses",
      addresses: [],
    });
    wafBadBotSetV4.cfnOptions.condition = badBotProtectionActivated;
    wafBadBotSetV4.addOverride("DependsOn", timerBadBotV4.node.id);

    // IPV6 IPSets
    // Introduced an artificial DependsOn property here on each of the previous IPSets to address
    // a rate throttling issue when creating so many calls to create IPSet
    // The rate limit is 1 call per second to the IPSet API
    const wafWhitelistSetV6 = new wafv2.CfnIPSet(this, "WAFWhitelistSetV6", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV6",
      name: cdk.Fn.sub("${ParentStackName}WhitelistSetIPV6"),
      description: "Allow list for IPV6 addresses",
      addresses: [],
    });
    wafWhitelistSetV6.addOverride("DependsOn", timerWhiteV6.node.id);

    const wafBlacklistSetV6 = new wafv2.CfnIPSet(this, "WAFBlacklistSetV6", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV6",
      name: cdk.Fn.sub("${ParentStackName}BlacklistSetIPV6"),
      description: "Block Denied List for IPV6 addresses",
      addresses: [],
    });
    wafBlacklistSetV6.addOverride("DependsOn", timerBlackV6.node.id);

    const wafHttpFloodSetV6 = new wafv2.CfnIPSet(this, "WAFHttpFloodSetV6", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV6",
      name: cdk.Fn.sub("${ParentStackName}HTTPFloodSetIPV6"),
      description: "Block HTTP Flood IPV6 addresses",
      addresses: [],
    });
    wafHttpFloodSetV6.cfnOptions.condition = httpFloodProtectionActivated;
    wafHttpFloodSetV6.addOverride("DependsOn", timerHttpFloodV6.node.id);

    const wafScannersProbesSetV6 = new wafv2.CfnIPSet(
      this,
      "WAFScannersProbesSetV6",
      {
        scope: cdk.Fn.sub("${RegionScope}"),
        ipAddressVersion: "IPV6",
        name: cdk.Fn.sub("${ParentStackName}ScannersProbesSetIPV6"),
        description: "Block Scanners/Probes IPV6 addresses",
        addresses: [],
      },
    );
    wafScannersProbesSetV6.cfnOptions.condition =
      scannersProbesProtectionActivated;
    wafScannersProbesSetV6.addOverride("DependsOn", timerScannersV6.node.id);

    const wafReputationListsSetV6 = new wafv2.CfnIPSet(
      this,
      "WAFReputationListsSetV6",
      {
        scope: cdk.Fn.sub("${RegionScope}"),
        ipAddressVersion: "IPV6",
        name: cdk.Fn.sub("${ParentStackName}IPReputationListsSetIPV6"),
        description: "Block Reputation List IPV6 addresses",
        addresses: [],
      },
    );
    wafReputationListsSetV6.cfnOptions.condition =
      reputationListsProtectionActivated;
    wafReputationListsSetV6.addOverride("DependsOn", timerReputationV6.node.id);

    const wafBadBotSetV6 = new wafv2.CfnIPSet(this, "WAFBadBotSetV6", {
      scope: cdk.Fn.sub("${RegionScope}"),
      ipAddressVersion: "IPV6",
      name: cdk.Fn.sub("${ParentStackName}IPBadBotSetIPV6"),
      description: "Block Bad Bot IPV6 addresses",
      addresses: [],
    });
    wafBadBotSetV6.cfnOptions.condition = badBotProtectionActivated;
    wafBadBotSetV6.addOverride("DependsOn", timerBadBotV6.node.id);

    const whiteRule: wafv2.CfnWebACL.RuleProperty = {
      name: cdk.Fn.sub("${ParentStackName}WhitelistRule"),
      priority: 0,
      action: {
        allow: {},
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: cdk.Fn.join("", [
          cdk.Fn.join("", cdk.Fn.split("-", cdk.Fn.ref("ParentStackName"))),
          "WhitelistRule",
        ]),
      },
      statement: {
        orStatement: {
          statements: [
            {
              ipSetReferenceStatement: {
                arn: cdk.Fn.getAtt("WAFWhitelistSetV4", "Arn").toString(),
              },
            },
            {
              ipSetReferenceStatement: {
                arn: cdk.Fn.getAtt("WAFWhitelistSetV6", "Arn").toString(),
              },
            },
          ],
        },
      },
    };

    const blackRule: wafv2.CfnWebACL.RuleProperty = {
      name: cdk.Fn.sub("${ParentStackName}BlacklistRule"),
      priority: 1,
      action: {
        block: {},
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: cdk.Fn.join("", [
          cdk.Fn.join("", cdk.Fn.split("-", cdk.Fn.ref("ParentStackName"))),
          "BlacklistRule",
        ]),
      },
      statement: {
        orStatement: {
          statements: [
            {
              ipSetReferenceStatement: {
                arn: cdk.Fn.getAtt("WAFBlacklistSetV4", "Arn").toString(),
              },
            },
            {
              ipSetReferenceStatement: {
                arn: cdk.Fn.getAtt("WAFBlacklistSetV6", "Arn").toString(),
              },
            },
          ],
        },
      },
    };

    const wafWebAcl = new wafv2.CfnWebACL(this, "WAFWebACL", {
      name: cdk.Fn.ref(parentStackName.logicalId),
      description: "Custom WAFWebACL",
      scope: cdk.Fn.sub("${RegionScope}"),
      defaultAction: {
        allow: {},
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: cdk.Fn.join("", [
          cdk.Fn.join("", cdk.Fn.split("-", parentStackName.valueAsString)),
          "WAFWebACL",
        ]),
      },
      rules: [
        cdk.Fn.conditionIf(
          awsManagedCRSActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesCommonRuleSet",
            Priority: 6,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: "MetricForAMRCRS",
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesCommonRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedAPActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesAdminProtectionRuleSet",
            Priority: 7,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRAP",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesAdminProtectionRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedKBIActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesKnownBadInputsRuleSet",
            Priority: 8,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRKBI",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesKnownBadInputsRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedIPRActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesAmazonIpReputationList",
            Priority: 2,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRIPR",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesAmazonIpReputationList",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedAIPActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesAnonymousIpList",
            Priority: 4,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRAIP",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesAnonymousIpList",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedSQLActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesSQLiRuleSet",
            Priority: 14,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRSQL",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesSQLiRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedLinuxActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesLinuxRuleSet",
            Priority: 11,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRLinux",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesLinuxRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedPOSIXActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesUnixRuleSet",
            Priority: 10,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRPOSIX",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesUnixRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedWindowsActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesWindowsRuleSet",
            Priority: 9,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRWindows",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesWindowsRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedPHPActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesPHPRuleSet",
            Priority: 12,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRPHP",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesPHPRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          awsManagedWPActivated.logicalId,
          {
            Name: "AWS-AWSManagedRulesWordPressRuleSet",
            Priority: 13,
            OverrideAction: {
              None: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "AMRWP",
              ]),
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: "AWSManagedRulesWordPressRuleSet",
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),
        whiteRule,
        blackRule,
        cdk.Fn.conditionIf(
          httpFloodProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}HttpFloodRegularRule"),
            Priority: 18,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "HttpFloodRegularRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFHttpFloodSetV4", "Arn"),
                    },
                  },
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFHttpFloodSetV6", "Arn"),
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          httpFloodProtectionRateBasedRuleActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}HttpFloodRateBasedRule"),
            Priority: 19,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "HttpFloodRateBasedRule",
              ]),
            },
            Statement: {
              RateBasedStatement: {
                AggregateKeyType: WebaclUtils.getAggregateKeyType(
                  isDefaultIP.logicalId,
                ),
                CustomKeys: cdk.Fn.conditionIf(
                  isDefaultIP.logicalId,
                  cdk.Aws.NO_VALUE,
                  cdk.Fn.conditionIf(
                    isCustomHeaderSelected.logicalId,
                    [
                      {
                        Header: {
                          Name: customHeaderName.valueAsString,
                          TextTransformations: [
                            { Priority: 1, Type: "URL_DECODE" },
                            { Priority: 2, Type: "HTML_ENTITY_DECODE" },
                          ],
                        },
                      },
                      {
                        IP: {},
                      },
                    ],
                    cdk.Fn.conditionIf(
                      isUriPathSelected.logicalId,
                      [
                        {
                          UriPath: {
                            TextTransformations: [
                              { Priority: 1, Type: "URL_DECODE" },
                              { Priority: 2, Type: "HTML_ENTITY_DECODE" },
                            ],
                          },
                        },
                        {
                          IP: {},
                        },
                      ],
                      cdk.Fn.conditionIf(
                        isHttpMethodSelected.logicalId,
                        [{ HTTPMethod: {} }, { IP: {} }],
                        cdk.Aws.NO_VALUE,
                      ),
                    ),
                  ),
                ),
                EvaluationWindowSec: rateLimitMap.findInMap(
                  cdk.Fn.ref(timeWindowThreshold.logicalId),
                  "seconds",
                ),
                Limit: cdk.Fn.ref(requestThreshold.logicalId),
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          scannersProbesProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}ScannersAndProbesRule"),
            Priority: 17,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "ScannersProbesRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFScannersProbesSetV4", "Arn"),
                    },
                  },
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFScannersProbesSetV6", "Arn"),
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          reputationListsProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}IPReputationListsRule"),
            Priority: 3,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "IPReputationListsRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFReputationListsSetV4", "Arn"),
                    },
                  },
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFReputationListsSetV6", "Arn"),
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          badBotProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}BadBotRule"),
            Priority: 5,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "BadBotRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFBadBotSetV4", "Arn"),
                    },
                  },
                  {
                    IPSetReferenceStatement: {
                      Arn: cdk.Fn.getAtt("WAFBadBotSetV6", "Arn"),
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          sqlInjectionProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}SqlInjectionRule"),
            Priority: 15,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "SqlInjectionRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    SqliMatchStatement: {
                      FieldToMatch: {
                        QueryString: {},
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                      SensitivityLevel: cdk.Fn.ref(
                        sqlInjectionProtectionSensitivityLevel.logicalId,
                      ),
                    },
                  },
                  {
                    SqliMatchStatement: {
                      FieldToMatch: {
                        Body: {
                          OversizeHandling: cdk.Fn.conditionIf(
                            sqlInjectionProtectionContinueActivated.logicalId,
                            "CONTINUE",
                            cdk.Fn.conditionIf(
                              sqlInjectionProtectionMatchActivated.logicalId,
                              "MATCH",
                              cdk.Fn.conditionIf(
                                sqlInjectionProtectionNoMatchActivated.logicalId,
                                "NO_MATCH",
                                "CONTINUE",
                              ),
                            ),
                          ),
                        },
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                      SensitivityLevel: cdk.Fn.ref(
                        sqlInjectionProtectionSensitivityLevel.logicalId,
                      ),
                    },
                  },
                  {
                    SqliMatchStatement: {
                      FieldToMatch: {
                        UriPath: {},
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                      SensitivityLevel: cdk.Fn.ref(
                        sqlInjectionProtectionSensitivityLevel.logicalId,
                      ),
                    },
                  },
                  {
                    SqliMatchStatement: {
                      FieldToMatch: {
                        SingleHeader: {
                          Name: "authorization",
                        },
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                      SensitivityLevel: cdk.Fn.ref(
                        sqlInjectionProtectionSensitivityLevel.logicalId,
                      ),
                    },
                  },
                  {
                    SqliMatchStatement: {
                      FieldToMatch: {
                        SingleHeader: {
                          Name: "cookie",
                        },
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                      SensitivityLevel: cdk.Fn.ref(
                        sqlInjectionProtectionSensitivityLevel.logicalId,
                      ),
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),

        cdk.Fn.conditionIf(
          crossSiteScriptingProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}XssRule"),
            Priority: 16,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "XssRule",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    XssMatchStatement: {
                      FieldToMatch: {
                        QueryString: {},
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                    },
                  },
                  {
                    XssMatchStatement: {
                      FieldToMatch: {
                        Body: {
                          OversizeHandling: cdk.Fn.conditionIf(
                            crossSiteScriptingProtectionContinueActivated.logicalId,
                            "CONTINUE",
                            cdk.Fn.conditionIf(
                              crossSiteScriptingProtectionMatchActivated.logicalId,
                              "MATCH",
                              cdk.Fn.conditionIf(
                                crossSiteScriptingProtectionNoMatchActivated.logicalId,
                                "NO_MATCH",
                                "CONTINUE",
                              ),
                            ),
                          ),
                        },
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                    },
                  },
                  {
                    XssMatchStatement: {
                      FieldToMatch: {
                        UriPath: {},
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                    },
                  },
                  {
                    XssMatchStatement: {
                      FieldToMatch: {
                        SingleHeader: {
                          Name: "cookie",
                        },
                      },
                      TextTransformations: [
                        {
                          Priority: 1,
                          Type: "URL_DECODE",
                        },
                        {
                          Priority: 2,
                          Type: "HTML_ENTITY_DECODE",
                        },
                      ],
                    },
                  },
                ],
              },
            },
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),
        cdk.Fn.conditionIf(
          badBotProtectionActivated.logicalId,
          {
            Name: cdk.Fn.sub("${ParentStackName}BadBotRuleFilter"),
            Priority: 20,
            Action: {
              Block: {},
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: cdk.Fn.join("", [
                cdk.Fn.join(
                  "",
                  cdk.Fn.split("-", cdk.Fn.ref("ParentStackName")),
                ),
                "BadBotRuleFilter",
              ]),
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    ByteMatchStatement: {
                      FieldToMatch: {
                        UriPath: {},
                      },
                      PositionalConstraint: "STARTS_WITH",
                      SearchString:
                        "/" +
                        manifest.wafSecurityAutomations.batBot.prodStageName,
                      TextTransformations: [
                        {
                          Type: "URL_DECODE",
                          Priority: 0,
                        },
                      ],
                    },
                  },
                  {
                    ByteMatchStatement: {
                      FieldToMatch: {
                        UriPath: {},
                      },
                      PositionalConstraint: "STARTS_WITH",
                      SearchString:
                        "/" + manifest.wafSecurityAutomations.batBot.stageName,
                      TextTransformations: [
                        {
                          Type: "URL_DECODE",
                          Priority: 0,
                        },
                      ],
                    },
                  },
                ],
              },
            },
            RuleLabels: [
              {
                Name: manifest.wafSecurityAutomations.batBot.ruleLabel,
              },
            ],
          },
          cdk.Fn.ref("AWS::NoValue"),
        ),
      ],
    });

    // ARN Outputs
    this.outputs[WebaclNestedstack.WAFWhitelistSetV4Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFWhitelistSetV4Arn_OUTPUT, {
        value: wafWhitelistSetV4.attrArn,
      });

    const test = new cdk.CfnOutput(
      this,
      WebaclNestedstack.WAFBlacklistSetV4Arn_OUTPUT + "ID",
      {
        value: wafBlacklistSetV4.attrArn,
      },
    );

    test.overrideLogicalId(WebaclNestedstack.WAFBlacklistSetV4Arn_OUTPUT);
    this.outputs[WebaclNestedstack.WAFBlacklistSetV4Arn_OUTPUT] = test;

    this.outputs[WebaclNestedstack.WAFHttpFloodSetV4Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFHttpFloodSetV4Arn_OUTPUT, {
        value: wafHttpFloodSetV4.attrArn,
        condition: props.httpFloodProtectionActivated,
      });

    this.outputs[WebaclNestedstack.WAFScannersProbesSetV4Arn_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFScannersProbesSetV4Arn_OUTPUT,
        {
          value: wafScannersProbesSetV4.attrArn,
          condition: props.scannersProbesProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFReputationListsSetV4Arn_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFReputationListsSetV4Arn_OUTPUT,
        {
          value: wafReputationListsSetV4.attrArn,
          condition: props.reputationListsProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFBadBotSetV4Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFBadBotSetV4Arn_OUTPUT, {
        value: wafBadBotSetV4.attrArn,
        condition: props.badBotProtectionActivated,
      });

    this.outputs[WebaclNestedstack.WAFWhitelistSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFWhitelistSetV6Arn_OUTPUT, {
        value: wafWhitelistSetV6.attrArn,
      });

    this.outputs[WebaclNestedstack.WAFBlacklistSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFBlacklistSetV6Arn_OUTPUT, {
        value: wafBlacklistSetV6.attrArn,
      });

    this.outputs[WebaclNestedstack.WAFHttpFloodSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFHttpFloodSetV6Arn_OUTPUT, {
        value: wafHttpFloodSetV6.attrArn,
        condition: props.httpFloodProtectionActivated,
      });

    this.outputs[WebaclNestedstack.WAFScannersProbesSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFScannersProbesSetV6Arn_OUTPUT,
        {
          value: wafScannersProbesSetV6.attrArn,
          condition: props.scannersProbesProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFReputationListsSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFReputationListsSetV6Arn_OUTPUT,
        {
          value: wafReputationListsSetV6.attrArn,
          condition: props.reputationListsProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFBadBotSetV6Arn_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFBadBotSetV6Arn_OUTPUT, {
        value: wafBadBotSetV6.attrArn,
        condition: props.badBotProtectionActivated,
      });

    // Name Outputs
    this.outputs[WebaclNestedstack.NameWAFWhitelistSetV4_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameWAFWhitelistSetV4_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}WhitelistSetIPV4"),
      });

    this.outputs[WebaclNestedstack.NameWAFBlacklistSetV4_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameWAFBlacklistSetV4_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}BlacklistSetIPV4"),
      });

    this.outputs[WebaclNestedstack.NameHttpFloodSetV4_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameHttpFloodSetV4_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}HTTPFloodSetIPV4"),
        condition: props.httpFloodProtectionActivated,
      });

    this.outputs["NameScannersProbesSetV4"] = new cdk.CfnOutput(
      this,
      "NameScannersProbesSetV4",
      {
        value: cdk.Fn.sub("${ParentStackName}ScannersProbesSetIPV4"),
        condition: props.scannersProbesProtectionActivated,
      },
    );

    this.outputs["NameReputationListsSetV4"] = new cdk.CfnOutput(
      this,
      "NameReputationListsSetV4",
      {
        value: cdk.Fn.sub("${ParentStackName}IPReputationListsSetIPV4"),
        condition: props.reputationListsProtectionActivated,
      },
    );

    this.outputs[WebaclNestedstack.NameBadBotSetV4_OUTPUT] = new cdk.CfnOutput(
      this,
      WebaclNestedstack.NameBadBotSetV4_OUTPUT,
      {
        value: cdk.Fn.sub("${ParentStackName}IPBadBotSetIPV4"),
        condition: props.badBotProtectionActivated,
      },
    );

    this.outputs[WebaclNestedstack.NameWAFWhitelistSetV6_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameWAFWhitelistSetV6_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}WhitelistSetIPV6"),
      });

    this.outputs[WebaclNestedstack.NameWAFBlacklistSetV6_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameWAFBlacklistSetV6_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}BlacklistSetIPV6"),
      });

    this.outputs[WebaclNestedstack.NameHttpFloodSetV6_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.NameHttpFloodSetV6_OUTPUT, {
        value: cdk.Fn.sub("${ParentStackName}HTTPFloodSetIPV6"),
        condition: props.httpFloodProtectionActivated,
      });

    this.outputs[WebaclNestedstack.NameScannersProbesSetV6_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.NameScannersProbesSetV6_OUTPUT,
        {
          value: cdk.Fn.sub("${ParentStackName}ScannersProbesSetIPV6"),
          condition: props.scannersProbesProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.NameReputationListsSetV6_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.NameReputationListsSetV6_OUTPUT,
        {
          value: cdk.Fn.sub("${ParentStackName}IPReputationListsSetIPV6"),
          condition: props.reputationListsProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.NameBadBotSetV6_OUTPUT] = new cdk.CfnOutput(
      this,
      WebaclNestedstack.NameBadBotSetV6_OUTPUT,
      {
        value: cdk.Fn.sub("${ParentStackName}IPBadBotSetIPV6"),
        condition: props.badBotProtectionActivated,
      },
    );

    const glueAccessLogsDatabaseOutput = (this.outputs[
      "GlueAccessLogsDatabaseOutput"
    ] = new cdk.CfnOutput(this, "GlueAccessLogsDatabaseOutput", {
      value: cdk.Fn.ref(glueAccessLogsDatabaseParam.logicalId),
    }));

    glueAccessLogsDatabaseOutput.overrideLogicalId("GlueAccessLogsDatabase");

    const glueAccessLogsTableOutput = (this.outputs[
      "GlueAppAccessLogsTableOutput"
    ] = new cdk.CfnOutput(this, "GlueAppAccessLogsTableOutput", {
      value: cdk.Fn.ref(glueAppAccessLogsTableParam.logicalId),
    }));
    glueAccessLogsTableOutput.overrideLogicalId("GlueAppAccessLogsTable");

    const glueWafAccessLogsTableOutput = (this.outputs[
      "GlueWafAccessLogsTableOutput"
    ] = new cdk.CfnOutput(this, "GlueWafAccessLogsTableOutput", {
      value: cdk.Fn.ref(glueWafAccessLogsTableParam.logicalId),
    }));

    glueWafAccessLogsTableOutput.overrideLogicalId("GlueWafAccessLogsTable");

    const wafWebAclOutput = new cdk.CfnOutput(
      this,
      WebaclNestedstack.WAFWebACL_OUTPUT + "Output",
      {
        value: wafWebAcl.ref,
      },
    );
    wafWebAclOutput.overrideLogicalId(WebaclNestedstack.WAFWebACL_OUTPUT);
    this.outputs[WebaclNestedstack.WAFWebACL_OUTPUT] = wafWebAclOutput;

    this.outputs[WebaclNestedstack.WAFWebACLArn_OUTPUT] = new cdk.CfnOutput(
      this,
      WebaclNestedstack.WAFWebACLArn_OUTPUT,
      {
        value: wafWebAcl.attrArn,
      },
    );

    this.outputs["WAFWebACLMetricName"] = new cdk.CfnOutput(
      this,
      "WAFWebACLMetricName",
      {
        value: cdk.Fn.join("", [
          cdk.Fn.join("", cdk.Fn.split("-", parentStackName.valueAsString)),
          "MaliciousRequesters",
        ]),
      },
    );

    this.outputs["IPReputationListsMetricName"] = new cdk.CfnOutput(
      this,
      "IPReputationListsMetricName",
      {
        value: cdk.Fn.join("", [
          cdk.Fn.join("", cdk.Fn.split("-", parentStackName.valueAsString)),
          "IPReputationListsRule",
        ]),
      },
    );

    this.outputs["Version"] = new cdk.CfnOutput(this, "Version", {
      value: distVersion,
    });

    this.outputs[WebaclNestedstack.WAFWhitelistSetV4Id_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFWhitelistSetV4Id_OUTPUT, {
        value: wafWhitelistSetV4.attrId,
      });

    this.outputs[WebaclNestedstack.WAFBlacklistSetV4Id_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFBlacklistSetV4Id_OUTPUT, {
        value: wafBlacklistSetV4.attrId,
      });

    this.outputs[WebaclNestedstack.WAFHttpFloodSetV4Id_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFHttpFloodSetV4Id_OUTPUT, {
        value: wafHttpFloodSetV4.attrId,
        condition: props.httpFloodProtectionActivated,
      });

    this.outputs[WebaclNestedstack.WAFScannersProbesSetV4Id_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFScannersProbesSetV4Id_OUTPUT,
        {
          value: wafScannersProbesSetV4.attrId,
          condition: props.scannersProbesProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFReputationListsSetV4Id_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFReputationListsSetV4Id_OUTPUT,
        {
          value: wafReputationListsSetV4.attrId,
          condition: props.reputationListsProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFBadBotSetV4Id_OUTPUT] = new cdk.CfnOutput(
      this,
      WebaclNestedstack.WAFBadBotSetV4Id_OUTPUT,
      {
        value: wafBadBotSetV4.attrId,
        condition: props.badBotProtectionActivated,
      },
    );

    this.outputs["WAFWhitelistSetV6Id"] = new cdk.CfnOutput(
      this,
      "WAFWhitelistSetV6Id",
      {
        value: wafWhitelistSetV6.attrId,
      },
    );

    this.outputs[WebaclNestedstack.WAFBlacklistSetV6Id_OUTPUT] =
      new cdk.CfnOutput(this, WebaclNestedstack.WAFBlacklistSetV6Id_OUTPUT, {
        value: wafBlacklistSetV6.attrId,
      });

    this.outputs["WAFHttpFloodSetV6Id"] = new cdk.CfnOutput(
      this,
      "WAFHttpFloodSetV6Id",
      {
        value: wafHttpFloodSetV6.attrId,
        condition: props.httpFloodProtectionActivated,
      },
    );

    this.outputs[WebaclNestedstack.WAFScannersProbesSetV6Id_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFScannersProbesSetV6Id_OUTPUT,
        {
          value: wafScannersProbesSetV6.attrId,
          condition: props.scannersProbesProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFReputationListsSetV6Id_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.WAFReputationListsSetV6Id_OUTPUT,
        {
          value: wafReputationListsSetV6.attrId,
          condition: props.reputationListsProtectionActivated,
        },
      );

    this.outputs[WebaclNestedstack.WAFBadBotSetV6Id_OUTPUT] = new cdk.CfnOutput(
      this,
      WebaclNestedstack.WAFBadBotSetV6Id_OUTPUT,
      {
        value: wafBadBotSetV6.attrId,
        condition: props.badBotProtectionActivated,
      },
    );

    this.outputs[WebaclNestedstack.CustomTimerFunctionName_OUTPUT] =
      new cdk.CfnOutput(
        this,
        WebaclNestedstack.CustomTimerFunctionName_OUTPUT,
        {
          value: this.customTimer.functionName,
        },
      );
  }
}
