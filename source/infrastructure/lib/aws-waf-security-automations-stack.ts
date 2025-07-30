// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  distOutputBucket,
  distVersion,
  manifest,
  solutionId,
  solutionName,
  templateOutputBucket,
  WafRuleKeysType,
} from "./constants/waf-constants";
import {
  CfnCondition,
  CfnOutput,
  CfnParameter,
  Fn,
  Stack,
  StackProps,
  CfnRule,
} from "aws-cdk-lib";
import { WafMetadata } from "./metadata/waf-metadata";
import { SourceCodeMapping } from "./mappings/sourcecode";
import { SolutionMapping } from "./mappings/solution";
import { HelperLambda } from "./components/helpers/helper-lambda";
import { CheckRequirements } from "./components/customs/check-requirements";
import { WebaclNestedstack } from "./nestedstacks/webacl/webacl-nestedstack";
import { CreateGlueDatabase } from "./components/customs/create-glue-database";
import { CreateDeliveryStreamName } from "./components/customs/create-delivery-stream";
import { CreateUniqueID } from "./components/customs/create-unique-id";
import { WafLogBucket } from "./components/s3buckets/waf-log";
import { AccessLoggingBucket } from "./components/s3buckets/access-logging";
import { FirehoseAthenaNestedStack } from "./nestedstacks/firehose-athena/firehose-athena-nestedstack";

import { CustomResourceLambda } from "./components/customResource/custom-resource-lambda";
import { LambdaRoleCustomResource } from "./components/customResource/custom-resource-role";
import { IPRetentionDDBTable } from "./components/setIpRetention/ip-retention-ddb-table";
import { LambdaRoleSetIPRetention } from "./components/setIpRetention/set-ip-retention-role";
import { SetIPRetention } from "./components/setIpRetention/set-ip-retention";
import { LambdaRoleRemoveExpiredIP } from "./components/setIpRetention/remove-expired-ip-role";
import { RemoveExpiredIP } from "./components/setIpRetention/remove-expired-ip";
import { IPExpirationSNSTopic } from "./components/setIpRetention/ip-expiration-sns-topic";
import { SetIPRetentionEventsRule } from "./components/setIpRetention/set-ip-retention-events-rule";
import { SetIPSNS } from "./components/setIpRetention/set-ip-sns";
import { LambdaInvokePermissionSetIPRetention } from "./components/setIpRetention/set-ip-retention-invoke-permission-lambda";
import { DDBStreamToLambdaESMapping } from "./components/setIpRetention/ddb-stream-to-lambda-es-mapping";
import { ReputationList } from "./components/reputationLists/reputation-list";
import { LogParser } from "./components/logParser/log-parser";
import { BadBot } from "./components/badBot/bad-bot";
import { LogsForPartition } from "./components/logsForPartition/logs-for-partition";
import { AddAthenaPartitions } from "./components/athenaPartition/athena-partitions";
import { LambdaRoleAddAthenaPartitions } from "./components/athenaPartition/athena-partitions-role";
import { ConfigureWafLogBucket } from "./components/s3buckets/configure-waf-log";
import { MonitoringDashboard } from "./components/dashboard/monitoring-dashboard";
import { CloudWatchLogRetention } from "./components/customResource/custom-cloudwatchlog-retention";
import { ConfigureWebAcl } from "./components/customResource/custom-configure-webacl";
import { ConfigureAWSWAFLogs } from "./components/customs/custom-config-waf-logs";
import { MetricsLambdaResources } from "./components/metricsLambdaResources/metricsLambdaResources";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import Utils from "./mappings/utils";

export class AwsWafSecurityAutomationsStack extends Stack {
  public static readonly ID = "AwsWafSecurityAutomations";
  public readonly firehoseAthenaNestedStack: FirehoseAthenaNestedStack;
  public readonly webAcl: WebaclNestedstack;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    //=============================================================================================
    // Parameters
    //=============================================================================================
    const parameters = {
      activateAWSManagedRules: new CfnParameter(
        this,
        "ActivateAWSManagedRulesParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "Core Rule Set provides protection against exploitation of a wide range of vulnerabilities,",
            "including some of the high risk and commonly occurring vulnerabilities. Consider using",
            "this rule group for any AWS WAF use case. Required WCU: 700. Your account should have",
            "sufficient WCU capacity to avoid WebACL stack deployment failure due to exceeding the",
            "capacity limit.",
          ].join(" "),
        },
      ),

      activateAWSManagedAP: new CfnParameter(
        this,
        "ActivateAWSManagedAPParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Admin protection rule group blocks external access to exposed administrative pages.",
            "This might be useful if you run third-party software or want to reduce the risk of a",
            "malicious actor gaining administrative access to your application. Required WCU: 100.",
          ].join(" "),
        },
      ),

      activateAWSManagedKBI: new CfnParameter(
        this,
        "ActivateAWSManagedKBIParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Known bad inputs rule group blocks request patterns that are known to be invalid and",
            "are associated with exploitation or discovery of vulnerabilities. This can help reduce",
            "the risk of a malicious actor discovering a vulnerable application. Required WCU: 200.",
          ].join(" "),
        },
      ),

      activateAWSManagedIPR: new CfnParameter(
        this,
        "ActivateAWSManagedIPRParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Amazon IP reputation list rule group are based on Amazon internal threat intelligence.",
            "This is useful if you would like to block IP addresses typically associated with bots or",
            "other threats. Blocking these IP addresses can help mitigate bots and reduce the risk of",
            "a malicious actor discovering a vulnerable application. Required WCU: 25.",
          ].join(" "),
        },
      ),

      activateAWSManagedAIP: new CfnParameter(
        this,
        "ActivateAWSManagedAIPParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Anonymous IP list rule group blocks requests from services that permit the obfuscation of",
            "viewer identity. These include requests from VPNs, proxies, Tor nodes, and hosting providers.",
            "This rule group is useful if you want to filter out viewers that might be trying to hide their",
            "identity from your application. Blocking the IP addresses of these services can help mitigate",
            "bots and evasion of geographic restrictions. Required WCU: 50.",
          ].join(" "),
        },
      ),

      activateAWSManagedSQL: new CfnParameter(
        this,
        "ActivateAWSManagedSQLParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The SQL database rule group blocks request patterns associated with exploitation of SQL databases,",
            "like SQL injection attacks. This can help prevent remote injection of unauthorized queries. Evaluate",
            "this rule group for use if your application interfaces with an SQL database. Using the SQL injection",
            "custom rule is optional, if you already have AWS managed SQL rule group activated. Required WCU: 200.",
          ].join(" "),
        },
      ),

      activateAWSManagedLinux: new CfnParameter(
        this,
        "ActivateAWSManagedLinuxParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Linux operating system rule group blocks request patterns associated with the exploitation of",
            "vulnerabilities specific to Linux, including Linux-specific Local File Inclusion (LFI) attacks.",
            "This can help prevent attacks that expose file contents or run code for which the attacker should",
            "not have had access. Evaluate this rule group if any part of your application runs on Linux. You",
            "should use this rule group in conjunction with the POSIX operating system rule group. Required WCU: 200.",
          ].join(" "),
        },
      ),

      activateAWSManagedPOSIX: new CfnParameter(
        this,
        "ActivateAWSManagedPOSIXParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The POSIX operating system rule group blocks request patterns associated with the exploitation of",
            "vulnerabilities specific to POSIX and POSIX-like operating systems, including Local File Inclusion",
            "(LFI) attacks. This can help prevent attacks that expose file contents or run code for which the",
            "attacker should not have had access. Evaluate this rule group if any part of your application runs",
            "on a POSIX or POSIX-like operating system. Required WCU: 100.",
          ].join(" "),
        },
      ),

      activateAWSManagedWindows: new CfnParameter(
        this,
        "ActivateAWSManagedWindowsParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The Windows operating system rule group blocks request patterns associated with the exploitation of",
            "vulnerabilities specific to Windows, like remote execution of PowerShell commands. This can help",
            "prevent exploitation of vulnerabilities that permit an attacker to run unauthorized commands or run",
            "malicious code. Evaluate this rule group if any part of your application runs on a Windows operating",
            "system. Required WCU: 200.",
          ].join(" "),
        },
      ),

      activateAWSManagedPHP: new CfnParameter(
        this,
        "ActivateAWSManagedPHPParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The PHP application rule group blocks request patterns associated with the exploitation of vulnerabilities",
            "specific to the use of the PHP programming language, including injection of unsafe PHP functions. This can",
            "help prevent exploitation of vulnerabilities that permit an attacker to remotely run code or commands for",
            "which they are not authorized. Evaluate this rule group if PHP is installed on any server with which your",
            "application interfaces. Required WCU: 100.",
          ].join(" "),
        },
      ),

      activateAWSManagedWP: new CfnParameter(
        this,
        "ActivateAWSManagedWPParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description: [
            "The WordPress application rule group blocks request patterns associated with the exploitation of vulnerabilities",
            "specific to WordPress sites. Evaluate this rule group if you are running WordPress. This rule group should be",
            "used in conjunction with the SQL database and PHP application rule groups. Required WCU: 100.",
          ].join(" "),
        },
      ),

      activateSqlInjectionProtection: new CfnParameter(
        this,
        "ActivateSqlInjectionProtectionParam",
        {
          type: "String",
          default: "yes",
          allowedValues: ["yes", "yes - MATCH", "yes - NO_MATCH", "no"],
          description: [
            "Choose yes to deploy the default SQL injection protection rule designed to block common SQL injection attacks.",
            "Consider activating it if you are not using Core Rule Set or AWS managed SQL database rule group. The 'yes' ",
            "option uses CONTINUE for oversized request handling by default. Note: If you customized the rule outside of",
            "CloudFormation, your changes will be overwritten after stack update.",
          ].join(" "),
        },
      ),

      sqlInjectionProtectionSensitivityLevel: new CfnParameter(
        this,
        "SqlInjectionProtectionSensitivityLevelParam",
        {
          type: "String",
          default: "LOW",
          allowedValues: ["LOW", "HIGH"],
          description: [
            "Choose the sensitivity level used by WAF to inspect for SQL injection attacks.",
            "If you choose to deactivate SQL injection protection, ignore this parameter.",
            "Note: The stack deploys the default SQL injection protection rule into your AWS account.",
            "If you customized the rule outside of CloudFormation, your changes will be overwritten after stack update.",
          ].join(" "),
        },
      ),

      activateCrossSiteScriptingProtection: new CfnParameter(
        this,
        "ActivateCrossSiteScriptingProtectionParam",
        {
          type: "String",
          default: "yes",
          allowedValues: ["yes", "yes - MATCH", "yes - NO_MATCH", "no"],
          description: [
            "Choose yes to deploy the default cross-site scripting protection rule designed to block common cross-site scripting attacks.",
            "Consider activating it if you are not using Core Rule Set. The 'yes' option uses CONTINUE for oversized request handling by",
            "default. Note: If you customized the rule outside of CloudFormation, your changes will be overwritten after stack update.",
          ].join(" "),
        },
      ),

      activateHttpFloodProtection: new CfnParameter(
        this,
        "ActivateHttpFloodProtectionParam",
        {
          type: "String",
          default: "yes - AWS WAF rate based rule",
          allowedValues: [
            "yes - AWS WAF rate based rule",
            "yes - AWS Lambda log parser",
            "yes - Amazon Athena log parser",
            "no",
          ],
          description:
            "Choose yes to activate the component designed to block HTTP flood attacks.",
        },
      ),

      activateScannersProbesProtection: new CfnParameter(
        this,
        "ActivateScannersProbesProtectionParam",
        {
          type: "String",
          default: "yes - AWS Lambda log parser",
          allowedValues: [
            "yes - AWS Lambda log parser",
            "yes - Amazon Athena log parser",
            "no",
          ],
          description:
            "Choose yes to activate the component designed to block scanners and probes.",
        },
      ),

      activateReputationListsProtection: new CfnParameter(
        this,
        "ActivateReputationListsProtectionParam",
        {
          type: "String",
          default: "yes",
          allowedValues: ["yes", "no"],
          description: [
            "Choose yes to block requests from IP addresses on third-party reputation lists (supported",
            "lists: spamhaus, torproject, and emergingthreats).",
          ].join(" "),
        },
      ),

      activateBadBotProtection: new CfnParameter(
        this,
        "ActivateBadBotProtectionParam",
        {
          type: "String",
          default: "yes",
          allowedValues: ["yes", "no"],
          description:
            "Choose yes to activate the component designed to block bad bots and content scrapers.",
        },
      ),

      endpointType: new CfnParameter(this, "EndpointType", {
        type: "String",
        default: "CloudFront",
        allowedValues: ["CloudFront", "ALB"],
        description:
          "Select the resource type and then select the resource below that you want to associate with this web ACL.",
      }),

      appAccessLogBucket: new CfnParameter(this, "AppAccessLogBucket", {
        type: "String",
        default: "",
        allowedPattern:
          manifest.wafSecurityAutomations.appAccessLogBucket.patter,
        constraintDescription:
          "Must be a valid S3 bucket name. Input must match the regex pattern: " +
          manifest.wafSecurityAutomations.appAccessLogBucket.patter,
        description:
          "If you chose yes for the Activate Scanners & Probes Protection parameter, enter a name for the Amazon S3 bucket (new or existing) where you want to store access logs for your CloudFront distribution or Application Load Balancer. More about bucket name restriction here: http://amzn.to/1p1YlU5. If you chose to deactivate this protection, ignore this parameter.",
      }),

      appAccessLogBucketPrefix: new CfnParameter(
        this,
        "AppAccessLogBucketPrefixParam",
        {
          type: "String",
          default: "AWSLogs/",
          description:
            "If you chose yes for the Activate Scanners & Probes Protection parameter, you can enter an optional user defined prefix for the application access logs bucket above. For ALB resource, you must append AWSLogs/ to your prefix such as yourprefix/AWSLogs/. For CloudFront resource, you can enter any prefix such as yourprefix/. Leave it to AWSLogs/ (default) if there isn't a user-defined prefix. If you chose to deactivate this protection, ignore this parameter.",
        },
      ),

      appAccessLogBucketLoggingStatus: new CfnParameter(
        this,
        "AppAccessLogBucketLoggingStatusParam",
        {
          type: "String",
          default: "no",
          allowedValues: ["yes", "no"],
          description:
            "Choose yes if you provided an existing application access log bucket above and the server access logging for the bucket is already turned on. If you chose no, the solution will turn on server access logging for your bucket. If you deactivate Scanners & Probes Protection, ignore this parameter.",
        },
      ),

      errorThreshold: new CfnParameter(this, "ErrorThreshold", {
        type: "Number",
        default: 50,
        minValue: 0,
        description: [
          "If you chose yes for the Activate Scanners & Probes Protection parameter, enter the maximum",
          "acceptable bad requests per minute per IP. If you chose to deactivate this protection",
          "protection, ignore this parameter.",
        ].join(" "),
      }),

      requestThreshold: new CfnParameter(this, "RequestThreshold", {
        type: "Number",
        default: 100,
        minValue: 0,
        description: [
          "If you chose yes for the Activate HTTP Flood Protection parameter, enter the maximum",
          "acceptable requests per IP address per FIVE-minute period (default). You can change",
          "the time period by entering a different number for Athena Query Run Time Schedule below.",
          "The request threshold is divided by this number to get the desired threshold per",
          "minute that is used in Athena query. Note: AWS WAF rate based rule requires a value",
          "greater than 10 (if you chose Lambda/Athena log parser options, you can use any value",
          "greater than zero). If you chose to deactivate this protection, ignore this parameter.",
        ].join(" "),
      }),

      requestThresholdByCountry: new CfnParameter(
        this,
        "RequestThresholdByCountryParam",
        {
          type: "String",
          default: "",
          allowedPattern:
            manifest.wafSecurityAutomations.requestThresholdByCountry.patter,
          constraintDescription:
            'You must enter a valid JSON format. Example: {"TR":50, "ER":150}. Note: Input must match the regex pattern: ' +
            manifest.wafSecurityAutomations.requestThresholdByCountry.patter,
          description: [
            "If you chose Athena Log Parser to activate HTTP Flood Protection, you can enter a threshold",
            'by country following this JSON format {"TR":50,"ER":150}. These thresholds will be used for',
            "the requests originated from the specified countries, while the default threshold above",
            "will be used for the remaining requests. The threshold is calculated in a default FIVE-minute",
            "period. You can change the time period by entering a different number for Athena Query Run Time",
            "Schedule below. The request threshold is divided by this number to get the desired threshold",
            "per minute that is used in Athena query. Note: If you define a threshold by country, country",
            "will automatically be included in Athena query group-by clause, along with ip and other group-by",
            "fields you may select below. If you chose to deactivate this protection, ignore this parameter.",
          ].join(" "),
        },
      ),

      httpFloodAthenaQueryGroupBy: new CfnParameter(
        this,
        "HTTPFloodAthenaQueryGroupByParam",
        {
          type: "String",
          default: "None",
          allowedValues: ["Country", "URI", "Country and URI", "None"],
          description: [
            "If you chose Athena Log Parser to activate HTTP Flood Protection, you can select a group-by field",
            "to count requests per IP along with the selected group-by field. For example, if URI is selected,",
            "the requests will be counted per IP and URI. If you chose to deactivate this protection,",
            "ignore this parameter.",
          ].join(" "),
        },
      ),

      wafBlockPeriod: new CfnParameter(this, "WAFBlockPeriod", {
        type: "Number",
        default: 240,
        minValue: 0,
        description: [
          "If you chose yes for the Activate Scanners & Probes Protection or HTTP Flood Lambda/Athena log",
          "parser parameters, enter the period (in minutes) to block applicable IP addresses. If you",
          "chose to deactivate log parsing, ignore this parameter.",
        ].join(" "),
      }),

      athenaQueryRunTimeSchedule: new CfnParameter(
        this,
        "AthenaQueryRunTimeScheduleParam",
        {
          type: "Number",
          default: 5,
          minValue: 1,
          description: [
            "If you chose Athena Log Parser to activate Scanners & Probes Protection or HTTP Flood Protection,",
            "you can enter a time interval (in minutes) over which the Athena query runs. By default, the Athena",
            "query runs every 5 minutes. Request threshold entered above is divided by this number to get the",
            "threshold per minute in the Athena query. If you chose to deactivate these protections, ignore this",
            "parameter.",
          ].join(" "),
        },
      ),

      keepDataInOriginalS3Location: new CfnParameter(
        this,
        "KeepDataInOriginalS3Location",
        {
          type: "String",
          default: "No",
          allowedValues: ["Yes", "No"],
          description: [
            "If you chose Amazon Athena log parser for the Activate Scanners & Probes Protection parameter,",
            "partitioning will be applied to log files and Athena queries. By default log files will be moved",
            "from their original location to a partitioned folder structure in s3. Choose Yes if you also want",
            'to keep a copy of the logs in their original location. Selecting "Yes" will duplicate your log',
            "storage. If you did not choose to activate Athena log parsing, ignore this parameter.",
          ].join(" "),
        },
      ),

      ipRetentionPeriodAllowed: new CfnParameter(
        this,
        "IPRetentionPeriodAllowedParam",
        {
          type: "Number",
          default: -1,
          minValue: -1,
          description: [
            "If you want to activate IP retention for the Allowed IP set, enter a number (15 or above) as the retention period (minutes).",
            "IP addresses reaching the retention period will expire and be removed from the IP set. A minimum 15-minute retention",
            "period is supported. If you enter a number between 0 and 15, it will be treated as 15. Leave it to default value -1",
            "to disable IP retention.",
          ].join(" "),
        },
      ),

      ipRetentionPeriodDenied: new CfnParameter(
        this,
        "IPRetentionPeriodDeniedParam",
        {
          type: "Number",
          default: -1,
          minValue: -1,
          description: [
            "If you want to activate IP retention for the Denied IP set, enter a number (15 or above) as the retention period (minutes).",
            "IP addresses reaching the retention period will expire and be removed from the IP set. A minimum 15-minute retention",
            "period is supported. If you enter a number between 0 and 15, it will be treated as 15. Leave it to default value -1",
            "to disable IP retention.",
          ].join(" "),
        },
      ),

      snsEmail: new CfnParameter(this, "SNSEmailParam", {
        type: "String",
        default: "",
        allowedPattern: manifest.wafSecurityAutomations.snsEmail.patter,
        constraintDescription:
          "You must enter a valid email address. Example: user@example.com. Input must match the regex pattern: " +
          manifest.wafSecurityAutomations.snsEmail.patter,
        description: [
          "If you activated IP retention period above and want to receive an email notification when IP addresses expire,",
          "enter a valid email address. If you did not activate IP retention or want to disable email notification,",
          "leave it blank (default).",
        ].join(" "),
      }),

      logGroupRetention: new CfnParameter(this, "LogGroupRetentionParam", {
        type: "Number",
        default: manifest.wafSecurityAutomations.logGroupRetention.default,
        allowedValues: [
          "-1",
          "1",
          "3",
          "5",
          "7",
          "14",
          "30",
          "60",
          "90",
          "120",
          "150",
          "180",
          "365",
          "400",
          "545",
          "731",
          "1827",
          "3653",
        ],
        description: [
          "If you want to activate retention for the CloudWatch Log Groups, enter a number (1 or above) as the retention period (days).",
          "You can choose a retention period between one day and 10 years. By default logs will expired after 1 year. Set it to -1 to",
          "keep the logs indefinitely.",
        ].join(" "),
      }),

      wafRuleKeysType: new CfnParameter(this, "WAFRuleKeysTypeParam", {
        type: "String",
        default: WafRuleKeysType.IP,
        allowedValues: [
          WafRuleKeysType.IP,
          WafRuleKeysType.IP_CUSTOM_HEADER,
          WafRuleKeysType.IP_URI,
          WafRuleKeysType.IP_HTTP_METHOD,
        ],
        description: [
          "If you chose yes for the WAF rate-based rule parameter, you can select the type of aggregation key to use for HTTP flood protection. IP is the default.",
          'If "IP+Custom Header" is selected, you must specify a custom header name.',
        ].join(" "),
      }),

      customHeaderName: new CfnParameter(this, "CustomHeaderNameParam", {
        type: "String",
        default: "",
        allowedPattern: manifest.wafSecurityAutomations.customHeaderName.patter,
        maxLength: 64,
        constraintDescription:
          "Max length must be between not more 64 characters. Input must match the regex pattern: " +
          manifest.wafSecurityAutomations.customHeaderName.patter,
        description:
          'If you chose yes for the WAF rate-based rule parameter and "IP+Custom Header" is selected above, enter the name of the custom header to use for request aggregation.',
      }),

      timeWindowThreshold: new CfnParameter(this, "TimeWindowThresholdParam", {
        type: "Number",
        default: 5,
        allowedValues: ["1", "2", "5", "10"],
        description:
          "Time window threshold in minutes for Activate Scanners & Probes Protection or HTTP Flood. Applies to both rate-based rule and lambda log parser.",
        constraintDescription:
          "Must be one of the following values: 1, 2, 5, or 10",
      }),
    };

    //=============================================================================================
    // Metadata
    //=============================================================================================
    // prettier-ignore
    new WafMetadata(this, "AwsWafSecurityAutomationsMetadata", {//NOSONAR - skip sonar detection useless object instantiation
      parameters,
      templateFormatVersion: manifest.awsTemplateFormatVersion,
      description: manifest.wafSecurityAutomations.description,
    });

    //=============================================================================================
    // Condition
    //=============================================================================================
    const httpFloodProtectionRateBasedRuleActivated = new CfnCondition(
      this,
      "HttpFloodProtectionRateBasedRuleActivated",
      {
        expression: Fn.conditionEquals(
          parameters.activateHttpFloodProtection.valueAsString,
          "yes - AWS WAF rate based rule",
        ),
      },
    );

    const httpFloodLambdaLogParser = new CfnCondition(
      this,
      "HttpFloodLambdaLogParser",
      {
        expression: Fn.conditionEquals(
          parameters.activateHttpFloodProtection.valueAsString,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const httpFloodAthenaLogParser = new CfnCondition(
      this,
      "HttpFloodAthenaLogParser",
      {
        expression: Fn.conditionEquals(
          parameters.activateHttpFloodProtection.valueAsString,
          "yes - Amazon Athena log parser",
        ),
      },
    );

    const scannersProbesLambdaLogParser = new CfnCondition(
      this,
      "ScannersProbesLambdaLogParser",
      {
        expression: Fn.conditionEquals(
          parameters.activateScannersProbesProtection.valueAsString,
          "yes - AWS Lambda log parser",
        ),
      },
    );

    const badBotProtectionActivated = new CfnCondition(
      this,
      "BadBotProtectionActivated",
      {
        expression: Fn.conditionEquals(
          parameters.activateBadBotProtection.valueAsString,
          "yes",
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

    const scannersProbesAthenaLogParser = new CfnCondition(
      this,
      "ScannersProbesAthenaLogParser",
      {
        expression: Fn.conditionEquals(
          parameters.activateScannersProbesProtection.valueAsString,
          "yes - Amazon Athena log parser",
        ),
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

    const scannersProbesProtectionActivated = new CfnCondition(
      this,
      "ScannersProbesProtectionActivated",
      {
        expression: Fn.conditionOr(
          scannersProbesLambdaLogParser,
          scannersProbesAthenaLogParser,
        ),
      },
    );

    const athenaLogParser = new CfnCondition(this, "AthenaLogParser", {
      expression: Fn.conditionOr(
        httpFloodAthenaLogParser,
        scannersProbesAthenaLogParser,
      ),
    });

    const logParser = new CfnCondition(this, "LogParser", {
      expression: Fn.conditionOr(
        httpFloodProtectionLogParserActivated,
        scannersProbesProtectionActivated,
      ),
    });

    const createFirehoseAthenaStack = new CfnCondition(
      this,
      "CreateFirehoseAthenaStack",
      {
        expression: Fn.conditionOr(
          httpFloodProtectionLogParserActivated,
          athenaLogParser,
        ),
      },
    );

    const reputationListsProtectionActivated = new CfnCondition(
      this,
      "ReputationListsProtectionActivated",
      {
        expression: Fn.conditionEquals(
          parameters.activateReputationListsProtection.valueAsString,
          "yes",
        ),
      },
    );

    const albEndpoint = new CfnCondition(this, "AlbEndpoint", {
      expression: Fn.conditionEquals(
        parameters.endpointType.valueAsString,
        "ALB",
      ),
    });

    const customResourceLambdaAccess = new CfnCondition(
      this,
      "CustomResourceLambdaAccess",
      {
        expression: Fn.conditionOr(
          reputationListsProtectionActivated,
          athenaLogParser,
        ),
      },
    );

    const ipRetentionAllowedPeriod = new CfnCondition(
      this,
      "IPRetentionAllowedPeriod",
      {
        expression: Fn.conditionNot(
          Fn.conditionEquals(
            parameters.ipRetentionPeriodAllowed.valueAsNumber,
            -1,
          ),
        ),
      },
    );

    const ipRetentionDeniedPeriod = new CfnCondition(
      this,
      "IPRetentionDeniedPeriod",
      {
        expression: Fn.conditionNot(
          Fn.conditionEquals(
            parameters.ipRetentionPeriodDenied.valueAsNumber,
            -1,
          ),
        ),
      },
    );

    const ipRetentionPeriod = new CfnCondition(this, "IPRetentionPeriod", {
      expression: Fn.conditionOr(
        ipRetentionAllowedPeriod,
        ipRetentionDeniedPeriod,
      ),
    });

    const snsEmailProvided = new CfnCondition(this, "SNSEmailProvided", {
      expression: Fn.conditionNot(
        Fn.conditionEquals(parameters.snsEmail.valueAsString, ""),
      ),
    });

    const snsEmail = new CfnCondition(this, "SNSEmail", {
      expression: Fn.conditionAnd(ipRetentionPeriod, snsEmailProvided),
    });

    const appAccessLogBucketLoggingOff = new CfnCondition(
      this,
      "AppAccessLogBucketLoggingOff",
      {
        expression: Fn.conditionEquals(
          parameters.appAccessLogBucketLoggingStatus.valueAsString,
          "no",
        ),
      },
    );

    const turnOnAppAccessLogBucketLogging = new CfnCondition(
      this,
      "TurnOnAppAccessLogBucketLogging",
      {
        expression: Fn.conditionAnd(
          scannersProbesProtectionActivated,
          appAccessLogBucketLoggingOff,
        ),
      },
    );

    const createS3LoggingBucket = new CfnCondition(
      this,
      "CreateS3LoggingBucket",
      {
        expression: Fn.conditionOr(
          httpFloodProtectionLogParserActivated,
          turnOnAppAccessLogBucketLogging,
        ),
      },
    );

    const userDefinedAppAccessLogBucketPrefix = new CfnCondition(
      this,
      "UserDefinedAppAccessLogBucketPrefix",
      {
        expression: Fn.conditionNot(
          Fn.conditionEquals(
            parameters.appAccessLogBucketPrefix.valueAsString,
            "AWSLogs/",
          ),
        ),
      },
    );

    const requestThresholdByCountry = new CfnCondition(
      this,
      "RequestThresholdByCountry",
      {
        expression: Fn.conditionNot(
          Fn.conditionEquals(
            parameters.requestThresholdByCountry.valueAsString,
            "",
          ),
        ),
      },
    );

    const isAthenaQueryRunEveryMinute = new CfnCondition(
      this,
      "IsAthenaQueryRunEveryMinute",
      {
        expression: Fn.conditionEquals(
          parameters.athenaQueryRunTimeSchedule.valueAsNumber,
          1,
        ),
      },
    );

    const logGroupRetentionEnabled = new CfnCondition(
      this,
      "LogGroupRetentionEnabled",
      {
        expression: Fn.conditionNot(
          Fn.conditionEquals(parameters.logGroupRetention.valueAsNumber, -1),
        ),
      },
    );

    const badBotWafLogActivated = new CfnCondition(
      this,
      "BadBotWafLogActivated",
      {
        expression: Fn.conditionAnd(
          badBotProtectionActivated,
          Fn.conditionOr(
            httpFloodLambdaLogParser,
            badBotLambdaLogParserActivated,
          ),
        ),
      },
    );

    const badBotLambdaAccessLogActivated = new CfnCondition(
      this,
      "BadBotLambdaAccessLogActivated",
      {
        expression: Fn.conditionAnd(
          badBotProtectionActivated,
          Fn.conditionAnd(
            Fn.conditionNot(httpFloodLambdaLogParser),
            scannersProbesLambdaLogParser,
          ),
        ),
      },
    );

    const badBotAthenaWafLogActivated = new CfnCondition(
      this,
      "BadBotAthenaWafLogActivated",
      {
        expression: Fn.conditionAnd(
          badBotProtectionActivated,
          Fn.conditionAnd(
            Fn.conditionNot(httpFloodLambdaLogParser),
            Fn.conditionNot(scannersProbesLambdaLogParser),
            httpFloodAthenaLogParser,
          ),
        ),
      },
    );

    const badBotAthenaAccessLogActivated = new CfnCondition(
      this,
      "BadBotAthenaAccessLogActivated",
      {
        expression: Fn.conditionAnd(
          badBotProtectionActivated,
          Fn.conditionAnd(
            Fn.conditionNot(httpFloodLambdaLogParser),
            Fn.conditionNot(scannersProbesLambdaLogParser),
            Fn.conditionNot(httpFloodAthenaLogParser),
            scannersProbesAthenaLogParser,
          ),
        ),
      },
    );

    //=============================================================================================
    // Util
    //=============================================================================================
    const metricNamePrefix = Fn.join(
      "",
      Fn.split("-", Fn.ref("AWS::StackName")),
    );

    //=============================================================================================
    // Mappings
    //=============================================================================================
    const sourceCodeMapping = new SourceCodeMapping(this, "SourceCode", {
      templateBucket: templateOutputBucket,
      sourceBucket: distOutputBucket,
      keyPrefix: `${solutionName}/${distVersion}`,
    });

    const solutionMapping = new SolutionMapping(this, "Solution", {
      solutionId: solutionId,
      distVersion: distVersion,
      metricsURL: manifest.wafSecurityAutomations.metricsURL,
      solutionName: manifest.solutionName,
    });

    //=============================================================================================
    // Resources
    //=============================================================================================
    const helperLambda = new HelperLambda(this, HelperLambda.ID, {
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      albEndpoint: albEndpoint,
    });

    const checkRequirements = new CheckRequirements(
      this,
      CheckRequirements.ID,
      {
        helperFunction: helperLambda.getHelperFunction(),
        athenaLogParser: athenaLogParser,
        httpFloodProtectionRateBasedRuleActivated:
          httpFloodProtectionRateBasedRuleActivated,
        httpFloodProtectionLogParserActivated:
          httpFloodProtectionLogParserActivated,
        scannersProbesProtectionActivated: scannersProbesProtectionActivated,
        appAccessLogBucket: parameters.appAccessLogBucket,
        endpointType: parameters.endpointType,
        requestThreshold: parameters.requestThreshold,
      },
    );

    const createUniqueID = new CreateUniqueID(this, CreateUniqueID.ID, {
      helperFunction: helperLambda.getHelperFunction(),
      checkRequirements: checkRequirements,
    });

    const createGlueDatabaseName = new CreateGlueDatabase(
      this,
      CreateGlueDatabase.ID,
      {
        helperFunction: helperLambda.getHelperFunction(),
        athenaLogParserCondition: athenaLogParser,
        checkRequirements: checkRequirements,
      },
    );

    const createDeliveryStreamName = new CreateDeliveryStreamName(
      this,
      CreateDeliveryStreamName.ID,
      {
        helperFunction: helperLambda.getHelperFunction(),
        httpFloodProtectionLogParserActivated:
          httpFloodProtectionLogParserActivated,
        checkRequirements: checkRequirements,
      },
    );

    //=============================================================================================
    // Resources S3 Buckets
    //=============================================================================================
    const wafLogBucket = new WafLogBucket(this, WafLogBucket.ID, {
      httpFloodProtectionLogParserActivated:
        httpFloodProtectionLogParserActivated,
      checkRequirements: checkRequirements,
      accessLoggingBucket: AccessLoggingBucket.ID,
    });

    const accessLoggingBucket = new AccessLoggingBucket(
      this,
      AccessLoggingBucket.ID,
      {
        createS3LoggingBucketCondition: createS3LoggingBucket,
        checkRequirements: checkRequirements,
        httpFloodProtectionLogParserActivated:
          httpFloodProtectionLogParserActivated,
        appAccessLogBucket: parameters.appAccessLogBucket,
        wafLogBucket: wafLogBucket.getBucket(),
      },
    );

    //=============================================================================================
    // Resources Firehose and Athena
    //=============================================================================================
    this.firehoseAthenaNestedStack = new FirehoseAthenaNestedStack(
      this,
      FirehoseAthenaNestedStack.ID,
      {
        createFirehoseAthenaStack: createFirehoseAthenaStack,
        checkRequirements: checkRequirements,
        sourceCodeMapping: sourceCodeMapping,
        parameters: {
          ["UUID"]: createUniqueID.getUUID(),
          ["ActivateHttpFloodProtectionParam"]:
            parameters.activateHttpFloodProtection.valueAsString,
          ["ActivateScannersProbesProtectionParam"]:
            parameters.activateScannersProbesProtection.valueAsString,
          ["EndpointType"]: parameters.endpointType.valueAsString,
          ["AppAccessLogBucket"]: parameters.appAccessLogBucket.valueAsString,
          ["ParentStackName"]: Fn.ref("AWS::StackName"),
          ["WafLogBucket"]: Fn.conditionIf(
            httpFloodProtectionLogParserActivated.logicalId,
            wafLogBucket.getBucket().ref,
            "",
          ).toString(),
          ["WafLogBucketArn"]: Fn.conditionIf(
            httpFloodProtectionLogParserActivated.logicalId,
            wafLogBucket.getBucket().attrArn,
            "",
          ).toString(),
          ["ActivateBadBotProtectionParam"]:
            parameters.activateBadBotProtection.valueAsString,
          ["ErrorThreshold"]: parameters.errorThreshold.valueAsString,
          ["RequestThreshold"]: parameters.requestThreshold.valueAsString,
          ["WAFBlockPeriod"]: parameters.wafBlockPeriod.valueAsString,
          ["GlueDatabaseName"]: Fn.conditionIf(
            athenaLogParser.logicalId,
            createGlueDatabaseName.getDatabaseName(),
            "",
          ).toString(),
          ["DeliveryStreamName"]: Fn.conditionIf(
            httpFloodProtectionLogParserActivated.logicalId,
            createDeliveryStreamName.getDeliveryStreamName(),
            "",
          ).toString(),
          ["TimeWindowThresholdParam"]:
            parameters.timeWindowThreshold.valueAsString,
        },
      },
    );

    //=============================================================================================
    // Resources WebACL
    //=============================================================================================
    this.webAcl = new WebaclNestedstack(this, "Webacl", {
      parameters: {
        ["ActivateAWSManagedAIPParam"]:
          parameters.activateAWSManagedAIP.valueAsString,
        ["ActivateAWSManagedAPParam"]:
          parameters.activateAWSManagedAP.valueAsString,
        ["ActivateAWSManagedIPRParam"]:
          parameters.activateAWSManagedIPR.valueAsString,
        ["ActivateAWSManagedKBIParam"]:
          parameters.activateAWSManagedKBI.valueAsString,
        ["ActivateAWSManagedLinuxParam"]:
          parameters.activateAWSManagedLinux.valueAsString,
        ["ActivateAWSManagedPHPParam"]:
          parameters.activateAWSManagedPHP.valueAsString,
        ["ActivateAWSManagedPOSIXParam"]:
          parameters.activateAWSManagedPOSIX.valueAsString,
        ["ActivateAWSManagedRulesParam"]:
          parameters.activateAWSManagedRules.valueAsString,
        ["ActivateAWSManagedSQLParam"]:
          parameters.activateAWSManagedSQL.valueAsString,
        ["ActivateAWSManagedWPParam"]:
          parameters.activateAWSManagedWP.valueAsString,
        ["ActivateAWSManagedWindowsParam"]:
          parameters.activateAWSManagedWindows.valueAsString,
        ["ActivateBadBotProtectionParam"]:
          parameters.activateBadBotProtection.valueAsString,
        ["ActivateCrossSiteScriptingProtectionParam"]:
          parameters.activateCrossSiteScriptingProtection.valueAsString,
        ["SqlInjectionProtectionSensitivityLevelParam"]:
          parameters.sqlInjectionProtectionSensitivityLevel.valueAsString,
        ["ActivateHttpFloodProtectionParam"]:
          parameters.activateHttpFloodProtection.valueAsString,
        ["ActivateReputationListsProtectionParam"]:
          parameters.activateReputationListsProtection.valueAsString,
        ["ActivateScannersProbesProtectionParam"]:
          parameters.activateScannersProbesProtection.valueAsString,
        ["ActivateSqlInjectionProtectionParam"]:
          parameters.activateSqlInjectionProtection.valueAsString,
        ["LogLevel"]: solutionMapping.findInMap("Data", "LogLevel"),
        ["RequestThreshold"]: parameters.requestThreshold.valueAsString,
        ["ParentStackName"]: Fn.ref("AWS::StackName"),
        ["RegionScope"]: Fn.conditionIf(
          albEndpoint.logicalId,
          "REGIONAL",
          "CLOUDFRONT",
        ).toString(),
        ["GlueAccessLogsDatabase"]: Fn.conditionIf(
          athenaLogParser.logicalId,
          Fn.getAtt(
            this.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
            "Outputs.GlueAccessLogsDatabase",
          ).toString(),
          "",
        ).toString(),
        ["GlueAppAccessLogsTable"]: Fn.conditionIf(
          scannersProbesAthenaLogParser.logicalId,
          Fn.getAtt(
            this.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
            "Outputs.GlueAppAccessLogsTable",
          ).toString(),
          "",
        ).toString(),
        ["GlueWafAccessLogsTable"]: Fn.conditionIf(
          httpFloodAthenaLogParser.logicalId,
          Fn.getAtt(
            this.firehoseAthenaNestedStack.nestedStackResource!.logicalId,
            "Outputs.GlueWafAccessLogsTable",
          ).toString(),
          "",
        ).toString(),
        ["CustomHeaderNameParam"]: parameters.customHeaderName.valueAsString,
        ["WAFRuleKeysTypeParam"]: parameters.wafRuleKeysType.valueAsString,
        ["TimeWindowThresholdParam"]:
          parameters.timeWindowThreshold.valueAsString,
      },
      athenaLogParser: athenaLogParser,
      badBotProtectionActivated: badBotProtectionActivated,
      scannersProbesProtectionActivated: scannersProbesProtectionActivated,
      reputationListsProtectionActivated: reputationListsProtectionActivated,
      httpFloodProtectionActivated: httpFloodProtectionActivated,
      httpFloodAthenaLogParser: httpFloodAthenaLogParser,
      httpFloodProtectionRateBasedRule:
        httpFloodProtectionRateBasedRuleActivated,
      sourceCodeMapping: sourceCodeMapping,
      checkRequirements: checkRequirements,
    });

    //=============================================================================================
    // Resources Customs
    //=============================================================================================
    const lambdaRoleCustomResource = new LambdaRoleCustomResource(
      this,
      LambdaRoleCustomResource.ID,
      {
        webAclStack: this.webAcl,
        httpFloodProtectionLogParserActivated:
          httpFloodProtectionLogParserActivated,
        scannersProbesLambdaLogParser: scannersProbesLambdaLogParser,
        httpFloodLambdaLogParser: httpFloodLambdaLogParser,
        customResourceLambdaAccess: customResourceLambdaAccess,
        scannersProbesProtectionActivated: scannersProbesProtectionActivated,
      },
    );

    const customResource = new CustomResourceLambda(
      this,
      CustomResourceLambda.ID,
      {
        lambdaRoleCustomResource: lambdaRoleCustomResource,
        albEndpoint: albEndpoint,
        sourceCodeMapping: sourceCodeMapping,
        solutionMapping: solutionMapping,
        createUniqueID: createUniqueID,
      },
    );

    // prettier-ignore
    new ConfigureAWSWAFLogs(this, ConfigureAWSWAFLogs.ID, {//NOSONAR - skip sonar detection useless object instantiation
      httpFloodProtectionLogParserActivated:
        httpFloodProtectionLogParserActivated,
      helperFunction: customResource.getFunction(),
      webACLStack: this.webAcl,
      firehoseAthenaNestedStack: this.firehoseAthenaNestedStack,
      badBotLambdaLogParserActivated: badBotLambdaLogParserActivated,
    });

    //=============================================================================================
    // Resources S3 Logs Partition
    //=============================================================================================
    const logsForPartition = new LogsForPartition(this, LogsForPartition.ID, {
      appAccessLogBucket: parameters.appAccessLogBucket.valueAsString,
      scannersProbesAthenaLogParserCondition: scannersProbesAthenaLogParser,
      solutionMapping: solutionMapping,
      sourceCodeMapping: sourceCodeMapping,
      keepDataInOriginalS3Location:
        parameters.keepDataInOriginalS3Location.valueAsString,
      endpointType: parameters.endpointType.valueAsString,
    });

    //=============================================================================================
    // Resources Bad bot
    //=============================================================================================
    // prettier-ignore
    new BadBot(this, "BadBot", { //NOSONAR - skip sonar detection useless object instantiation
      badBotProtectionActivated: badBotProtectionActivated,
    });

    //=============================================================================================
    // Resources Athena Partitions
    //=============================================================================================
    const lambdaRoleAddAthena = new LambdaRoleAddAthenaPartitions(
      this,
      LambdaRoleAddAthenaPartitions.ID,
      {
        scannersProbesAthenaLogParserCondition: scannersProbesAthenaLogParser,
        httpFloodAthenaLogParserCondition: httpFloodAthenaLogParser,
        athenaLogParser: athenaLogParser,
      },
    );

    const addAthenaPartitions = new AddAthenaPartitions(
      this,
      AddAthenaPartitions.ID,
      {
        athenaLogParserCondition: athenaLogParser,
        lambdaRoleAddAthena: lambdaRoleAddAthena.getRole(),
        solutionMapping: solutionMapping,
        scannersProbesAthenaLogParserCondition: scannersProbesAthenaLogParser,
        httpFloodAthenaLogParserCondition: httpFloodAthenaLogParser,
        sourceCodeMapping: sourceCodeMapping,
        firehoseAthenaNestedStack: this.firehoseAthenaNestedStack,
        appAccessLogBucket: parameters.appAccessLogBucket,
        wafLogBucket: wafLogBucket.getBucket(),
        customResource: customResource,
      },
    );

    //=============================================================================================
    // Resources log parser
    //=============================================================================================
    const logParserResource = new LogParser(this, "LogParserResources", {
      httpFloodProtectionActivated: httpFloodProtectionActivated,
      badBotWafLogActivated: badBotWafLogActivated,
      badBotLambdaAccessLogActivated: badBotLambdaAccessLogActivated,
      badBotAthenaWafLogActivated: badBotAthenaWafLogActivated,
      badBotAthenaAccessLogActivated: badBotAthenaAccessLogActivated,
      badBotLambdaLogParserActivated: badBotLambdaLogParserActivated,
      badBotProtectionActivated: badBotProtectionActivated,
      httpFloodProtectionLogParserActivated:
        httpFloodProtectionLogParserActivated,
      httpFloodLambdaLogParser: httpFloodLambdaLogParser,
      scannersProbesAthenaLogParser: scannersProbesAthenaLogParser,
      param: parameters,
      scannersProbesProtectionActivated: scannersProbesProtectionActivated,
      scannersProbesLambdaLogParser: scannersProbesLambdaLogParser,
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      httpFloodAthenaLogParser: httpFloodAthenaLogParser,
      logParser: logParser,
      albEndpoint: albEndpoint,
      isAthenaQueryRunEveryMinute: isAthenaQueryRunEveryMinute,
      customResource: customResource,
      logsForPartition: logsForPartition,
      accessLoggingBucket: accessLoggingBucket.getBucket(),
      wafLogBucket: wafLogBucket.getBucket(),
      UUID: createUniqueID,
      metricNamePrefix: metricNamePrefix,
      moveS3LogsForPartition: logsForPartition.getLambdaFunction(),
      turnOnAppAccessLogBucketLogging: turnOnAppAccessLogBucketLogging,
      webACLStack: this.webAcl,
    });

    //=============================================================================================
    // Resources Reputation list
    //=============================================================================================
    const reputationLists = new ReputationList(this, "ReputationList", {
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      albEndpoint: albEndpoint,
      version: distVersion,
      reputationListsProtectionActivated: reputationListsProtectionActivated,
      webACLStack: this.webAcl,
      UUID: createUniqueID,
    });

    //=============================================================================================
    // Resources Configures
    //=============================================================================================
    // prettier-ignore
    new ConfigureWafLogBucket(this, ConfigureWafLogBucket.ID, { //NOSONAR - skip sonar detection useless object instantiation
      badBotLambdaLogParserActivated: badBotLambdaLogParserActivated,
      httpFloodProtectionLogParserActivatedCondition:
        httpFloodProtectionLogParserActivated,
      customResourceLambda: customResource.getFunction(),
      wafLogBucket: wafLogBucket.getBucket(),
      logParserCondition: logParser,
      logParserLambda: logParserResource.getLambdaFunction(),
      httpFloodLambdaLogParserCondition: httpFloodLambdaLogParser,
      httpFloodAthenaLogParserCondition: httpFloodAthenaLogParser,
    });

    //=============================================================================================
    // Resources IP Retention
    //=============================================================================================
    const ipRetentionDDBTable = new IPRetentionDDBTable(
      this,
      IPRetentionDDBTable.ID,
      {
        ipRetentionPeriodCondition: ipRetentionPeriod,
      },
    );

    const lambdaRoleSetIPRetention = new LambdaRoleSetIPRetention(
      this,
      LambdaRoleSetIPRetention.ID,
      {
        ipRetentionPeriodCondition: ipRetentionPeriod,
        ipRetentionDDBTable: ipRetentionDDBTable.getTable(),
      },
    );

    const lambdaRoleRemoveExpiredIP = new LambdaRoleRemoveExpiredIP(
      this,
      LambdaRoleRemoveExpiredIP.ID,
      {
        ipRetentionPeriodCondition: ipRetentionPeriod,
        webACLStack: this.webAcl,
        ipRetentionDDBTable: ipRetentionDDBTable.getTable(),
      },
    );

    const setIPRetention = new SetIPRetention(this, SetIPRetention.ID, {
      ipRetentionPeriodCondition: ipRetentionPeriod,
      lambdaRoleSetIPRetention: lambdaRoleSetIPRetention,
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      ipRetentionDDBTable: ipRetentionDDBTable.getTable(),
      ipRetentionPeriodAllowedParam: parameters.ipRetentionPeriodAllowed,
      ipRetentionPeriodDeniedParam: parameters.ipRetentionPeriodDenied,
      lambdaRoleRemoveExpiredIP: lambdaRoleRemoveExpiredIP.getRole(),
    });

    const ipExpirationSNSTopic = new IPExpirationSNSTopic(
      this,
      IPExpirationSNSTopic.ID,
      {
        snsEmailCondition: snsEmail,
        createUniqueID: createUniqueID,
      },
    );

    const removeExpiredIP = new RemoveExpiredIP(this, RemoveExpiredIP.ID, {
      ipRetentionPeriodCondition: ipRetentionPeriod,
      lambdaRoleRemoveExpiredIP: lambdaRoleRemoveExpiredIP,
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      createUniqueID: createUniqueID,
      snsEmail: snsEmail,
      ipExpirationSNSTopic: ipExpirationSNSTopic.getTopic(),
    });

    const setIPRetentionEventsRule = new SetIPRetentionEventsRule(
      this,
      SetIPRetentionEventsRule.ID,
      {
        ipRetentionPeriodCondition: ipRetentionPeriod,
        setIPRetention: setIPRetention,
        webACLStack: this.webAcl,
      },
    );

    // prettier-ignore
    new SetIPSNS(this, SetIPSNS.ID, {//NOSONAR - skip sonar detection useless object instantiation
      lambdaRoleRemoveExpiredIP: lambdaRoleRemoveExpiredIP.getRole(),
      ipExpirationSnsTopic: ipExpirationSNSTopic.getTopic(),
      snsEmailCondition: snsEmail,
      snsEmailParam: parameters.snsEmail,
    });

    // prettier-ignore
    new LambdaInvokePermissionSetIPRetention(this, LambdaInvokePermissionSetIPRetention.ID, {//NOSONAR - skip sonar detection useless object instantiation
        ipRetentionPeriodCondition: ipRetentionPeriod,
        setIPRetentionLambda: setIPRetention.getFunction(),
        setIPRetentionEventsRule: setIPRetentionEventsRule.getRule(),
      },
    );

    // prettier-ignore
    new DDBStreamToLambdaESMapping(this, DDBStreamToLambdaESMapping.ID, {//NOSONAR - skip sonar detection useless object instantiation
      ipRetentionPeriodCondition: ipRetentionPeriod,
      ipRetentionDDBTable: ipRetentionDDBTable.getTable(),
      removeExpiredIPLambda: removeExpiredIP.getFunction(),
    });

    // prettier-ignore
    new MonitoringDashboard(this, MonitoringDashboard.ID, {//NOSONAR - skip sonar detection useless object instantiation
      albEndpoint: albEndpoint,
      webACLStack: this.webAcl,
      checkRequirements: checkRequirements,
    });

    // prettier-ignore
    new CloudWatchLogRetention(this, CloudWatchLogRetention.ID, {//NOSONAR - skip sonar detection useless object instantiation
      customResource: customResource.getFunction(),
      parameters: parameters,
      webaclOutputs: this.webAcl.outputs,
      logParserName: logParserResource.getLambdaFunction().ref,
      helperName: helperLambda.getHelperFunction().functionName,
      moveS3LogsForPartitionName:
        logsForPartition.getLambdaFunction().functionName,
      addAthenaPartitionsName: addAthenaPartitions.getFunction().functionName,
      setIPRetentionName: setIPRetention.getFunction().functionName,
      removeExpiredIPName: removeExpiredIP.getFunction().functionName,
      reputationListsParserName: reputationLists.getFunction()?.ref,
      logGroupRetentionEnabled: logGroupRetentionEnabled,
      athenaLogParser: athenaLogParser,
      badBotProtectionActivated: badBotProtectionActivated,
      checkRequirements: checkRequirements,
      scannersProbesAthenaLogParser: scannersProbesAthenaLogParser,
      ipRetentionPeriod: ipRetentionPeriod,
      logParser: logParser,
      reputationListsProtectionActivated: reputationListsProtectionActivated,
      webACLStack: this.webAcl,
    });

    // prettier-ignore
    new ConfigureWebAcl(this, ConfigureWebAcl.ID, {//NOSONAR - skip sonar detection useless object instantiation
      customResource: customResource.getFunction(),
      parameters: parameters,
      webACLStack: this.webAcl,
      userDefinedAppAccessLogBucketPrefix: userDefinedAppAccessLogBucketPrefix,
      requestThresholdByCountry: requestThresholdByCountry,
      checkRequirements: checkRequirements,
      httpFloodProtectionActivated: httpFloodProtectionActivated,
      solutionMapping: solutionMapping,
      UUID: createUniqueID,
      badBotProtectionActivated: badBotProtectionActivated,
      reputationListsProtectionActivated: reputationListsProtectionActivated,
      scannersProbesProtectionActivated: scannersProbesProtectionActivated,
      snsEmail: snsEmail,
    });

    //=============================================================================================
    // Rule
    //=============================================================================================
    // prettier-ignore
    new CfnRule(this, "HTTPFloodRuleCustomHeaderValidation", {//NOSONAR - skip sonar detection useless object instantiation
      ruleCondition: Fn.conditionEquals(
        parameters.wafRuleKeysType.valueAsString,
        WafRuleKeysType.IP_CUSTOM_HEADER,
      ),
      assertions: [
        {
          assert: Fn.conditionNot(
            Fn.conditionEquals(parameters.customHeaderName.valueAsString, ""),
          ),
          assertDescription:
            "CustomHeaderName is required when IP + Custom Header is selected",
        },
      ],
    });

    //=============================================================================================
    // Metrics Resources
    //=============================================================================================
    const retentionInDays = Fn.conditionIf(
      logGroupRetentionEnabled.logicalId,
      parameters.logGroupRetention.valueAsNumber,
      RetentionDays.ONE_YEAR,
    );

    // prettier-ignore
    new MetricsLambdaResources(this, "MetricsLambdaResources", {//NOSONAR - skip sonar detection useless object instantiation
      sourceCodeMapping: sourceCodeMapping,
      solutionMapping: solutionMapping,
      uuid: createUniqueID.getUUID(),
      metricNamePrefix: metricNamePrefix,
      waf_endpoint_type: parameters.endpointType.valueAsString,
      retentionInDays: Utils.safeNumberValue(
        retentionInDays,
        manifest.wafSecurityAutomations.logGroupRetention.default,
      ),
    });

    //=============================================================================================
    // Outputs
    //=============================================================================================
    const solutionVersionOutput = new CfnOutput(this, "SolutionVersionOutput", {
      description: "Solution Version Number",
      exportName: Fn.sub("${AWS::StackName}-SolutionVersion"),
      value: distVersion,
    });
    solutionVersionOutput.overrideLogicalId("SolutionVersion");

    const wafWebACLOutput = new CfnOutput(this, "WAFWebACLOutput", {
      description: "AWS WAF WebACL",
      exportName: Fn.sub("${AWS::StackName}-WAFWebACL"),
      value: Fn.getAtt(
        this.webAcl.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.WAFWebACL_OUTPUT,
      ).toString(),
    });
    wafWebACLOutput.overrideLogicalId("WAFWebACL");

    const wafWebACLArnOutput = new CfnOutput(this, "WAFWebACLArnOutput", {
      description: "AWS WAF WebACL Arn",
      exportName: Fn.sub("${AWS::StackName}-WAFWebACLArn"),
      value: Fn.getAtt(
        this.webAcl.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.WAFWebACLArn_OUTPUT,
      ).toString(),
    });
    wafWebACLArnOutput.overrideLogicalId("WAFWebACLArn");

    const wafLogBucketOutput = new CfnOutput(this, "WafLogBucketOutput", {
      exportName: Fn.sub("${AWS::StackName}-WafLogBucket"),
      value: wafLogBucket.getBucket().ref,
    });
    wafLogBucketOutput.overrideLogicalId("WafLogBucket");
    wafLogBucketOutput.condition = httpFloodProtectionLogParserActivated;
  }

  public getFirehoseAthenaNestedStack() {
    return this.firehoseAthenaNestedStack;
  }

  public getWebAclNestedStack() {
    return this.webAcl;
  }
}
