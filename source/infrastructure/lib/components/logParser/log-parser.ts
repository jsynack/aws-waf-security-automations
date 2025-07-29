// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { SolutionMapping } from "../../mappings/solution";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { LogsForPartition } from "../logsForPartition/logs-for-partition";
import { CustomResourceLambda } from "../customResource/custom-resource-lambda";
import { distVersion, manifest } from "../../constants/waf-constants";
import {
  CfnFunction,
  CfnPermission,
  IFunction,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { CreateUniqueID } from "../customs/create-unique-id";
import { ConfigureAppAccessLogBucket } from "../customs/custom-config-app-log-bucket";
import { CfnBucket } from "aws-cdk-lib/aws-s3";
import {
  Aws,
  CfnCondition,
  CfnParameter,
  CfnResource,
  CustomResource,
  Fn,
} from "aws-cdk-lib";
import { CfnRole } from "aws-cdk-lib/aws-iam";
import { CfnRule } from "aws-cdk-lib/aws-events";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";
import Utils from "../../mappings/utils";

export interface LogParserProps {
  badBotProtectionActivated: CfnCondition;
  badBotWafLogActivated: CfnCondition;
  badBotLambdaLogParserActivated: CfnCondition;
  httpFloodProtectionLogParserActivated: CfnCondition;
  httpFloodLambdaLogParser: CfnCondition;
  scannersProbesAthenaLogParser: CfnCondition;
  httpFloodProtectionActivated: CfnCondition;
  param: { [key: string]: CfnParameter };
  scannersProbesProtectionActivated: CfnCondition;
  scannersProbesLambdaLogParser: CfnCondition;
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  turnOnAppAccessLogBucketLogging: CfnCondition;
  httpFloodAthenaLogParser: CfnCondition;
  logParser: CfnCondition;
  albEndpoint: CfnCondition;
  isAthenaQueryRunEveryMinute: CfnCondition;
  badBotLambdaAccessLogActivated: CfnCondition;
  badBotAthenaWafLogActivated: CfnCondition;
  badBotAthenaAccessLogActivated: CfnCondition;
  customResource: CustomResourceLambda;
  logsForPartition: LogsForPartition;
  accessLoggingBucket: CfnBucket;
  wafLogBucket: CfnBucket;
  UUID: CreateUniqueID;
  moveS3LogsForPartition: IFunction;
  metricNamePrefix: string;
  webACLStack: WebaclNestedstack;
}

export class LogParser extends Construct {
  public static readonly ID_CONF = "GenerateAppLogParserConfFile";
  public static readonly ID_WAF_CONF = "GenerateWafLogParserConfFile";
  public static readonly ID_LAMBDA_PARSER = "LambdaAthenaAppLogParser";
  public static readonly ID_WAF_LAMBDA_PARSER = "LambdaAthenaWAFLogParser";
  public static readonly ID = "LogParser";

  private readonly logParserFunction: CfnFunction;

  constructor(scope: Construct, id: string, props: LogParserProps) {
    super(scope, id);

    const lambdaRoleLogParser = new CfnRole(this, "LambdaRoleLogParser", {
      assumeRolePolicyDocument: {
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: ["lambda.amazonaws.com"],
            },
            Action: ["sts:AssumeRole"],
          },
        ],
      },
      path: "/",
      policies: [
        Fn.conditionIf(
          props.badBotProtectionActivated.logicalId,
          {
            PolicyName: "WAFGetAndUpdateIPSet",
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                  Resource: [
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." + WebaclNestedstack.WAFBadBotSetV4Arn_OUTPUT,
                    ),
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." + WebaclNestedstack.WAFBadBotSetV6Arn_OUTPUT,
                    ),
                  ],
                },
              ],
            },
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          {
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "s3:GetObject",
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: "s3:PutObject",
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/${AWS::StackName}-app_log_out.json",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/${AWS::StackName}-app_log_conf.json",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                  Resource: [
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFScannersProbesSetV4Arn_OUTPUT,
                    ),
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFScannersProbesSetV6Arn_OUTPUT,
                    ),
                  ],
                },
              ],
            },
            PolicyName: "ScannersProbesProtectionActivatedAccess",
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.scannersProbesAthenaLogParser.logicalId,
          {
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: [
                    "athena:GetNamedQuery",
                    "athena:StartQueryExecution",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:athena:${AWS::Region}:${AWS::AccountId}:workgroup/WAF*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                    "s3:PutObject",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${AppAccessLogBucket}/athena_results/*",
                    ),
                    Fn.sub("arn:${AWS::Partition}:s3:::${AppAccessLogBucket}"),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["glue:GetTable", "glue:GetPartitions"],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${WebACLStack.Outputs.GlueAccessLogsDatabase}",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/${WebACLStack.Outputs.GlueAccessLogsDatabase}/${WebACLStack.Outputs.GlueAppAccessLogsTable}",
                    ),
                  ],
                },
              ],
            },
            PolicyName: "ScannersProbesAthenaLogParserAccess",
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.httpFloodProtectionLogParserActivated.logicalId,
          {
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "s3:GetObject",
                  Resource: [
                    Fn.sub("arn:${AWS::Partition}:s3:::${WafLogBucket}/*"),
                  ],
                },
              ],
            },
            PolicyName: "HttpFloodProtectionLogParserActivatedAccess",
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.httpFloodProtectionActivated.logicalId,
          {
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "s3:PutObject",
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${WafLogBucket}/${AWS::StackName}-waf_log_out.json",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${WafLogBucket}/${AWS::StackName}-waf_log_conf.json",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                  Resource: [
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFHttpFloodSetV4Arn_OUTPUT,
                    ),
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFHttpFloodSetV6Arn_OUTPUT,
                    ),
                  ],
                },
              ],
            },
            PolicyName: "HttpFloodProtectionActivated",
          },
          Aws.NO_VALUE,
        ),
        Fn.conditionIf(
          props.httpFloodAthenaLogParser.logicalId,
          {
            PolicyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: [
                    "athena:GetNamedQuery",
                    "athena:StartQueryExecution",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:athena:${AWS::Region}:${AWS::AccountId}:workgroup/WAF*",
                    ),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                    "s3:PutObject",
                  ],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:s3:::${WafLogBucket}/athena_results/*",
                    ),
                    Fn.sub("arn:${AWS::Partition}:s3:::${WafLogBucket}"),
                  ],
                },
                {
                  Effect: "Allow",
                  Action: ["glue:GetTable", "glue:GetPartitions"],
                  Resource: [
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${WebACLStack.Outputs.GlueAccessLogsDatabase}",
                    ),
                    Fn.sub(
                      "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/${WebACLStack.Outputs.GlueAccessLogsDatabase}/${WebACLStack.Outputs.GlueWafAccessLogsTable}",
                    ),
                  ],
                },
              ],
            },
            PolicyName: "HttpFloodAthenaLogParserAccess",
          },
          Aws.NO_VALUE,
        ),
        {
          policyName: "LogsAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents",
                ],
                Resource: [
                  Fn.sub(
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*LogParser*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "CloudWatchAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: "cloudwatch:GetMetricStatistics",
                Resource: [
                  Fn.sub(
                    "arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:metric/*",
                  ),
                ],
              },
            ],
          },
        },
        {
          policyName: "XRayAccess",
          policyDocument: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                Resource: ["*"],
              },
            ],
          },
        },
      ],
    });

    lambdaRoleLogParser.overrideLogicalId("LambdaRoleLogParser");
    lambdaRoleLogParser.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "LogsAccess - permission restricted to account, region and log group name substring (LogParser); CloudWatchAccess - this actions does not support resource-level permissions",
          },
        ],
      },
    };
    lambdaRoleLogParser.cfnOptions.condition = props.logParser;
    lambdaRoleLogParser.addOverride("DependsOn", WebaclNestedstack.ID);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "log_parser.zip",
    ]);

    this.logParserFunction = new CfnFunction(this, LogParser.ID, {
      description:
        "This function parses access logs to identify suspicious behavior, such as an abnormal amount of errors. It then blocks those IP addresses for a customer-defined period of time.",
      handler: "log_parser.lambda_handler",
      role: lambdaRoleLogParser?.attrArn as string,
      code: {
        s3Bucket: s3Bucket,
        s3Key: s3Key,
      },
      environment: {
        variables: {
          BAD_BOT_LAMBDA_WAF_ENABLED: Fn.conditionIf(
            props.badBotWafLogActivated.logicalId,
            "true",
            "false",
          ).toString(),
          BAD_BOT_LAMBDA_ACCESS_LOG_ENABLED: Fn.conditionIf(
            props.badBotLambdaAccessLogActivated.logicalId,
            "true",
            "false",
          ).toString(),
          BAD_BOT_ATHENA_WAF_ENABLED: Fn.conditionIf(
            props.badBotAthenaWafLogActivated.logicalId,
            "true",
            "false",
          ).toString(),
          BAD_BOT_ATHENA_ACCESS_LOG_ENABLED: Fn.conditionIf(
            props.badBotAthenaAccessLogActivated.logicalId,
            "true",
            "false",
          ).toString(),
          BAD_BOT_LOG_PARSER: Fn.conditionIf(
            props.badBotLambdaLogParserActivated.logicalId,
            "true",
            "false",
          ).toString(),
          APP_ACCESS_LOG_BUCKET: Fn.conditionIf(
            props.scannersProbesProtectionActivated.logicalId,
            props.param.appAccessLogBucket.valueAsString,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          WAF_ACCESS_LOG_BUCKET: Fn.conditionIf(
            props.httpFloodProtectionLogParserActivated.logicalId,
            props.wafLogBucket.ref,
            Fn.ref("AWS::NoValue"),
          ).toString(),
          SEND_ANONYMIZED_USAGE_DATA: props.solutionMapping.findInMap(
            "Data",
            "SendAnonymizedUsageData",
          ),
          UUID: props.UUID.getUUID(),
          LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION:
            manifest.wafSecurityAutomations.limitIpAddressRangesPerIp,
          MAX_AGE_TO_UPDATE: "30",
          REGION: Aws.REGION,
          SCOPE: Utils.getRegionScope(props.albEndpoint.logicalId),
          LOG_TYPE: Utils.getLogType(props.albEndpoint.logicalId),
          METRIC_NAME_PREFIX: props.metricNamePrefix,
          LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
          STACK_NAME: Aws.STACK_NAME,
          IP_SET_ID_HTTP_FLOODV4: Fn.conditionIf(
            props.httpFloodProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFHttpFloodSetV4Arn_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_ID_HTTP_FLOODV6: Fn.conditionIf(
            props.httpFloodProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFHttpFloodSetV6Arn_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_HTTP_FLOODV4: Fn.conditionIf(
            props.httpFloodProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameHttpFloodSetV4_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_HTTP_FLOODV6: Fn.conditionIf(
            props.httpFloodProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameHttpFloodSetV6_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_ID_SCANNERS_PROBESV4: Fn.conditionIf(
            props.scannersProbesProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFScannersProbesSetV4Arn_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_ID_SCANNERS_PROBESV6: Fn.conditionIf(
            props.scannersProbesProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFScannersProbesSetV6Arn_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_SCANNERS_PROBESV4: Fn.conditionIf(
            props.scannersProbesProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameScannersProbesSetV4_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_SCANNERS_PROBESV6: Fn.conditionIf(
            props.scannersProbesProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameScannersProbesSetV6_OUTPUT,
            ),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_ID_BAD_BOTV4: Fn.conditionIf(
            props.badBotProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFBadBotSetV4Arn_OUTPUT,
            ).toString(),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_ID_BAD_BOTV6: Fn.conditionIf(
            props.badBotProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFBadBotSetV6Arn_OUTPUT,
            ).toString(),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_BAD_BOTV4: Fn.conditionIf(
            props.badBotProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameBadBotSetV4_OUTPUT,
            ).toString(),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          IP_SET_NAME_BAD_BOTV6: Fn.conditionIf(
            props.badBotProtectionActivated.logicalId,
            Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameBadBotSetV6_OUTPUT,
            ).toString(),
            Fn.ref("AWS::NoValue"),
          ).toString(),
          WAF_BLOCK_PERIOD: props.param.wafBlockPeriod.valueAsString,
          ERROR_THRESHOLD: props.param.errorThreshold.valueAsString,
          REQUEST_THRESHOLD: props.param.requestThreshold.valueAsString,
          REQUEST_THRESHOLD_BY_COUNTRY:
            props.param.requestThresholdByCountry.valueAsString,
          HTTP_FLOOD_ATHENA_GROUP_BY:
            props.param.httpFloodAthenaQueryGroupBy.valueAsString,
          ATHENA_QUERY_RUN_SCHEDULE:
            props.param.athenaQueryRunTimeSchedule.valueAsString,
          SOLUTION_ID: props.solutionMapping.findInMap("Data", "SolutionID"),
          METRICS_URL: props.solutionMapping.findInMap("Data", "MetricsURL"),
          USER_AGENT_EXTRA: props.solutionMapping.findInMap(
            "UserAgent",
            "UserAgentExtra",
          ),
          BAD_BOT_URLS:
            manifest.wafSecurityAutomations.batBot.prodStageName +
            "|" +
            manifest.wafSecurityAutomations.batBot.stageName,
          SOLUTION_VERSION: distVersion,
          POWERTOOLS_SERVICE_NAME: LogParser.ID,
        },
      },
      runtime: "python3.12",
      memorySize: 512,
      timeout: 300,
      tracingConfig: {
        mode: Tracing.ACTIVE,
      },
    });

    this.logParserFunction.cfnOptions.condition = props.logParser;
    this.logParserFunction.overrideLogicalId(LogParser.ID);
    this.logParserFunction.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W58",
            reason:
              "Log permissions are defined in the LambdaRoleLogParser policies",
          },
        ],
      },
    };

    const configureAppAccessLogBucket = new ConfigureAppAccessLogBucket(
      this,
      ConfigureAppAccessLogBucket.ID,
      {
        scannersProbesProtectionActivated:
          props.scannersProbesProtectionActivated,
        scannersProbesLambdaLogParser: props.scannersProbesLambdaLogParser,
        scannersProbesAthenaLogParser: props.scannersProbesAthenaLogParser,
        appAccessLogBucket: props.param.appAccessLogBucket,
        appAccessLogBucketPrefix: props.param.appAccessLogBucketPrefix,
        helperFunction: props.customResource.getFunction(),
        logParserFunction: this.logParserFunction,
        logsForPartition: props.logsForPartition.getLambdaFunction(),
        moveS3LogsForPartition: props.moveS3LogsForPartition,
        accessLoggingBucket: props.accessLoggingBucket,
        turnOnAppAccessLogBucketLogging: props.turnOnAppAccessLogBucketLogging,
      },
    );

    const scheduleExpression = Fn.conditionIf(
      props.isAthenaQueryRunEveryMinute.logicalId,
      "rate(1 minute)",
      Fn.join("", [
        "rate(",
        Fn.ref(`${props.param.athenaQueryRunTimeSchedule.logicalId}`),
        " minutes)",
      ]),
    ).toString();

    const logParserInput = Fn.sub(
      `{
  "resourceType": "LambdaAthenaAppLogParser",
  "glueAccessLogsDatabase": "\${FirehoseAthenaStack.Outputs.GlueAccessLogsDatabase}",
  "accessLogBucket": "\${AppAccessLogBucket}",
  "glueAppAccessLogsTable": "\${FirehoseAthenaStack.Outputs.GlueAppAccessLogsTable}",
  "athenaWorkGroup": "\${FirehoseAthenaStack.Outputs.WAFAppAccessLogAthenaQueryWorkGroup}"
}
`,
    );

    const lambdaAthenaAppLogParser = new CfnRule(
      this,
      LogParser.ID_LAMBDA_PARSER,
      {
        description: "Security Automation - App Logs Athena parser",
        scheduleExpression: scheduleExpression,
        targets: [
          {
            arn: this.logParserFunction.attrArn,
            id: LogParser.ID,
            input: logParserInput,
          },
        ],
      },
    );
    lambdaAthenaAppLogParser.overrideLogicalId(LogParser.ID_LAMBDA_PARSER);
    lambdaAthenaAppLogParser.cfnOptions.condition =
      props.scannersProbesAthenaLogParser;

    const wafLogParserInput = Fn.sub(
      `{
  "resourceType": "LambdaAthenaWAFLogParser",
  "glueAccessLogsDatabase": "\${FirehoseAthenaStack.Outputs.GlueAccessLogsDatabase}",
  "accessLogBucket": "\${WafLogBucket}",
  "glueWafAccessLogsTable": "\${FirehoseAthenaStack.Outputs.GlueWafAccessLogsTable}",
  "athenaWorkGroup":"\${FirehoseAthenaStack.Outputs.WAFLogAthenaQueryWorkGroup}"
}
`,
    );
    const lambdaAthenaWafLogParser = new CfnRule(
      this,
      LogParser.ID_WAF_LAMBDA_PARSER,
      {
        description: "Security Automation - WAF Logs Athena parser",
        scheduleExpression: scheduleExpression,
        targets: [
          {
            arn: this.logParserFunction.attrArn,
            id: LogParser.ID,
            input: wafLogParserInput,
          },
        ],
      },
    );
    lambdaAthenaWafLogParser.overrideLogicalId(LogParser.ID_WAF_LAMBDA_PARSER);
    lambdaAthenaWafLogParser.cfnOptions.condition =
      props.httpFloodAthenaLogParser;

    const lambdaInvokePermissionAppLogParserS3 = new CfnPermission(
      this,
      "LambdaInvokePermissionAppLogParserS3",
      {
        functionName: this.logParserFunction.attrArn,
        action: "lambda:InvokeFunction",
        principal: "s3.amazonaws.com",
        sourceAccount: Aws.ACCOUNT_ID,
      },
    );
    lambdaInvokePermissionAppLogParserS3.overrideLogicalId(
      "LambdaInvokePermissionAppLogParserS3",
    );
    lambdaInvokePermissionAppLogParserS3.cfnOptions.condition = props.logParser;

    const lambdaInvokePermissionAppLogParserCloudWatch = new CfnPermission(
      this,
      "LambdaInvokePermissionAppLogParserCloudWatch",
      {
        functionName: this.logParserFunction.ref,
        action: "lambda:InvokeFunction",
        principal: "events.amazonaws.com",
        sourceArn: lambdaAthenaAppLogParser?.attrArn,
      },
    );
    lambdaInvokePermissionAppLogParserCloudWatch.overrideLogicalId(
      "LambdaInvokePermissionAppLogParserCloudWatch",
    );
    lambdaInvokePermissionAppLogParserCloudWatch.cfnOptions.condition =
      props.scannersProbesAthenaLogParser;

    const lambdaInvokePermissionWafLogParserCloudWatch = new CfnPermission(
      this,
      "LambdaInvokePermissionWafLogParserCloudWatch",
      {
        functionName: this.logParserFunction.ref,
        action: "lambda:InvokeFunction",
        principal: "events.amazonaws.com",
        sourceArn: lambdaAthenaWafLogParser?.attrArn,
      },
    );

    lambdaInvokePermissionWafLogParserCloudWatch.overrideLogicalId(
      "LambdaInvokePermissionWafLogParserCloudWatch",
    );
    lambdaInvokePermissionWafLogParserCloudWatch.cfnOptions.condition =
      props.httpFloodAthenaLogParser;

    const generateWafLogParserConfFile = new CustomResource(
      this,
      LogParser.ID_WAF_CONF,
      {
        serviceToken: props.customResource.getFunction().functionArn,
        resourceType: "Custom::" + LogParser.ID_WAF_CONF,
        properties: {
          StackName: Fn.ref("AWS::StackName"),
          WafAccessLogBucket: props.wafLogBucket.ref,
          RequestThreshold: props.param.requestThreshold,
          WAFBlockPeriod: props.param.wafBlockPeriod,
        },
      },
    );
    const generateWafLogParserConfFileCustomResource =
      generateWafLogParserConfFile.node.defaultChild as CfnResource;
    generateWafLogParserConfFileCustomResource.overrideLogicalId(
      LogParser.ID_WAF_CONF,
    );
    generateWafLogParserConfFileCustomResource.cfnOptions.condition =
      props.httpFloodLambdaLogParser;
    generateWafLogParserConfFileCustomResource.addOverride(
      "DeletionPolicy",
      undefined,
    );
    generateWafLogParserConfFileCustomResource.addOverride(
      "UpdateReplacePolicy",
      undefined,
    );

    const generateAppLogParserConfFile = new CustomResource(
      this,
      LogParser.ID_CONF,
      {
        serviceToken: props.customResource.getFunction().functionArn,
        resourceType: "Custom::" + LogParser.ID_CONF,
        properties: {
          StackName: Fn.ref("AWS::StackName"),
          AppAccessLogBucket: props.param.appAccessLogBucket,
          ErrorThreshold: props.param.errorThreshold,
          WAFBlockPeriod: props.param.wafBlockPeriod,
        },
      },
    );
    const generateAppLogParserConfFileCustomResource =
      generateAppLogParserConfFile.node.defaultChild as CfnResource;
    generateAppLogParserConfFileCustomResource.overrideLogicalId(
      LogParser.ID_CONF,
    );
    generateAppLogParserConfFileCustomResource.cfnOptions.condition =
      props.scannersProbesLambdaLogParser;
    generateAppLogParserConfFileCustomResource.addOverride(
      "DeletionPolicy",
      undefined,
    );
    generateAppLogParserConfFileCustomResource.addOverride(
      "UpdateReplacePolicy",
      undefined,
    );
    generateAppLogParserConfFileCustomResource.addOverride(
      "DependsOn",
      configureAppAccessLogBucket.node.id,
    );
  }

  public getLambdaFunction(): CfnFunction {
    return this.logParserFunction;
  }
}
