// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { SolutionMapping } from "../../mappings/solution";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { CreateUniqueID } from "../customs/create-unique-id";
import { CfnRole } from "aws-cdk-lib/aws-iam";
import {
  Aws,
  CfnCondition,
  CfnResource,
  CustomResource,
  Fn,
} from "aws-cdk-lib";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";
import { CfnFunction, CfnPermission, Tracing } from "aws-cdk-lib/aws-lambda";
import { CfnRule } from "aws-cdk-lib/aws-events";
import Utils from "../../mappings/utils";

export interface ReputationListProps {
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  albEndpoint: CfnCondition;
  version: string;
  reputationListsProtectionActivated: CfnCondition;
  UUID: CreateUniqueID;
  webACLStack: WebaclNestedstack;
}

export class ReputationList extends Construct {
  public static readonly ID_PARSER = "LambdaRoleReputationListsParser";

  private readonly reputationListsParser: CfnFunction | undefined;

  constructor(scope: Construct, id: string, props: ReputationListProps) {
    super(scope, id);

    const lambdaRoleReputationListsParser = new CfnRole(
      this,
      ReputationList.ID_PARSER,
      {
        assumeRolePolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Service: ["lambda.amazonaws.com"],
              },
              Action: "sts:AssumeRole",
            },
          ],
        },
        policies: [
          {
            policyName: "CloudWatchLogs",
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
                      "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*ReputationListsParser*",
                    ),
                  ],
                },
              ],
            },
          },
          {
            policyName: "WAFGetAndUpdateIPSet",
            policyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                  Resource: [
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFReputationListsSetV4Arn_OUTPUT,
                    ),
                    Fn.getAtt(
                      props.webACLStack.nestedStackResource!.logicalId,
                      "Outputs." +
                        WebaclNestedstack.WAFReputationListsSetV6Arn_OUTPUT,
                    ),
                  ],
                },
              ],
            },
          },
          {
            policyName: "CloudFormationAccess",
            policyDocument: {
              Statement: [
                {
                  Effect: "Allow",
                  Action: "cloudformation:DescribeStacks",
                  Resource: [
                    {
                      "Fn::Sub":
                        "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*",
                    },
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
      },
    );
    lambdaRoleReputationListsParser.overrideLogicalId(ReputationList.ID_PARSER);
    lambdaRoleReputationListsParser.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W11",
            reason:
              "CloudWatchLogs - permission restricted to account, region and log group name substring (ReputationListsParser); CloudFormationAccess - account, region and stack name; CloudWatchAccess - this actions does not support resource-level permissions",
          },
        ],
      },
    };
    lambdaRoleReputationListsParser.cfnOptions.condition =
      props.reputationListsProtectionActivated;

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "reputation_lists_parser.zip",
    ]);

    this.reputationListsParser = new CfnFunction(
      this,
      "ReputationListsParser",
      {
        description:
          "This lambda function checks third-party IP reputation lists hourly for new IP ranges to block. These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list.",
        handler: "reputation_lists.lambda_handler",
        role: lambdaRoleReputationListsParser?.attrArn as string,
        code: {
          s3Bucket: s3Bucket,
          s3Key: s3Key,
        },
        runtime: "python3.12",
        memorySize: 512,
        timeout: 300,
        environment: {
          variables: {
            IP_SET_ID_REPUTATIONV4: Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFReputationListsSetV4Arn_OUTPUT,
            ).toString(),
            IP_SET_ID_REPUTATIONV6: Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.WAFReputationListsSetV6Arn_OUTPUT,
            ).toString(),
            IP_SET_NAME_REPUTATIONV4: Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameReputationListsSetV4_OUTPUT,
            ).toString(),
            IP_SET_NAME_REPUTATIONV6: Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.NameReputationListsSetV6_OUTPUT,
            ).toString(),
            SCOPE: Utils.getRegionScope(props.albEndpoint.logicalId),
            LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
            URL_LIST:
              '[{"url":"https://www.spamhaus.org/drop/drop.txt"},{"url":"https://www.spamhaus.org/drop/edrop.txt"},{"url":"https://check.torproject.org/exit-addresses", "prefix":"ExitAddress"},{"url":"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"}]',
            SOLUTION_ID: props.solutionMapping.findInMap("Data", "SolutionID"),
            METRICS_URL: props.solutionMapping.findInMap("Data", "MetricsURL"),
            STACK_NAME: Aws.STACK_NAME,
            LOG_TYPE: Utils.getLogType(props.albEndpoint.logicalId),
            SEND_ANONYMIZED_USAGE_DATA: props.solutionMapping.findInMap(
              "Data",
              "SendAnonymizedUsageData",
            ),
            IPREPUTATIONLIST_METRICNAME: Fn.getAtt(
              props.webACLStack.nestedStackResource!.logicalId,
              "Outputs." + WebaclNestedstack.IPReputationListsMetricName_OUTPUT,
            ).toString(),
            USER_AGENT_EXTRA: props.solutionMapping.findInMap(
              "UserAgent",
              "UserAgentExtra",
            ),
            UUID: props.UUID.getUUID(),
            SOLUTION_VERSION: props.version,
            POWERTOOLS_SERVICE_NAME: "ReputationListsParser",
          },
        },
        tracingConfig: {
          mode: Tracing.ACTIVE,
        },
      },
    );
    this.reputationListsParser.cfnOptions.condition =
      props.reputationListsProtectionActivated;
    this.reputationListsParser.overrideLogicalId("ReputationListsParser");
    this.reputationListsParser.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W58",
            reason:
              "Log permissions are defined in the LambdaRoleReputationListsParser policies",
          },
        ],
      },
    };

    const urlList =
      "{\n" +
      '                "URL_LIST": [\n' +
      '                  {"url":"https://www.spamhaus.org/drop/drop.txt"},\n' +
      '                  {"url":"https://www.spamhaus.org/drop/edrop.txt"},\n' +
      '                  {"url":"https://check.torproject.org/exit-addresses", "prefix":"ExitAddress"},\n' +
      '                  {"url":"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"}\n' +
      "                ],\n" +
      '                "IP_SET_ID_REPUTATIONV4": "${IP_SET_ID_REPUTATIONV4}",\n' +
      '                "IP_SET_ID_REPUTATIONV6": "${IP_SET_ID_REPUTATIONV6}",\n' +
      '                "IP_SET_NAME_REPUTATIONV4": "${IP_SET_NAME_REPUTATIONV4}",\n' +
      '                "IP_SET_NAME_REPUTATIONV6": "${IP_SET_NAME_REPUTATIONV6}",\n' +
      '                "SCOPE": "${SCOPE}"\n' +
      "              }";

    const configJson = Fn.sub(urlList, {
      IP_SET_ID_REPUTATIONV4: Fn.getAtt(
        props.webACLStack.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.WAFReputationListsSetV4Arn_OUTPUT,
      ).toString(),
      IP_SET_ID_REPUTATIONV6: Fn.getAtt(
        props.webACLStack.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.WAFReputationListsSetV6Arn_OUTPUT,
      ).toString(),
      IP_SET_NAME_REPUTATIONV4: Fn.getAtt(
        props.webACLStack.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.NameReputationListsSetV4_OUTPUT,
      ).toString(),
      IP_SET_NAME_REPUTATIONV6: Fn.getAtt(
        props.webACLStack.nestedStackResource!.logicalId,
        "Outputs." + WebaclNestedstack.NameReputationListsSetV6_OUTPUT,
      ).toString(),
      SCOPE: "CLOUDFRONT",
    });

    const reputationListsParserEventsRule = new CfnRule(
      this,
      "ReputationListsParserEventsRule",
      {
        description: "Security Automation - WAF Reputation Lists",
        scheduleExpression: "rate(1 hour)",
        targets: [
          {
            arn: this.reputationListsParser?.attrArn as string,
            id: "ReputationListsParser",
            input: configJson,
          },
        ],
      },
    );
    reputationListsParserEventsRule.overrideLogicalId(
      "ReputationListsParserEventsRule",
    );
    reputationListsParserEventsRule.cfnOptions.condition =
      props.reputationListsProtectionActivated;

    const lambdaInvokePermissionReputationListsParse = new CfnPermission(
      this,
      "LambdaInvokePermissionReputationListsParser",
      {
        functionName: this.reputationListsParser?.ref as string,
        action: "lambda:InvokeFunction",
        principal: "events.amazonaws.com",
        sourceArn: reputationListsParserEventsRule?.attrArn,
      },
    );

    lambdaInvokePermissionReputationListsParse.overrideLogicalId(
      "LambdaInvokePermissionReputationListsParser",
    );
    lambdaInvokePermissionReputationListsParse.cfnOptions.condition =
      props.reputationListsProtectionActivated;

    const updateReputationLists = new CustomResource(
      this,
      "UpdateReputationListsOnLoad",
      {
        serviceToken: this.reputationListsParser?.attrArn as string,
        resourceType: "Custom::UpdateReputationLists",
        properties: {},
      },
    );

    const updateReputationListsCfnResource = updateReputationLists.node
      .defaultChild as CfnResource;
    updateReputationListsCfnResource.overrideLogicalId(
      "UpdateReputationListsOnLoad",
    );
    updateReputationListsCfnResource.addOverride(
      "DependsOn",
      WebaclNestedstack.ID,
    );
    updateReputationListsCfnResource.cfnOptions.condition =
      props.reputationListsProtectionActivated;
    updateReputationListsCfnResource.addOverride("DeletionPolicy", undefined);
    updateReputationListsCfnResource.addOverride(
      "UpdateReplacePolicy",
      undefined,
    );
  }

  public getFunction() {
    return this.reputationListsParser;
  }
}
