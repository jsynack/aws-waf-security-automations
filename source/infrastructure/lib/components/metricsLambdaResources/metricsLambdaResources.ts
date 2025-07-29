// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { StackProps, Duration, RemovalPolicy, Aws, Fn } from "aws-cdk-lib";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as logs from "aws-cdk-lib/aws-logs";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { SolutionMapping } from "../../mappings/solution";
import { distVersion, solutionName } from "../../constants/waf-constants";
import { Code } from "aws-cdk-lib/aws-lambda";
import { Bucket } from "aws-cdk-lib/aws-s3";

export interface MetricsLambdaProps extends StackProps {
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  uuid: string;
  metricNamePrefix: string;
  retentionInDays: number;
  waf_endpoint_type: string;
}

export class MetricsLambdaResources extends Construct {
  constructor(scope: Construct, id: string, props: MetricsLambdaProps) {
    super(scope, id);

    const metricsLambdaRole = new iam.Role(this, "LambdaExecutionRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "Custom role for Lambda to query CloudWatch metrics",
    });

    metricsLambdaRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
        resources: ["*"],
      }),
    );
    metricsLambdaRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [
          Fn.sub(
            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/*MetricsLambdaResources*",
          ),
        ],
      }),
    );
    const deploymentSourceBucket = Bucket.fromBucketAttributes(
      this,
      "SolutionRegionalBucket",
      {
        bucketName:
          props.sourceCodeMapping.findInMap("General", "SourceBucket") +
          "-" +
          Aws.REGION,
      },
    );

    const metricsFunction = new lambda.Function(this, "MetricsFunction", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "metrics.handler",
      code: Code.fromBucket(
        deploymentSourceBucket,
        `${solutionName}/${distVersion}/metrics.zip`,
      ),
      timeout: Duration.seconds(300),
      memorySize: 256,
      role: metricsLambdaRole,
      tracing: lambda.Tracing.ACTIVE,
      environment: {
        SOLUTION_ID: props.solutionMapping.findInMap("Data", "SolutionID"),
        SOLUTION_VERSION: props.solutionMapping.findInMap(
          "Data",
          "SolutionVersion",
        ),
        SOLUTION_NAME: props.solutionMapping.findInMap("Data", "SolutionName"),
        SOLUTION_BUCKET: props.solutionMapping.findInMap(
          "Data",
          "DistOutputBucket",
        ),
        UUID: props.uuid,
        REGION: Aws.REGION,
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        STACK_NAME: Aws.STACK_NAME,
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        POWERTOOLS_SERVICE_NAME: "Metrics",
        METRICS_NAME_PREFIX: props.metricNamePrefix,
        WEB_ACL_NAME: Aws.STACK_NAME,
        LOG_GROUP_RETENTION: props.retentionInDays.toString(),
        SEND_ANONYMIZED_USAGE_DATA: props.solutionMapping.findInMap(
          "Data",
          "SendAnonymizedUsageData",
        ),
        METRICS_FREQUENCY_HOURS: props.solutionMapping.findInMap(
          "Data",
          "MetricsFrequencyHours",
        ),
        METRICS_URL: props.solutionMapping.findInMap("Data", "MetricsURL"),
        WAF_ENDPOINT_TYPE: props.waf_endpoint_type,
        RULE_NAMES: `
        ${props.solutionMapping.findInMap("WAFRuleNames", "BadBotRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "HttpFloodRateBasedRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "HttpFloodRegularRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "ScannersProbesRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "IPReputationListsRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "SqlInjectionRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "XssRule")},
        ${props.solutionMapping.findInMap("WAFRuleNames", "BlacklistRule")}
        `,
      },
    });

    // prettier-ignore
    new logs.LogGroup(this, "LambdaLogGroup", {//NOSONAR - skip sonar detection useless object instantiation
      logGroupName: `/aws/lambda/${metricsFunction.functionName}`,
      retention: props.retentionInDays,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // prettier-ignore
    new events.Rule(this, "ScheduleRule", {//NOSONAR - skip sonar detection useless object instantiation
      schedule: events.Schedule.rate(Duration.hours(24)),
      targets: [new targets.LambdaFunction(metricsFunction)],
    });
  }
}
