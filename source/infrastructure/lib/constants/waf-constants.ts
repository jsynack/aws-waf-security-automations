// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const solutionId = process.env["SOLUTION_ID"] || "SO0006";
export const distVersion = process.env["VERSION"] || "%%VERSION%%";
export const templateOutputBucket =
  process.env["TEMPLATE_OUTPUT_BUCKET"] || "%%TEMPLATE_OUTPUT_BUCKET%%";
export const distOutputBucket =
  process.env["DIST_OUTPUT_BUCKET"] || "%%DIST_OUTPUT_BUCKET%%";
export const solutionName = process.env["SOLUTION_NAME"] || "%%SOLUTION_NAME%%";

export const manifest = {
  awsTemplateFormatVersion: "2010-09-09",
  solutionName: "WAF Security Automations",
  badBotVersion: "2012-10-17",
  ipSnsVersion: "2012-10-17",
  wafSecurityAutomations: {
    description: `(${solutionId}) - Security Automations for AWS WAF: This AWS CloudFormation template helps you provision the Security Automations for AWS WAF stack without worrying about creating and configuring the underlying AWS infrastructure. **WARNING** This template creates multiple AWS Lambda functions, an AWS WAFv2 Web ACL, an Amazon S3 bucket, and an Amazon CloudWatch custom metric. You will be billed for the AWS resources used if you create a stack from this template. ${distVersion}`,
    metricsURL: "https://metrics.awssolutionsbuilder.com/generic",
    firehoseAthenaTemplateId: "aws-waf-security-automations-firehose-athena",
    webaclTemplateId: "aws-waf-security-automations-webacl",
    logGroupRetention: {
      default: 365,
    },
    appAccessLogBucket: {
      patter:
        "(^$|^([a-z]|(\\d(?!\\d{0,2}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})))([a-z\\d]|(\\.(?!(\\.|-)))|(-(?!\\.))){1,61}[a-z\\d]$)",
    },
    requestThresholdByCountry: {
      patter: '^$|^\\{"\\w+":\\d+([,]"\\w+":\\d+)*\\}+$',
    },
    snsEmail: {
      patter: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$|^$",
    },
    customHeaderName: {
      patter: "(^$)|.*\\S.*",
    },
    firehoseWAFLogs: {
      timeWindowThresholdSeconds: 300,
    },
    batBot: {
      prodStageName: "ProdStage",
      stageName: "CFDeploymentStage",
      ruleLabel: "badbot",
    },
    //https://docs.aws.amazon.com/waf/latest/developerguide/limits.html | Maximum number of unique IP addresses that can be rate limited per rate-based rule
    limitIpAddressRangesPerIp: "10000",
  },
};

export enum WafRuleKeysType {
  IP = "IP",
  IP_CUSTOM_HEADER = "IP+Custom Header",
  IP_URI = "IP+URI",
  IP_HTTP_METHOD = "IP+HTTP METHOD",
}

export enum WafAggregateKeyType {
  IP = "IP",
  CUSTOM_KEYS = "CUSTOM_KEYS",
}
