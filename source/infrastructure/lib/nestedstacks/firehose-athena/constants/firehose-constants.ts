// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  manifest,
  distVersion,
  solutionId,
} from "../../../constants/waf-constants";

export const firehoseAthenaManifest = {
  firehoseAthena: {
    description: `(${solutionId}-FA) - Security Automations for AWS WAF - FA: This AWS CloudFormation template helps you provision the Security Automations for AWS WAF stack without worrying about creating and configuring the underlying AWS infrastructure. **WARNING** This template creates an AWS Lambda function, an AWS WAF Web ACL, an Amazon S3 bucket, and an Amazon CloudWatch custom metric. You will be billed for the AWS resources used if you create a stack from this template. ${distVersion}`,
  },
  ...manifest,
};
