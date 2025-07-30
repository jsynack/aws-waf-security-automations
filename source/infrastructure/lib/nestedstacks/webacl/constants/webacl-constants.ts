// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  manifest,
  distVersion,
  solutionId,
} from "../../../constants/waf-constants";

export const webaclManifest = {
  webacl: {
    description: `(${solutionId}-WebACL) - Security Automations for AWS WAF: This AWS CloudFormation template helps you provision the Security Automations for AWS WAF stack without worrying about creating and configuring the underlying AWS infrastructure. **WARNING** This template creates an AWS WAF Web ACL and Amazon CloudWatch custom metrics. You will be billed for the AWS resources used if you create a stack from this template. ${distVersion}`,
  },
  ...manifest,
};
