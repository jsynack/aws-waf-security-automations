// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { App, Aspects, DefaultStackSynthesizer } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { AwsWafSecurityAutomationsStack } from "../lib/aws-waf-security-automations-stack";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { CfnGuardSuppressResourceList } from "../lib/utils/appUtils";

jest.mock("../../infrastructure/lib/constants/waf-constants", () => {
  const actual = jest.requireActual(
    "../../infrastructure/lib/constants/waf-constants",
  ); // Import the actual module
  return {
    ...actual,
    distVersion: "v4.1.0",
    templateOutputBucket: "solutions-reference",
    distOutputBucket: "solutions",
    solutionName: "security-automations-for-aws-waf",
  };
});

describe("WAF firehose-athena end-to-end", () => {
  let oldTemplate: any;
  let newTemplate: any;

  beforeAll(() => {
    const oldTemplateJson = readFileSync(
      path.join(
        __dirname + "/test_data",
        "aws-waf-security-automations-firehose-athena.template",
      ),
      "utf8",
    );
    oldTemplate = JSON.parse(oldTemplateJson);

    // Create a new CDK stack
    const app = new App();

    const stack = new AwsWafSecurityAutomationsStack(
      app,
      "aws-waf-security-automations",
      {
        analyticsReporting: false, // CDK::Metadata breaks deployment in some regions
        synthesizer: new DefaultStackSynthesizer({
          generateBootstrapVersionRule: false, //CDK:: Clean bootstrap stack version
        }),
      },
    );
    const resourceSuppressions = {
      "AWS::IAM::Role": ["IAM_NO_INLINE_POLICY_CHECK"],
    };

    Aspects.of(stack).add(
      new CfnGuardSuppressResourceList(resourceSuppressions),
    );

    newTemplate = Template.fromStack(stack.getFirehoseAthenaNestedStack());

    oldTemplate = oldTemplate || {};
    newTemplate = newTemplate.toJSON() || {};
  });

  test("AWSTemplateFormatVersion match", () => {
    expect(newTemplate.AWSTemplateFormatVersion).toEqual(
      oldTemplate.AWSTemplateFormatVersion,
    );
  });

  test("Description match", () => {
    expect(newTemplate.Description).toEqual(oldTemplate.Description);
  });

  test("Metadata match", () => {
    expect(newTemplate.Metadata).toEqual(oldTemplate.Metadata);
  });

  test("Parameters match", () => {
    expect(newTemplate.Parameters).toEqual(oldTemplate.Parameters);
  });

  test("Conditions match", () => {
    expect(newTemplate.Conditions).toEqual(oldTemplate.Conditions);
  });

  test("Mappings match", () => {
    expect(newTemplate.Mappings).toEqual(oldTemplate.Mappings);
  });

  test("Resources match", () => {
    expect(newTemplate.Resources).toEqual(oldTemplate.Resources);
  });

  test("Outputs match", () => {
    expect(newTemplate.Outputs).toEqual(oldTemplate.Outputs);
  });
});
