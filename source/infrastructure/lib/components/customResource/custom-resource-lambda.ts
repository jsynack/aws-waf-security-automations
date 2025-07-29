// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { Aws, CfnCondition, Duration, Fn } from "aws-cdk-lib";
import { Role } from "aws-cdk-lib/aws-iam";
import {
  CfnFunction,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { SolutionMapping } from "../../mappings/solution";
import { distVersion } from "../../constants/waf-constants";
import { CreateUniqueID } from "../customs/create-unique-id";
import { LambdaRoleCustomResource } from "./custom-resource-role";
import Utils from "../../mappings/utils";

interface CustomResourceLambdaProps {
  lambdaRoleCustomResource: LambdaRoleCustomResource;
  albEndpoint: CfnCondition;
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  createUniqueID: CreateUniqueID;
}

export class CustomResourceLambda extends Construct {
  public static readonly ID = "CustomResource";

  private readonly lambdaFunction: Function;

  constructor(scope: Construct, id: string, props: CustomResourceLambdaProps) {
    super(scope, id);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "custom_resource.zip",
    ]);

    this.lambdaFunction = new Function(this, CustomResourceLambda.ID, {
      description:
        "This lambda function configures the Web ACL rules based on the features activated in the CloudFormation template.",
      handler: "custom_resource.lambda_handler",
      role: Role.fromRoleArn(
        this,
        LambdaRoleCustomResource.ID,
        props.lambdaRoleCustomResource.getRole().attrArn,
        { mutable: false },
      ),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        SCOPE: Utils.getRegionScope(props.albEndpoint.logicalId),
        SOLUTION_ID: props.solutionMapping.findInMap("Data", "SolutionID"),
        METRICS_URL: props.solutionMapping.findInMap("Data", "MetricsURL"),
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        SOLUTION_VERSION: distVersion,
        UUID: props.createUniqueID.getUUID(),
        POWERTOOLS_SERVICE_NAME: CustomResourceLambda.ID,
      },
      runtime: Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(300),
      tracing: Tracing.ACTIVE,
    });

    const customResourceCfn = this.lambdaFunction.node
      .defaultChild as CfnFunction;
    customResourceCfn.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W58",
          reason:
            "Log permissions are defined in the LambdaRoleCustomResource policies",
        },
      ],
    });
    customResourceCfn.overrideLogicalId(CustomResourceLambda.ID);
  }

  public getFunction() {
    return this.lambdaFunction;
  }
}
