// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CreateUniqueID } from "../customs/create-unique-id";
import { ITopic } from "aws-cdk-lib/aws-sns";
import { Aws, CfnCondition, Duration, Fn } from "aws-cdk-lib";
import {
  CfnFunction,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { SolutionMapping } from "../../mappings/solution";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { distVersion } from "../../constants/waf-constants";
import { Role } from "aws-cdk-lib/aws-iam";
import { LambdaRoleRemoveExpiredIP } from "./remove-expired-ip-role";

interface RemoveExpiredIPProps {
  ipRetentionPeriodCondition: CfnCondition;
  lambdaRoleRemoveExpiredIP: LambdaRoleRemoveExpiredIP;
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  createUniqueID: CreateUniqueID;
  snsEmail: CfnCondition;
  ipExpirationSNSTopic: ITopic;
}

export class RemoveExpiredIP extends Construct {
  public static readonly ID = "RemoveExpiredIP";
  private readonly function: Function;

  constructor(scope: Construct, id: string, props: RemoveExpiredIPProps) {
    super(scope, id);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "ip_retention_handler.zip",
    ]);

    this.function = new Function(this, RemoveExpiredIP.ID, {
      description:
        "This lambda function processes the DDB streams records (IP) expired by TTL. It removes expired IPs from WAF allowed or denied IP sets.",
      handler: "remove_expired_ip.lambda_handler",
      role: Role.fromRoleArn(
        this,
        LambdaRoleRemoveExpiredIP.ID,
        props.lambdaRoleRemoveExpiredIP.getRole().attrArn,
        { mutable: false },
      ),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      runtime: Runtime.PYTHON_3_12,
      memorySize: 512,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        SNS_EMAIL: Fn.conditionIf(
          props.snsEmail.logicalId,
          "yes",
          "no",
        ).toString(),
        SNS_TOPIC_ARN: Fn.conditionIf(
          props.snsEmail.logicalId,
          props.ipExpirationSNSTopic.topicArn,
          "",
        ).toString(),
        SEND_ANONYMIZED_USAGE_DATA: props.solutionMapping.findInMap(
          "Data",
          "SendAnonymizedUsageData",
        ),
        UUID: props.createUniqueID.getUUID(),
        SOLUTION_ID: props.solutionMapping.findInMap("Data", "SolutionID"),
        METRICS_URL: props.solutionMapping.findInMap("Data", "MetricsURL"),
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        SOLUTION_VERSION: distVersion,
        POWERTOOLS_SERVICE_NAME: RemoveExpiredIP.ID,
      },
      tracing: Tracing.ACTIVE,
    });

    const cfnFunction = this.function.node.defaultChild as CfnFunction;
    cfnFunction.cfnOptions.condition = props.ipRetentionPeriodCondition;
    cfnFunction.overrideLogicalId(RemoveExpiredIP.ID);
  }

  public getFunction(): Function {
    return this.function;
  }
}
