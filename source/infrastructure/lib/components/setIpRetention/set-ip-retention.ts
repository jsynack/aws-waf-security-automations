// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { Aws, CfnCondition, CfnParameter, Duration, Fn } from "aws-cdk-lib";
import {
  CfnFunction,
  Code,
  Function,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { CfnRole, Role } from "aws-cdk-lib/aws-iam";
import { CfnTable } from "aws-cdk-lib/aws-dynamodb";
import { SourceCodeMapping } from "../../mappings/sourcecode";
import { SolutionMapping } from "../../mappings/solution";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { LambdaRoleSetIPRetention } from "./set-ip-retention-role";

interface SetIPRetentionProps {
  ipRetentionPeriodCondition: CfnCondition;
  lambdaRoleSetIPRetention: LambdaRoleSetIPRetention;
  sourceCodeMapping: SourceCodeMapping;
  solutionMapping: SolutionMapping;
  ipRetentionDDBTable: CfnTable;
  ipRetentionPeriodAllowedParam: CfnParameter;
  ipRetentionPeriodDeniedParam: CfnParameter;
  lambdaRoleRemoveExpiredIP: CfnRole;
}

export class SetIPRetention extends Construct {
  public static readonly ID = "SetIPRetention";

  private readonly function: Function;

  constructor(scope: Construct, id: string, props: SetIPRetentionProps) {
    super(scope, id);

    const s3Bucket = Fn.join("-", [
      props.sourceCodeMapping.findInMap("General", "SourceBucket"),
      Aws.REGION,
    ]);

    const s3Key = Fn.join("/", [
      props.sourceCodeMapping.findInMap("General", "KeyPrefix"),
      "ip_retention_handler.zip",
    ]);

    this.function = new Function(this, SetIPRetention.ID, {
      description:
        "This lambda function processes CW events for WAF UpdateIPSet API calls. It writes relevant ip retention data into a DynamoDB table.",
      handler: "set_ip_retention.lambda_handler",
      role: Role.fromRoleArn(
        this,
        LambdaRoleSetIPRetention.ID,
        props.lambdaRoleSetIPRetention.getRole().attrArn,
        { mutable: false },
      ),
      code: Code.fromBucket(
        Bucket.fromBucketName(this, "SourceBucket", s3Bucket),
        s3Key,
      ),
      runtime: Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: props.solutionMapping.findInMap("Data", "LogLevel"),
        TABLE_NAME: props.ipRetentionDDBTable.ref,
        STACK_NAME: Aws.STACK_NAME,
        IP_RETENTION_PERIOD_ALLOWED_MINUTE:
          props.ipRetentionPeriodAllowedParam.valueAsString,
        IP_RETENTION_PERIOD_DENIED_MINUTE:
          props.ipRetentionPeriodDeniedParam.valueAsString,
        REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME: props.lambdaRoleRemoveExpiredIP.ref,
        USER_AGENT_EXTRA: props.solutionMapping.findInMap(
          "UserAgent",
          "UserAgentExtra",
        ),
        POWERTOOLS_SERVICE_NAME: SetIPRetention.ID,
      },
      tracing: Tracing.ACTIVE,
    });
    const cfnFunction = this.function.node.defaultChild as CfnFunction;
    cfnFunction.overrideLogicalId(SetIPRetention.ID);
    cfnFunction.cfnOptions.condition = props.ipRetentionPeriodCondition;
  }

  public getFunction(): Function {
    return this.function;
  }
}
