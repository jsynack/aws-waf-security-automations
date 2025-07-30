// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnCondition,
  CfnOutput,
  CfnParameter,
  CfnResource,
  CustomResource,
  Fn,
  Stack,
} from "aws-cdk-lib";
import { CfnFunction, IFunction } from "aws-cdk-lib/aws-lambda";
import { distVersion } from "../../constants/waf-constants";
import { CfnBucket } from "aws-cdk-lib/aws-s3";

export interface ConfigureAppAccessLogBucketProps {
  scannersProbesProtectionActivated: CfnCondition;
  scannersProbesLambdaLogParser: CfnCondition;
  scannersProbesAthenaLogParser: CfnCondition;
  turnOnAppAccessLogBucketLogging: CfnCondition;
  appAccessLogBucket: CfnParameter;
  appAccessLogBucketPrefix: CfnParameter;
  helperFunction: IFunction;
  logParserFunction: CfnFunction;
  logsForPartition: IFunction;
  moveS3LogsForPartition: IFunction;
  accessLoggingBucket: CfnBucket;
}

export class ConfigureAppAccessLogBucket extends Construct {
  public readonly resource: CustomResource;
  public static readonly ID = "ConfigureAppAccessLogBucket";
  public static readonly TYPE = "Custom::ConfigureAppAccessLogBucket";

  constructor(
    scope: Construct,
    id: string,
    props: ConfigureAppAccessLogBucketProps,
  ) {
    super(scope, id);

    this.resource = new CustomResource(this, ConfigureAppAccessLogBucket.ID, {
      resourceType: ConfigureAppAccessLogBucket.TYPE,
      serviceToken: props.helperFunction.functionArn,
      properties: {
        Region: Stack.of(this).region,
        SolutionVersion: distVersion,
        AppAccessLogBucket: props.appAccessLogBucket,
        AppAccessLogBucketPrefix: props.appAccessLogBucketPrefix,
        LogParser: Fn.conditionIf(
          props.logParserFunction.logicalId,
          props.logParserFunction.attrArn,
          Fn.ref("AWS::NoValue"),
        ),
        ScannersProbesLambdaLogParser: Fn.conditionIf(
          props.scannersProbesLambdaLogParser.logicalId,
          "yes",
          "no",
        ),
        ScannersProbesAthenaLogParser: Fn.conditionIf(
          props.scannersProbesAthenaLogParser.logicalId,
          "yes",
          "no",
        ),
        MoveS3LogsForPartition: Fn.conditionIf(
          props.scannersProbesAthenaLogParser.logicalId,
          props.moveS3LogsForPartition.functionArn,
          Fn.ref("AWS::NoValue"),
        ).toString(),
        AccessLoggingBucket: Fn.conditionIf(
          props.turnOnAppAccessLogBucketLogging.logicalId,
          props.accessLoggingBucket.ref,
          Fn.ref("AWS::NoValue"),
        ).toString(),
      },
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.cfnOptions.condition = props.scannersProbesProtectionActivated;
    cfnResource.addOverride("Type", ConfigureAppAccessLogBucket.TYPE);
    cfnResource.overrideLogicalId(ConfigureAppAccessLogBucket.ID);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);

    const cfnOutputAppAccessLogBucket = new CfnOutput(
      this,
      "AppAccessLogBucketOutput",
      {
        key: "AppAccessLogBucket",
        exportName: Fn.sub("${AWS::StackName}-AppAccessLogBucket"),
        value: Fn.ref(props.appAccessLogBucket.logicalId),
      },
    );
    cfnOutputAppAccessLogBucket.condition =
      props.scannersProbesProtectionActivated;
  }
}
