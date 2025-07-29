// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { IFunction } from "aws-cdk-lib/aws-lambda";
import { CfnCondition, CfnResource, CustomResource, Fn } from "aws-cdk-lib";
import { CheckRequirements } from "./check-requirements";

export interface CreateDeliveryStreamNameProps {
  helperFunction: IFunction;
  httpFloodProtectionLogParserActivated: CfnCondition;
  checkRequirements: CheckRequirements;
}

export class CreateDeliveryStreamName extends Construct {
  public static readonly ID = "CreateDeliveryStreamName";
  private static readonly TYPE = "Custom::CreateDeliveryStreamName";

  private readonly resource: CustomResource;

  constructor(
    scope: Construct,
    id: string,
    props: CreateDeliveryStreamNameProps,
  ) {
    super(scope, id);

    this.resource = new CustomResource(this, "Resource", {
      serviceToken: props.helperFunction.functionArn,
      properties: {
        StackName: Fn.ref("AWS::StackName"),
      },
      resourceType: CreateDeliveryStreamName.TYPE,
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.addOverride("Type", CreateDeliveryStreamName.TYPE);
    cfnResource.overrideLogicalId(CreateDeliveryStreamName.ID);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);
    cfnResource.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivated;
    cfnResource.addOverride("DependsOn", props.checkRequirements.node.id);
  }

  public getDeliveryStreamName(): string {
    return this.resource.getAttString("DeliveryStreamName");
  }
}
