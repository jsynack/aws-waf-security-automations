// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { IFunction } from "aws-cdk-lib/aws-lambda";
import { CfnResource, CustomResource } from "aws-cdk-lib";
import { CheckRequirements } from "./check-requirements";

export interface CreateUniqueIDProps {
  helperFunction: IFunction;
  checkRequirements: CheckRequirements;
}

export class CreateUniqueID extends Construct {
  public static readonly ID = "CreateUniqueID";
  private static readonly TYPE = "Custom::CreateUUID";

  public readonly resource: CustomResource;

  constructor(scope: Construct, id: string, props: CreateUniqueIDProps) {
    super(scope, id);

    this.resource = new CustomResource(this, "Resource", {
      serviceToken: props.helperFunction.functionArn,
      resourceType: CreateUniqueID.TYPE,
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.addOverride("Type", CreateUniqueID.TYPE);
    cfnResource.overrideLogicalId(CreateUniqueID.ID);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);
    cfnResource.addOverride("DependsOn", props.checkRequirements.node.id);
  }

  public getUUID(): string {
    return this.resource.getAttString("UUID");
  }
}
