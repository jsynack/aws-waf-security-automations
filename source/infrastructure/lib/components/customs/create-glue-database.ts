// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { IFunction } from "aws-cdk-lib/aws-lambda";
import { CfnCondition, CfnResource, CustomResource, Fn } from "aws-cdk-lib";
import { CheckRequirements } from "./check-requirements";

export interface CreateGlueDatabaseNameProps {
  helperFunction: IFunction;
  athenaLogParserCondition: CfnCondition;
  checkRequirements: CheckRequirements;
}

export class CreateGlueDatabase extends Construct {
  public static readonly ID = "CreateGlueDatabaseName";
  private static readonly TYPE = "Custom::CreateGlueDatabaseName";

  private readonly resource: CustomResource;

  constructor(
    scope: Construct,
    id: string,
    props: CreateGlueDatabaseNameProps,
  ) {
    super(scope, id);

    this.resource = new CustomResource(this, "Resource", {
      resourceType: CreateGlueDatabase.TYPE,
      serviceToken: props.helperFunction.functionArn,
      properties: {
        StackName: Fn.ref("AWS::StackName"),
      },
    });

    const cfnResource = this.resource.node.defaultChild as CfnResource;
    cfnResource.addOverride("Type", CreateGlueDatabase.TYPE);
    cfnResource.overrideLogicalId(CreateGlueDatabase.ID);
    cfnResource.addOverride("UpdateReplacePolicy", undefined);
    cfnResource.addOverride("DeletionPolicy", undefined);
    cfnResource.cfnOptions.condition = props.athenaLogParserCondition;
    cfnResource.addOverride("DependsOn", props.checkRequirements.node.id);
  }

  public getDatabaseName(): string {
    return this.resource.getAttString("DatabaseName");
  }
}
