// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnMapping } from "aws-cdk-lib";
import Utils from "./utils";

export interface SolutionMappingsProps {
  templateBucket: string;
  sourceBucket: string;
  keyPrefix: string;
}

export class SourceCodeMapping extends Construct {
  public readonly mapping: CfnMapping;
  private static readonly ID = "SourceCode";

  constructor(scope: Construct, id: string, props: SolutionMappingsProps) {
    super(scope, id);

    this.mapping = new CfnMapping(this, id, {
      mapping: {
        General: {
          TemplateBucket: props.templateBucket,
          SourceBucket: props.sourceBucket,
          KeyPrefix: props.keyPrefix,
        },
      },
    });

    this.mapping.overrideLogicalId(SourceCodeMapping.ID);
  }

  public findInMap(firstLevel: string, secondLevel: string): string {
    return Utils.findInMap(this.mapping, firstLevel, secondLevel);
  }
}
