// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnMapping, Fn, Token } from "aws-cdk-lib";

export default class Utils {
  static findInMap(
    mapping: CfnMapping,
    firstLevel: string,
    secondLevel: string,
  ): string {
    return mapping.findInMap(firstLevel, secondLevel);
  }

  static isCfnNoValueReference(value: unknown) {
    return (
      typeof value === "object" &&
      value !== null &&
      "Ref" in value &&
      (value as { Ref: unknown }).Ref === "AWS::NoValue"
    );
  }

  static safeNumberValue(value: unknown, defaultValue: number): number {
    if (Utils.isCfnNoValueReference(value)) {
      return defaultValue;
    }
    return Token.asNumber(value);
  }

  static getRegionScope(value: string): string {
    return Fn.conditionIf(value, "REGIONAL", "CLOUDFRONT").toString();
  }

  static getLogType(value: string): string {
    return Fn.conditionIf(value, "alb", "cloudfront").toString();
  }
}
