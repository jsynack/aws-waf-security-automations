// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Fn } from "aws-cdk-lib";
import { WafAggregateKeyType } from "../../../constants/waf-constants";

export default class WebaclUtils {
  static getAggregateKeyType(value: string): string {
    return Fn.conditionIf(
      value,
      WafAggregateKeyType.IP,
      WafAggregateKeyType.CUSTOM_KEYS,
    ).toString();
  }
}
