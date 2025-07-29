// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Fn } from "aws-cdk-lib";
import WebaclUtils from "../lib/nestedstacks/webacl/utils/webaclUtils";
import { WafAggregateKeyType } from "../lib/constants/waf-constants";

jest.mock("aws-cdk-lib", () => ({
  Fn: {
    conditionIf: jest.fn((value, ifTrue, ifFalse) =>
      value ? ifTrue : ifFalse,
    ),
  },
}));

describe("WebaclUtils cover", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return WafAggregateKeyType.IP when value is truthy", () => {
    const result = WebaclUtils.getAggregateKeyType("some-value"); // Non-empty string is truthy
    expect(result).toBe(WafAggregateKeyType.IP);
    expect(Fn.conditionIf).toHaveBeenCalledWith(
      "some-value",
      WafAggregateKeyType.IP,
      WafAggregateKeyType.CUSTOM_KEYS,
    );
  });

  it("should return WafAggregateKeyType.CUSTOM_KEYS when value is falsy", () => {
    const result = WebaclUtils.getAggregateKeyType("");
    expect(result).toBe(WafAggregateKeyType.CUSTOM_KEYS);
    expect(Fn.conditionIf).toHaveBeenCalledWith(
      "",
      WafAggregateKeyType.IP,
      WafAggregateKeyType.CUSTOM_KEYS,
    );
  });
});
