// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CfnMapping,
  Fn,
  ICfnRuleConditionExpression,
  Token,
} from "aws-cdk-lib";
import Utils from "../lib/mappings/utils";

describe("Utils", () => {
  describe("findInMap", () => {
    it("should call findInMap with correct parameters", () => {
      const mockMapping = {
        findInMap: jest.fn().mockReturnValue("mappedValue"),
      } as unknown as CfnMapping;

      const result = Utils.findInMap(mockMapping, "firstLevel", "secondLevel");

      expect(mockMapping.findInMap).toHaveBeenCalledWith(
        "firstLevel",
        "secondLevel",
      );
      expect(result).toBe("mappedValue");
    });
  });

  describe("isCfnNoValueReference", () => {
    it("should return true for AWS::NoValue reference", () => {
      const value = { Ref: "AWS::NoValue" };
      expect(Utils.isCfnNoValueReference(value)).toBe(true);
    });

    it("should return false for other references", () => {
      const value = { Ref: "SomeOtherRef" };
      expect(Utils.isCfnNoValueReference(value)).toBe(false);
    });

    it("should return false for null", () => {
      expect(Utils.isCfnNoValueReference(null)).toBe(false);
    });

    it("should return false for non-object values", () => {
      expect(Utils.isCfnNoValueReference("string")).toBe(false);
      expect(Utils.isCfnNoValueReference(123)).toBe(false);
      expect(Utils.isCfnNoValueReference(undefined)).toBe(false);
    });
  });

  describe("safeNumberValue", () => {
    it("should return default value for AWS::NoValue reference", () => {
      const value = { Ref: "AWS::NoValue" };
      const defaultValue = 42;
      expect(Utils.safeNumberValue(value, defaultValue)).toBe(defaultValue);
    });

    it("should return Token.asNumber result for other values", () => {
      const mockValue = "someValue";
      const defaultValue = 42;

      // Mock Token.asNumber
      jest.spyOn(Token, "asNumber").mockReturnValue(123);

      expect(Utils.safeNumberValue(mockValue, defaultValue)).toBe(123);
      expect(Token.asNumber).toHaveBeenCalledWith(mockValue);
    });
  });

  describe("getRegionScope", () => {
    it("should return correct condition for region scope", () => {
      const mockConditionResult: ICfnRuleConditionExpression = {
        toString: () => "REGIONAL",
        disambiguator: true, // Changed to boolean
        creationStack: [],
        resolve: () => ({ Condition: "testCondition" }),
      };

      jest.spyOn(Fn, "conditionIf").mockReturnValue(mockConditionResult);

      const result = Utils.getRegionScope("testCondition");

      expect(Fn.conditionIf).toHaveBeenCalledWith(
        "testCondition",
        "REGIONAL",
        "CLOUDFRONT",
      );
      expect(result).toBe("REGIONAL");
    });
  });

  describe("getLogType", () => {
    it("should return correct condition for log type", () => {
      const mockConditionResult: ICfnRuleConditionExpression = {
        toString: () => "alb",
        disambiguator: true, // Changed to boolean
        creationStack: [],
        resolve: () => ({ Condition: "testCondition" }),
      };

      jest.spyOn(Fn, "conditionIf").mockReturnValue(mockConditionResult);

      const result = Utils.getLogType("testCondition");

      expect(Fn.conditionIf).toHaveBeenCalledWith(
        "testCondition",
        "alb",
        "cloudfront",
      );
      expect(result).toBe("alb");
    });
  });
});
