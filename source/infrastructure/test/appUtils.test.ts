// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnResource } from "aws-cdk-lib";
import { IConstruct } from "constructs";
import {
  addCfnGuardSuppressions,
  CfnGuardSuppressResourceList,
} from "../lib/utils/appUtils";

describe("appUtils", () => {
  describe("addCfnGuardSuppressions", () => {
    let mockResource: jest.Mocked<CfnResource>;
    let mockDefaultChild: jest.Mocked<CfnResource>;

    beforeEach(() => {
      mockDefaultChild = {
        getMetadata: jest.fn(),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;

      mockResource = {
        node: {
          defaultChild: mockDefaultChild,
        },
        getMetadata: jest.fn(),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;
    });

    it("should add new suppressions to target resource", () => {
      const suppressions = ["RULE1", "RULE2"];
      mockDefaultChild.getMetadata.mockReturnValue(undefined);

      addCfnGuardSuppressions(mockResource, suppressions);

      expect(mockDefaultChild.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["RULE1", "RULE2"],
      });
    });

    it("should merge suppressions with existing ones", () => {
      const suppressions = ["RULE2", "RULE3"];
      mockDefaultChild.getMetadata.mockReturnValue({
        SuppressedRules: ["RULE1", "RULE2"],
      });

      addCfnGuardSuppressions(mockResource, suppressions);

      expect(mockDefaultChild.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["RULE1", "RULE2", "RULE3"],
      });
    });

    it("should use resource itself if no defaultChild", () => {
      const resourceWithoutDefaultChild = {
        node: {},
        getMetadata: jest.fn().mockReturnValue(undefined),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;

      const suppressions = ["RULE1", "RULE2"];

      addCfnGuardSuppressions(resourceWithoutDefaultChild, suppressions);

      expect(resourceWithoutDefaultChild.addMetadata).toHaveBeenCalledWith(
        "guard",
        {
          SuppressedRules: ["RULE1", "RULE2"],
        },
      );
    });

    it("should preserve existing metadata", () => {
      const suppressions = ["RULE2"];
      mockDefaultChild.getMetadata.mockReturnValue({
        SuppressedRules: ["RULE1"],
        OtherProperty: "value",
      });

      addCfnGuardSuppressions(mockResource, suppressions);

      expect(mockDefaultChild.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["RULE1", "RULE2"],
        OtherProperty: "value",
      });
    });

    it("should remove duplicate suppressions", () => {
      const suppressions = ["RULE1", "RULE2", "RULE1"];
      mockDefaultChild.getMetadata.mockReturnValue({
        SuppressedRules: ["RULE1", "RULE3"],
      });

      addCfnGuardSuppressions(mockResource, suppressions);

      expect(mockDefaultChild.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["RULE1", "RULE3", "RULE2"],
      });
    });
  });

  describe("CfnGuardSuppressResourceList", () => {
    let mockCfnResource: jest.Mocked<CfnResource>;
    let mockConstruct: jest.Mocked<IConstruct>;
    let mockDefaultChild: jest.Mocked<CfnResource>;

    beforeEach(() => {
      mockCfnResource = {
        cfnResourceType: "AWS::IAM::Role",
        node: {}, // Ensure node exists but without defaultChild
        getMetadata: jest.fn().mockReturnValue(undefined),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;

      mockDefaultChild = {
        cfnResourceType: "AWS::Lambda::Function",
        node: {}, // Ensure node exists
        getMetadata: jest.fn().mockReturnValue(undefined),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;

      mockConstruct = {
        node: {
          defaultChild: mockDefaultChild,
        },
      } as unknown as jest.Mocked<IConstruct>;

      jest
        .spyOn(CfnResource, "isCfnResource")
        .mockImplementation(
          (node) => node === mockCfnResource || node === mockDefaultChild,
        );
    });

    it("should add suppressions to matching CfnResource", () => {
      const resourceSuppressions = {
        "AWS::IAM::Role": ["IAM_NO_INLINE_POLICY_CHECK"],
      };
      const aspect = new CfnGuardSuppressResourceList(resourceSuppressions);

      aspect.visit(mockCfnResource);

      expect(mockCfnResource.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["IAM_NO_INLINE_POLICY_CHECK"],
      });
    });

    it("should add suppressions to defaultChild if it's a matching CfnResource", () => {
      const resourceSuppressions = {
        "AWS::Lambda::Function": ["LAMBDA_PERMISSION_CHECK"],
      };
      const aspect = new CfnGuardSuppressResourceList(resourceSuppressions);

      aspect.visit(mockConstruct);

      expect(mockDefaultChild.addMetadata).toHaveBeenCalledWith("guard", {
        SuppressedRules: ["LAMBDA_PERMISSION_CHECK"],
      });
    });

    it("should not add suppressions when resource type doesn't match", () => {
      const resourceSuppressions = {
        "AWS::S3::Bucket": ["S3_BUCKET_LOGGING_ENABLED"],
      };
      const aspect = new CfnGuardSuppressResourceList(resourceSuppressions);

      const nonMatchingResource = {
        cfnResourceType: "AWS::IAM::Role", // This type is not in resourceSuppressions
        node: { defaultChild: undefined }, // Ensure node and defaultChild are defined
        getMetadata: jest.fn(),
        addMetadata: jest.fn(),
      } as unknown as jest.Mocked<CfnResource>;

      aspect.visit(nonMatchingResource);

      expect(nonMatchingResource.addMetadata).not.toHaveBeenCalled();
    });

    it("should not add suppressions when node is not a CfnResource", () => {
      jest.spyOn(CfnResource, "isCfnResource").mockReturnValue(false);
      const resourceSuppressions = {
        "AWS::IAM::Role": ["IAM_NO_INLINE_POLICY_CHECK"],
      };
      const aspect = new CfnGuardSuppressResourceList(resourceSuppressions);

      const nonCfnConstruct = {
        node: { defaultChild: undefined }, // Ensure node exists but without defaultChild
      } as unknown as jest.Mocked<IConstruct>;

      aspect.visit(nonCfnConstruct);

      expect(mockCfnResource.addMetadata).not.toHaveBeenCalled();
      expect(mockDefaultChild.addMetadata).not.toHaveBeenCalled();
    });
  });
});
