// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnDeletionPolicy, Fn } from "aws-cdk-lib";
import { CfnBucket, CfnBucketPolicy } from "aws-cdk-lib/aws-s3";
import { CheckRequirements } from "../customs/check-requirements";

interface WafLogBucketProps {
  httpFloodProtectionLogParserActivated: CfnCondition;
  checkRequirements: CheckRequirements;
  accessLoggingBucket: string;
}

export class WafLogBucket extends Construct {
  public static readonly ID = "WafLogBucket";
  public static readonly POLICY_ID = "WafLogBucketPolicy";
  private readonly bucket: CfnBucket;

  constructor(scope: Construct, id: string, props: WafLogBucketProps) {
    super(scope, id);

    this.bucket = new CfnBucket(this, WafLogBucket.ID, {
      accessControl: "Private",
      bucketEncryption: {
        serverSideEncryptionConfiguration: [
          {
            serverSideEncryptionByDefault: {
              sseAlgorithm: "AES256",
            },
          },
        ],
      },
      publicAccessBlockConfiguration: {
        blockPublicAcls: true,
        blockPublicPolicy: true,
        ignorePublicAcls: true,
        restrictPublicBuckets: true,
      },
      loggingConfiguration: {
        destinationBucketName: Fn.ref(props.accessLoggingBucket),
        logFilePrefix: "WAF_Logs/",
      },
    });
    this.bucket.cfnOptions.deletionPolicy = CfnDeletionPolicy.RETAIN;
    this.bucket.cfnOptions.updateReplacePolicy = CfnDeletionPolicy.RETAIN;
    this.bucket.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivated;
    this.bucket.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "W51",
            reason: "WafLogBucket does not require a bucket policy.",
          },
        ],
      },
    };
    this.bucket.addOverride("DependsOn", props.checkRequirements.node.id);
    this.bucket.overrideLogicalId(WafLogBucket.ID);

    const bucketPolicy = new CfnBucketPolicy(this, WafLogBucket.POLICY_ID, {
      bucket: this.bucket.ref,
      policyDocument: {
        Statement: [
          {
            Sid: "HttpsOnly",
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              this.bucket.attrArn,
              {
                "Fn::Join": ["/", [this.bucket.attrArn, "*"]],
              },
            ],
            Condition: {
              Bool: {
                "aws:SecureTransport": "false",
              },
            },
          },
        ],
      },
    });

    bucketPolicy.cfnOptions.condition =
      props.httpFloodProtectionLogParserActivated;
    bucketPolicy.overrideLogicalId(WafLogBucket.POLICY_ID);
  }

  public getBucket() {
    return this.bucket;
  }
}
