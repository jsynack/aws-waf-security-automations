// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnBucket, CfnBucketPolicy } from "aws-cdk-lib/aws-s3";
import { CfnCondition, CfnDeletionPolicy, CfnParameter } from "aws-cdk-lib";
import { CheckRequirements } from "../customs/check-requirements";

interface AccessLoggingBucketProps {
  createS3LoggingBucketCondition: CfnCondition;
  checkRequirements: CheckRequirements;
  httpFloodProtectionLogParserActivated: CfnCondition;
  appAccessLogBucket: CfnParameter;
  wafLogBucket: CfnBucket;
}

export class AccessLoggingBucket extends Construct {
  public static readonly ID = "AccessLoggingBucket";
  public static readonly POLICY_ID = "AccessLoggingBucketPolicy";

  private readonly bucket: CfnBucket;

  constructor(scope: Construct, id: string, props: AccessLoggingBucketProps) {
    super(scope, id);

    this.bucket = new CfnBucket(this, "AccessLoggingBucket", {
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
    });

    this.bucket.cfnOptions.condition = props.createS3LoggingBucketCondition;
    this.bucket.cfnOptions.deletionPolicy = CfnDeletionPolicy.RETAIN;
    this.bucket.cfnOptions.updateReplacePolicy = CfnDeletionPolicy.RETAIN;
    this.bucket.addMetadata("cfn_nag", {
      rules_to_suppress: [
        {
          id: "W35",
          reason:
            "This bucket is an access logging bucket for another bucket and does not require access logging to be configured for it.",
        },
      ],
    });

    this.bucket.cfnOptions.condition = props.createS3LoggingBucketCondition;
    this.bucket.addOverride("DependsOn", props.checkRequirements.node.id);
    this.bucket.overrideLogicalId(AccessLoggingBucket.ID);

    const bucketPolicy = new CfnBucketPolicy(
      this,
      AccessLoggingBucket.POLICY_ID,
      {
        bucket: this.bucket.ref,
        policyDocument: {
          Version: "2012-10-17",
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
            {
              Sid: "S3ServerAccessLogsPolicy",
              Effect: "Allow",
              Principal: {
                Service: "logging.s3.amazonaws.com",
              },
              Action: ["s3:PutObject"],
              Resource: [
                this.bucket.attrArn,
                {
                  "Fn::Join": ["/", [this.bucket.attrArn, "*"]],
                },
              ],
              Condition: {
                ArnLike: {
                  "aws:SourceArn": [
                    {
                      "Fn::If": [
                        props.httpFloodProtectionLogParserActivated.logicalId,
                        props.wafLogBucket.attrArn,
                        this.bucket.attrArn,
                      ],
                    },
                    {
                      "Fn::Join": [
                        "",
                        [
                          "arn:aws:s3:::",
                          props.appAccessLogBucket.valueAsString,
                        ],
                      ],
                    },
                  ],
                },
                StringEquals: {
                  "aws:SourceAccount": { Ref: "AWS::AccountId" },
                },
              },
            },
          ],
        },
      },
    );

    bucketPolicy.cfnOptions.condition = props.createS3LoggingBucketCondition;
    bucketPolicy.overrideLogicalId(AccessLoggingBucket.POLICY_ID);
  }

  public getBucket() {
    return this.bucket;
  }
}
