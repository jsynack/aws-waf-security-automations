// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { CreateUniqueID } from "../customs/create-unique-id";
import { CfnTopic, Topic } from "aws-cdk-lib/aws-sns";
import { Key } from "aws-cdk-lib/aws-kms";

interface IPExpirationSNSTopicProps {
  snsEmailCondition: CfnCondition;
  createUniqueID: CreateUniqueID;
}

export class IPExpirationSNSTopic extends Construct {
  public static readonly ID = "IPExpirationSNSTopic";

  private readonly topic: Topic;

  constructor(scope: Construct, id: string, props: IPExpirationSNSTopicProps) {
    super(scope, id);

    const snsKey = "alias/aws/sns";
    const defaultSNSKmsKey = Key.fromKeyArn(
      this,
      "DefaultSNSKmsKey",
      "arn:arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:" +
        snsKey,
    );

    this.topic = new Topic(this, IPExpirationSNSTopic.ID, {
      displayName:
        "Security Automations for AWS WAF IP Expiration Notification",
      topicName: Fn.join("-", [
        "AWS-WAF-Security-Automations-IP-Expiration-Notification",
        props.createUniqueID.getUUID(),
      ]),
      masterKey: defaultSNSKmsKey,
    });

    const cfnTopic = this.topic.node.defaultChild as CfnTopic;
    cfnTopic.kmsMasterKeyId = snsKey;
    cfnTopic.cfnOptions.condition = props.snsEmailCondition;
    cfnTopic.overrideLogicalId(IPExpirationSNSTopic.ID);
  }

  public getTopic(): Topic {
    return this.topic;
  }
}
