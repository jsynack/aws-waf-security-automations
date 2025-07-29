// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, CfnParameter, CfnResource, Fn } from "aws-cdk-lib";
import {
  CfnTopicPolicy,
  Subscription,
  SubscriptionProtocol,
  Topic,
} from "aws-cdk-lib/aws-sns";
import { CfnPolicy, CfnRole } from "aws-cdk-lib/aws-iam";
import { manifest } from "../../constants/waf-constants";

interface SetIPSNSProps {
  lambdaRoleRemoveExpiredIP: CfnRole;
  ipExpirationSnsTopic: Topic;
  snsEmailCondition: CfnCondition;
  snsEmailParam: CfnParameter;
}

export class SetIPSNS extends Construct {
  public static readonly ID = "SetIPSNS";
  public static readonly ID_POLICY = "SNSPublishPolicy";
  public static readonly ID_SNS_POLICY = "SNSNotificationPolicy";
  public static readonly ID_NOTIFICATION = "IPExpirationEmailNotification";

  constructor(scope: Construct, id: string, props: SetIPSNSProps) {
    super(scope, id);

    const subscription = new Subscription(this, SetIPSNS.ID_NOTIFICATION, {
      topic: props.ipExpirationSnsTopic,
      protocol: SubscriptionProtocol.EMAIL,
      endpoint: props.snsEmailParam.valueAsString,
    });
    const cfnSubscription = subscription.node.defaultChild as CfnResource;
    cfnSubscription.overrideLogicalId(SetIPSNS.ID_NOTIFICATION);
    cfnSubscription.cfnOptions.condition = props.snsEmailCondition;

    const snsPolicy = new CfnTopicPolicy(this, SetIPSNS.ID_SNS_POLICY, {
      topics: [Fn.ref("IPExpirationSNSTopic")],
      policyDocument: {
        Statement: [
          {
            Sid: "__default_statement_ID",
            Effect: "Allow",
            Principal: {
              AWS: "*",
            },
            Action: [
              "SNS:GetTopicAttributes",
              "SNS:SetTopicAttributes",
              "SNS:AddPermission",
              "SNS:RemovePermission",
              "SNS:DeleteTopic",
              "SNS:Subscribe",
              "SNS:ListSubscriptionsByTopic",
              "SNS:Publish",
              "SNS:Receive",
            ],
            Resource: Fn.ref("IPExpirationSNSTopic"),
            Condition: {
              StringEquals: {
                "AWS:SourceOwner": Fn.sub("${AWS::AccountId}"),
              },
            },
          },
          {
            Sid: "TrustLambdaToPublishEventsToMyTopic",
            Effect: "Allow",
            Principal: {
              Service: "lambda.amazonaws.com",
            },
            Action: "SNS:Publish",
            Resource: Fn.ref("IPExpirationSNSTopic"),
          },
          {
            Principal: "*",
            Sid: "AllowPublishThroughSSLOnly",
            Action: "SNS:Publish",
            Effect: "Deny",
            Resource: [Fn.ref("IPExpirationSNSTopic")],
            Condition: {
              Bool: {
                "aws:SecureTransport": "false",
              },
            },
          },
        ],
      },
    });
    snsPolicy.cfnOptions.condition = props.snsEmailCondition;
    snsPolicy.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: "F18",
            reason: "Condition restricts permissions to current account.",
          },
        ],
      },
    };
    snsPolicy.overrideLogicalId(SetIPSNS.ID_SNS_POLICY);

    const publishPolicy = new CfnPolicy(this, SetIPSNS.ID_POLICY, {
      policyName: SetIPSNS.ID_POLICY,
      roles: [props.lambdaRoleRemoveExpiredIP.ref],
      policyDocument: {
        Statement: [
          {
            Effect: "Allow",
            Action: ["SNS:Publish"],
            Resource: [props.ipExpirationSnsTopic.topicArn],
          },
        ],
        Version: manifest.ipSnsVersion,
      },
    });
    publishPolicy.overrideLogicalId(SetIPSNS.ID_POLICY);
    publishPolicy.cfnOptions.condition = props.snsEmailCondition;
  }
}
