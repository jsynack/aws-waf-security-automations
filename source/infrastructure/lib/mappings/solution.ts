// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnMapping } from "aws-cdk-lib";
import { Construct } from "constructs";
import Utils from "./utils";
import { distOutputBucket } from "../constants/waf-constants";

export interface SolutionMappingProps {
  solutionId: string;
  distVersion: string;
  metricsURL: string;
  solutionName: string;
}

export class SolutionMapping extends Construct {
  private readonly mapping: CfnMapping;
  private static readonly ID = "Solution";

  constructor(scope: Construct, id: string, props: SolutionMappingProps) {
    super(scope, id);

    this.mapping = new CfnMapping(this, id, {
      mapping: {
        Data: {
          SendAnonymizedUsageData: "Yes",
          LogLevel: "INFO",
          SolutionID: props.solutionId,
          MetricsURL: props.metricsURL,
          SolutionVersion: props.distVersion,
          SolutionName: props.solutionName,
          MetricsFrequencyHours: "24",
          DistOutputBucket: distOutputBucket,
        },
        Action: {
          WAFWhitelistRule: "ALLOW",
          WAFBlacklistRule: "BLOCK",
          WAFSqlInjectionRule: "BLOCK",
          WAFXssRule: "BLOCK",
          WAFHttpFloodRateBasedRule: "BLOCK",
          WAFHttpFloodRegularRule: "BLOCK",
          WAFScannersProbesRule: "BLOCK",
          WAFIPReputationListsRule: "BLOCK",
          WAFBadBotRule: "BLOCK",
        },
        WAFRuleNames: {
          BadBotRule: "BadBotRule",
          HttpFloodRegularRule: "HttpFloodRegularRule",
          HttpFloodRateBasedRule: "HttpFloodRateBasedRule",
          ScannersProbesRule: "ScannersProbesRule",
          IPReputationListsRule: "IPReputationListsRule",
          SqlInjectionRule: "SqlInjectionRule",
          XssRule: "XssRule",
          BlacklistRule: "BlacklistRule",
        },
        UserAgent: {
          UserAgentExtra: `AwsSolution/${props.solutionId}/${props.distVersion}`,
        },
      },
    });

    this.mapping.overrideLogicalId(SolutionMapping.ID);
  }

  public findInMap(firstLevel: string, secondLevel: string): string {
    return Utils.findInMap(this.mapping, firstLevel, secondLevel);
  }
}
