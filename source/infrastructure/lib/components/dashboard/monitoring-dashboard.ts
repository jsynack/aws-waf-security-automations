// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import { CfnCondition, Fn } from "aws-cdk-lib";
import { CheckRequirements } from "../customs/check-requirements";
import { CfnDashboard } from "aws-cdk-lib/aws-cloudwatch";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";

interface MonitoringDashboardProps {
  albEndpoint: CfnCondition;
  checkRequirements: CheckRequirements;
  webACLStack: WebaclNestedstack;
}

export class MonitoringDashboard extends Construct {
  public static readonly ID = "MonitoringDashboard";

  constructor(scope: Construct, id: string, props: MonitoringDashboardProps) {
    super(scope, id);

    const regionMetric = Fn.conditionIf(
      props.albEndpoint.logicalId,
      Fn.sub(', "Region", "${AWS::Region}"'),
      "",
    ).toString();

    const regionProperties = Fn.conditionIf(
      props.albEndpoint.logicalId,
      Fn.sub("${AWS::Region}"),
      "us-east-1",
    ).toString();

    const wafWebAclName = Fn.select(
      0,
      Fn.split(
        "|",
        Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFWebACL_OUTPUT,
        ).toString(),
      ),
    );

    const dashboard = new CfnDashboard(this, MonitoringDashboard.ID, {
      dashboardName: Fn.sub("${AWS::StackName}-${AWS::Region}"),
      dashboardBody: Fn.sub(
        `{
  "widgets": [{
    "type": "metric",
    "x": 0,
    "y": 0,
    "width": 15,
    "height": 10,
    "properties": {
      "view": "timeSeries",
      "stacked": false,
      "stat": "Sum",
      "period": 300,
      "metrics": [
        ["AWS/WAFV2", "BlockedRequests", "WebACL", "\${WAFWebACLName}", "Rule", "ALL" \${RegionMetric}],
        ["AWS/WAFV2", "AllowedRequests", "WebACL", "\${WAFWebACLName}", "Rule", "ALL" \${RegionMetric}]
      ],
      "region": "\${RegionProperties}"
    }
  }]
}`,
        {
          WAFWebACLName: wafWebAclName,
          RegionMetric: regionMetric,
          RegionProperties: regionProperties,
        },
      ),
    });

    dashboard.overrideLogicalId(MonitoringDashboard.ID);
    dashboard.addOverride("DependsOn", props.checkRequirements.node.id);
  }
}
