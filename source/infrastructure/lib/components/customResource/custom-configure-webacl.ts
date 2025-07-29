// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnCondition,
  CfnResource,
  CfnParameter,
  CustomResource,
  Aws,
  Fn,
} from "aws-cdk-lib";
import { IFunction } from "aws-cdk-lib/aws-lambda";

import { CheckRequirements } from "../customs/check-requirements";
import { distVersion } from "../../constants/waf-constants";
import { SolutionMapping } from "../../mappings/solution";
import { CreateUniqueID } from "../customs/create-unique-id";
import { WebaclNestedstack } from "../../nestedstacks/webacl/webacl-nestedstack";

interface ConfigureWebAclProps {
  customResource: IFunction;
  parameters: { [key: string]: CfnParameter };
  httpFloodProtectionActivated: CfnCondition;
  webACLStack: WebaclNestedstack;
  userDefinedAppAccessLogBucketPrefix: CfnCondition;
  badBotProtectionActivated: CfnCondition;
  requestThresholdByCountry: CfnCondition;
  reputationListsProtectionActivated: CfnCondition;
  scannersProbesProtectionActivated: CfnCondition;
  snsEmail: CfnCondition;
  checkRequirements: CheckRequirements;
  solutionMapping: SolutionMapping;
  UUID: CreateUniqueID;
}

export class ConfigureWebAcl extends Construct {
  public static readonly ID = "ConfigureWebAcl";

  constructor(scope: Construct, id: string, props: ConfigureWebAclProps) {
    super(scope, id);

    const customConfigureWebAcl = new CustomResource(this, ConfigureWebAcl.ID, {
      serviceToken: props.customResource.functionArn,
      resourceType: "Custom::" + ConfigureWebAcl.ID,
      properties: {
        ActivateSqlInjectionProtectionParam:
          props.parameters.activateSqlInjectionProtection,
        ActivateCrossSiteScriptingProtectionParam:
          props.parameters.activateCrossSiteScriptingProtection,
        ActivateHttpFloodProtectionParam:
          props.parameters.activateHttpFloodProtection,
        ActivateScannersProbesProtectionParam:
          props.parameters.activateScannersProbesProtection,
        ActivateReputationListsProtectionParam:
          props.parameters.activateReputationListsProtection,
        ActivateBadBotProtectionParam:
          props.parameters.activateBadBotProtection,
        ActivateAWSManagedRulesParam: props.parameters.activateAWSManagedRules,
        ActivateAWSManagedAPParam: props.parameters.activateAWSManagedAP,
        ActivateAWSManagedKBIParam: props.parameters.activateAWSManagedKBI,
        ActivateAWSManagedIPRParam: props.parameters.activateAWSManagedIPR,
        ActivateAWSManagedAIPParam: props.parameters.activateAWSManagedAIP,
        ActivateAWSManagedSQLParam: props.parameters.activateAWSManagedSQL,
        ActivateAWSManagedLinuxParam: props.parameters.activateAWSManagedLinux,
        ActivateAWSManagedPOSIXParam: props.parameters.activateAWSManagedPOSIX,
        ActivateAWSManagedWindowsParam:
          props.parameters.activateAWSManagedWindows,
        ActivateAWSManagedPHPParam: props.parameters.activateAWSManagedPHP,
        ActivateAWSManagedWPParam: props.parameters.activateAWSManagedWP,
        KeepDataInOriginalS3Location:
          props.parameters.keepDataInOriginalS3Location,
        IPRetentionPeriodAllowedParam:
          props.parameters.ipRetentionPeriodAllowed,
        IPRetentionPeriodDeniedParam: props.parameters.ipRetentionPeriodDenied,
        SNSEmailParam: Fn.conditionIf(props.snsEmail.logicalId, "yes", "no"),
        UserDefinedAppAccessLogBucketPrefixParam: Fn.conditionIf(
          props.userDefinedAppAccessLogBucketPrefix.logicalId,
          "yes",
          "no",
        ),
        AppAccessLogBucketLoggingStatusParam:
          props.parameters.appAccessLogBucketLoggingStatus,
        RequestThresholdByCountryParam: Fn.conditionIf(
          props.requestThresholdByCountry.logicalId,
          "yes",
          "no",
        ),
        HTTPFloodAthenaQueryGroupByParam:
          props.parameters.httpFloodAthenaQueryGroupBy,
        AthenaQueryRunTimeScheduleParam:
          props.parameters.athenaQueryRunTimeSchedule,
        WAFWebACL: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFWebACL_OUTPUT,
        ),
        WAFWhitelistSetIPV4: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFWhitelistSetV4Id_OUTPUT,
        ),
        WAFBlacklistSetIPV4: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFBlacklistSetV4Id_OUTPUT,
        ),
        WAFHttpFloodSetIPV4: Fn.conditionIf(
          props.httpFloodProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFHttpFloodSetV4Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFScannersProbesSetIPV4: Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFScannersProbesSetV4Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFReputationListsSetIPV4: Fn.conditionIf(
          props.reputationListsProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFReputationListsSetV4Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFBadBotSetIPV4: Fn.conditionIf(
          props.badBotProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFBadBotSetV4Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFWhitelistSetIPV6: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFWhitelistSetV6Id_OUTPUT,
        ),
        WAFBlacklistSetIPV6: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.WAFBlacklistSetV6Id_OUTPUT,
        ),
        WAFHttpFloodSetIPV6: Fn.conditionIf(
          props.httpFloodProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFHttpFloodSetV6Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFScannersProbesSetIPV6: Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFScannersProbesSetV6Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFReputationListsSetIPV6: Fn.conditionIf(
          props.reputationListsProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFReputationListsSetV6Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFBadBotSetIPV6: Fn.conditionIf(
          props.badBotProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.WAFBadBotSetV6Id_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFWhitelistSetIPV4Name: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.NameWAFWhitelistSetV4_OUTPUT,
        ),
        WAFBlacklistSetIPV4Name: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.NameWAFBlacklistSetV4_OUTPUT,
        ),
        WAFHttpFloodSetIPV4Name: Fn.conditionIf(
          props.httpFloodProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameHttpFloodSetV4_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFScannersProbesSetIPV4Name: Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameScannersProbesSetV4_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFReputationListsSetIPV4Name: Fn.conditionIf(
          props.reputationListsProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameReputationListsSetV4_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFBadBotSetIPV4Name: Fn.conditionIf(
          props.badBotProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameBadBotSetV4_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFWhitelistSetIPV6Name: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.NameWAFWhitelistSetV6_OUTPUT,
        ),
        WAFBlacklistSetIPV6Name: Fn.getAtt(
          props.webACLStack.nestedStackResource!.logicalId,
          "Outputs." + WebaclNestedstack.NameWAFBlacklistSetV6_OUTPUT,
        ),
        WAFHttpFloodSetIPV6Name: Fn.conditionIf(
          props.httpFloodProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameHttpFloodSetV6_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFScannersProbesSetIPV6Name: Fn.conditionIf(
          props.scannersProbesProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameScannersProbesSetV6_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFReputationListsSetIPV6Name: Fn.conditionIf(
          props.reputationListsProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameReputationListsSetV6_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        WAFBadBotSetIPV6Name: Fn.conditionIf(
          props.badBotProtectionActivated.logicalId,
          Fn.getAtt(
            props.webACLStack.nestedStackResource!.logicalId,
            "Outputs." + WebaclNestedstack.NameBadBotSetV6_OUTPUT,
          ),
          { Ref: "AWS::NoValue" },
        ),
        UUID: props.UUID.getUUID(),
        Region: Aws.REGION,
        RequestThreshold: props.parameters.requestThreshold,
        ErrorThreshold: props.parameters.errorThreshold,
        WAFBlockPeriod: props.parameters.wafBlockPeriod,
        SOLUTION_VERSION: distVersion,
        SendAnonymizedUsageData: props.solutionMapping.findInMap(
          "Data",
          "SendAnonymizedUsageData",
        ),
      },
    });

    const cfnCustomConfigureWebAcl = customConfigureWebAcl.node
      .defaultChild as CfnResource;
    cfnCustomConfigureWebAcl.overrideLogicalId(ConfigureWebAcl.ID);
    cfnCustomConfigureWebAcl.addOverride("DeletionPolicy", undefined);
    cfnCustomConfigureWebAcl.addOverride("UpdateReplacePolicy", undefined);
  }
}
