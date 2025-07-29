#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

##############################################################################
##############################################################################

import os
from dataclasses import dataclass
from typing import Dict

@dataclass
class Config:
    rules: Dict[str, str]   # { rule_name: rule_id }
    web_acl: str
    region: str
    metrics_url: str
    uuid: str
    log_level: str
    solution_id: str 
    solution_version: str
    enable_metrics: bool
    user_agent_extra: str
    metrics_frequency_hours: int
    waf_endpoint_type: str


def load_config() -> Config:
    prefix = os.environ.get('METRICS_NAME_PREFIX')
    rule_names_str = os.environ.get('RULE_NAMES')

    # Split and strip each rule name
    rule_names = [name.strip() for name in rule_names_str.split(',') if name.strip()]

    # Create mapping: rule_name -> rule_id
    rules = {name: prefix + name for name in rule_names}

    # Check if metrics are enabled
    enable_metrics = os.environ.get("SEND_ANONYMIZED_USAGE_DATA", "yes").strip().lower() == "yes"

    return Config(
        rules=rules,
        web_acl=os.environ['WEB_ACL_NAME'],
        region=os.environ.get('AWS_REGION'),
        metrics_url=os.environ['METRICS_URL'],
        uuid=os.environ['UUID'],
        log_level=os.environ.get('LOG_LEVEL', 'INFO'),
        solution_id=os.environ['SOLUTION_ID'],
        solution_version=os.environ['SOLUTION_VERSION'],
        enable_metrics=enable_metrics,
        user_agent_extra=os.environ.get('USER_AGENT_EXTRA'),
        metrics_frequency_hours=int(os.environ.get('METRICS_FREQUENCY_HOURS', '24')),
        waf_endpoint_type=os.environ.get('WAF_ENDPOINT_TYPE')
    )
