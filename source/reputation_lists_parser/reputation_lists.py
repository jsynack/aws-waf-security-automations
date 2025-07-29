#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import os
import urllib.request
import json
import re
import ssl
from urllib.parse import urlparse
from time import sleep
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from lib.waflibv2 import WAFLIBv2
from lib.cfn_response import send_response
from aws_lambda_powertools import Logger, Tracer

logger = Logger(
    level=os.getenv('LOG_LEVEL')
)
tracer = Tracer()
waflib = WAFLIBv2()

delay_between_updates = 5

HTTPS = 'https'

TRUSTED_DOMAINS = [
    'rules.emergingthreats.net',
    'check.torproject.org',
    'spamhaus.org'
]

ALLOWED_CONTENT_TYPES = [
    'text/plain',
    'text/csv'
]

# Find matching ip address ranges from a line
def find_ips(line, prefix=""):
    reg = re.compile('^' + prefix + '\\s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?)')
    ips = re.findall(reg, line)

    return ips
    
# Read each address from source URL
def read_url_list(log, current_list, url, prefix=""):
    try:
        log.info(f"[read_url_list]reading url {url}")
        initial_count = len(current_list)
        
        if not is_url_valid(url):
            return current_list

        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as response:
            if not is_response_valid(response) or response.status != 200:
                return current_list

            for line in response:
                new_ips = find_ips(line.decode("utf-8").strip(), prefix)
                current_list = list(set(current_list) | set(new_ips))
        
        added_count = len(current_list) - initial_count
        log.info(f"[read_url_list]{url}: added {added_count} IPs, total: {len(current_list)}")
    except Exception as e:
        log.error(e)

    return current_list


# Fully qualify each address with network cidr
def process_url_list(log, current_list):
    process_list = []
    for source_ip in current_list:
        try:
            ip_type = "IPV%s" % ip_address(source_ip).version
            if (ip_type == "IPV4"):
                process_list.append(IPv4Network(source_ip).with_prefixlen)
            elif (ip_type == "IPV6"):
                process_list.append(IPv6Network(source_ip).with_prefixlen)
        except Exception:
            try:
                if (ip_network(source_ip)):
                    process_list.append(source_ip)
            except Exception:
                log.debug(source_ip + " not an IP address.")
    return process_list


# push each source_ip into the appropriate IPSet
def populate_ipsets(log, scope, ipset_name_v4, ipset_name_v6, ipset_arn_v4, ipset_arn_v6, current_list):
    addresses_v4 = []
    addresses_v6 = []

    for address in current_list:
        try:
            source_ip = address.split("/")[0]
            ip_type = "IPV%s" % ip_address(source_ip).version
            if ip_type == "IPV4":
                addresses_v4.append(address)
            elif ip_type == "IPV6":
                addresses_v6.append(address)
        except Exception as e:
            log.error(e)

    log.info("[populate_ipsets] Changes in WAF IP set v4")
    waflib.update_ip_set(log, scope, ipset_name_v4, ipset_arn_v4, addresses_v4)
    log.info("[populate_ipsets] Updated IPSet %s with %d IP addresses v4", ipset_name_v4, len(addresses_v4))

    # Sleep for a few seconds to mitigate AWS WAF Update API call throttling issue
    sleep(delay_between_updates)

    log.info("[populate_ipsets] Changes in WAF IP set v6")
    waflib.update_ip_set(log, scope, ipset_name_v6, ipset_arn_v6, addresses_v6)
    log.info("[populate_ipsets] Updated IPSet %s with %d IP addresses v6", ipset_name_v6, len(addresses_v6))


def is_scheme_valid(parsed_url):
    """Check if URL scheme is HTTPS."""
    return parsed_url.scheme == HTTPS

def is_domain_trusted(domain):
    """Check if domain is in trusted domains list."""
    return any(domain.endswith(trusted_domain) for trusted_domain in TRUSTED_DOMAINS)

def is_url_valid(url):
    """Check if URL scheme and domain are trusted."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return is_scheme_valid(parsed_url) and is_domain_trusted(domain)
    except Exception as e:
        logger.error(f"URL validation error: {str(e)}")
        return False

def validate_content_type(response):
    """Check if the response has a valid Content-Type header."""
    content_type = response.headers.get('Content-Type', '').split(';')[0]
    return content_type and content_type in ALLOWED_CONTENT_TYPES

def has_nosniff_header(response):
    """Check if the response has X-Content-Type-Options: nosniff header."""
    x_content_type = response.headers.get('X-Content-Type-Options', '').lower()
    return x_content_type == 'nosniff'

def is_response_valid(response):
    """Check if response has valid headers."""
    return validate_content_type(response) or has_nosniff_header(response)

# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    logger.info('[lambda_handler] Start')

    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    current_list = []
    try:
        scope = os.getenv('SCOPE')
        ipset_name_v4 = os.getenv('IP_SET_NAME_REPUTATIONV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_REPUTATIONV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_REPUTATIONV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_REPUTATIONV6')
        URL_LIST = os.getenv('URL_LIST')
        url_list = json.loads(URL_LIST)

        logger.info("SCOPE = %s", scope)
        logger.info("ipset_name_v4 = %s", ipset_name_v4)
        logger.info("ipset_name_v6 = %s", ipset_name_v6)
        logger.info("ipset_arn_v4 = %s", ipset_arn_v4)
        logger.info("ipset_arn_v6 = %s", ipset_arn_v6)
        logger.info("URLLIST = %s", url_list)
    except Exception as e:
        logger.error(e)
        raise

    try:
        for info in url_list:
            try:
                if("prefix" in info):
                    current_list = read_url_list(logger, current_list, info["url"], info["prefix"])
                else:
                    current_list = read_url_list(logger, current_list, info["url"])
            except Exception as e:
                logger.error(e)
                logger.error("URL info not valid %s", info)
                

        current_list = sorted(current_list, key=str)
        current_list = process_url_list(logger, current_list)

        populate_ipsets(logger, scope, ipset_name_v4, ipset_name_v6, ipset_arn_v4, ipset_arn_v6, current_list)

    except Exception as error:
        logger.error(str(error))
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }
    finally:
        logger.info('[lambda_handler] End')
        if 'ResponseURL' in event:
            resource_id = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
            logger.info("ResourceId %s", resource_id)
            send_response(logger, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result) #NOSONAR needed to send a response of the result
