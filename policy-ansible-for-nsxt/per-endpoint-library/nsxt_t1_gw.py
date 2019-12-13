#!/usr/bin/python
#
# Copyright (c) 2008-2020 Virtustream Corporation
# All Rights Reserved
#
# This software contains the intellectual property of Virtustream Corporation
# or is licensed to Virtustream Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of Virtustream.

from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_utils import get_params, get_nsxt_object, create_nsxt_object, delete_nsxt_object
from ansible.module_utils.rest_functions import Rest
from ansible.module_utils.vmware_nsxt import vmware_argument_spec

__metaclass__ = type
__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_t1_gw
short_description: 'Creates a T-0 Gateway via the Policy API endpoint.'
description: "Deploys a T-0 Gateway as specified by the deployment config using the Policy API endpoint."
version_added: ''
author: 'Juan Artiles <juan.artiles@virtustream.com>'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: 'tr
    display_name:
        description: 'Identifier to use when displaying entity in logs or GUI. '
        required: true
        type: str
    description:
        description: 'Description of this resource'
        required: false
        type: str
    _revision:
        description: 'The _revision property describes the current revision of the resource. To prevent clients from 
                      overwriting each other's changes, PUT operations must include the current _revision of the 
                      resource, which clients should obtain by issuing a GET operation. If the _revision provided in 
                      a PUT request is missing or stale, the operation will be rejected.'
        required: false
        type: int
    dhcp_config_paths:
        description: 'DHCP configuration for Segments connected to Tier-1. DHCP service is enabled in relay mode.'
        required: false
        type: 'array of strings'
    disable_firewall: 
        description: 'Disable or enable gateway fiewall.'
        required: false
        type: 'boolean'
        default: False
    enable_standby_relocation: 
        description: 'Flag to enable standby service router relocation. Standby relocation is not enabled until edge 
                     cluster is configured for Tier1.'
        required: false
        type: 'boolean'
        default: False
    failover_mode:
        description: 'Determines the behavior when a Tier-1 instance in ACTIVE-STANDBY high-availability mode restarts 
                     after a failure. If set to PREEMPTIVE, the preferred node will take over, even if it causes 
                     another 
                     failure. If set to NON_PREEMPTIVE, then the instance that restarted will remain secondary. This 
                     property must not be populated unless the ha_mode property is set to ACTIVE_STANDBY'
        required: false
        choices:
            - PREEMPTIVE
            - NON_PREEMPTIVE
        default: NON_PREEMPTIVE 
    ipv6_profile_paths:
        description: 'IPv6 NDRA and DAD profiles configuration on Tier1. Either or both NDRA and/or DAD profiles can be 
                      configured.'
        required: false
        type: 'array of strings'
    route_advertisement_rules:
        description: 'Route advertisement rules and filtering'
        required: false
        type: array of RouteAdvertisementRule
    route_advertisement_types:
        description: 'Enable different types of route advertisements. When not specified, routes to IPSec VPN 
                     local-endpoint subnets (TIER1_IPSEC_LOCAL_ENDPOINT) are automatically advertised.'
        required: false
        type: array of Tier1RouteAdvertisentTypes
    tier0:
        description: 'Specify Tier-1 connectivity to Tier-0 instance.'
        required: false
        type: string
    type:
        description: 'Tier1 connectivity type for reference. Property value is not validated with Tier1 configuration.
                     ROUTED: Tier1 is connected to Tier0 gateway and routing is enabled. ISOLATED: Tier1 is not 
                     connected to any Tier0 gateway. NATTED: Tier1 is in ROUTED type with NAT configured locally.'
        required: false
        type: string
        choices:
            - ROUTED
            - ISOLATED
            - 
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true
    
'''

EXAMPLES = '''
  ---
- name: Create T1 GW
  nsxt_t1_gw:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T1-TEST"
    description: "T1 deployment test"
    tier0: "T0-TEST"
    route_advertisement_types:
      - TIER1_STATIC_ROUTES
      - TIER1_CONNECTED
      - TIER1_NAT
      - TIER1_LB_VIP
      - TIER1_LB_SNAT
      - TIER1_DNS_FORWARDER_IP
      - TIER1_IPSEC_LOCAL_ENDPOINT
    state: present
'''

RETURN = '''# '''


def get_data(module, error_on_missing=False, **session):
    get_status, response = get_nsxt_object(**session)
    data = response.get("data")
    if not get_status and error_on_missing:
        if response["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=response["response"]
            )

    return data


def create_data(module, **session):
    get_status, response = create_nsxt_object(**session)
    if not get_status:

        if response["type"] == "error":
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                error=response["response"]
            )
    return response["data"]


def delete_data(module, **session):
    delete_status, response = delete_nsxt_object(**session)
    if not delete_status:
        if response["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=response["response"]
            )
    return response["data"]



def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         dhcp_config_paths=dict(required=False, type='list'),
                         disable_firewall=dict(required=False, type='bool'),
                         enable_standby_relocation=dict(required=False, type='bool'),
                         failover_mode=dict(required=False, choices=['PREEMPTIVE', 'NON_PREEMPTIVE']),
                         force_whitelisting=dict(required=False, type='bool'),
                         ipv6_profile_paths=dict(required=False, type='list'),
                         route_advertisement_rules=dict(required=False, type='list'),
                         route_advertisement_types=dict(required=False, type='list'),
                         tier0=dict(required=False, type='str'),
                         type=dict(required=False, choices=['ROUTED', 'ISOLATED', 'NATTED']),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['tier0'])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    tier0 = module.params.get('tier0')
    validate_certs = module.params["validate_certs"]
    display_name = module.params["display_name"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-1s'
    resource_type = "Tier1"

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   module=module,
                   client=client,
                   )

    # Check T0 exists
    tier0_endpoint = '/infra/tier-0s'
    get_data(endpoint=tier0_endpoint,
             name=tier0,
             error_on_missing=True,
             api_version=api_version,
             **session)

    node_params["tier0_path"] = "{}/{}".format(tier0_endpoint, tier0)

    # check if the T1 exists
    current_t1 = get_data(endpoint=endpoint,
                          name=display_name,
                          api_version=api_version,
                          **session)


    # Handle Object
    if state == "present":

        if current_t1:
            module.exit_json(changed=False,
                             message="{resource_type} {display_name} already exists".format(
                                 resource_type=resource_type,
                                 display_name=display_name)
                             )

        request = create_data(endpoint=endpoint,
                              resource_type=resource_type,
                              api_version=api_version,
                              payload=node_params,
                              add_name=True,
                              update=True,
                              **session)
    elif state == "absent":

        if not current_t1:
            module.exit_json(changed=False, message="{} with name {} not found".format(resource_type,
                                                                                       display_name))
        request = delete_data(endpoint=endpoint,
                              name=display_name,
                              **session
                              )

    module.exit_json(changed=True,
                     msg="{resource_type} {display_name} is now {state}"
                     .format(resource_type=resource_type, display_name=display_name,
                             state=state),
                     response=request
                     )

if __name__ == "__main__":
    main()
