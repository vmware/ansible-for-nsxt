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
module: nsxt_t0_prefix_list
short_description: 'Creates a T-0 Prefix-list via the Policy API endpoint.'
description: "Deploys a T-0 Prefix-list as specified by the deployment config using the Policy API endpoint."
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
        description: 'DHCP configuration for Segments connected to Tier-0. DHCP service is configured in relay mode.'
        required: false
        type: 'array of strings'
    failover_mode:
        description: 'etermines the behavior when a Tier-0 instance in ACTIVE-STANDBY high-availability mode restarts 
                      after a failure. If set to PREEMPTIVE, the preferred node will take over, even if it causes 
                      another failure. If set to NON_PREEMPTIVE, then the instance that restarted will remain secondary.
                      This property must not be populated unless the ha_mode property is set to ACTIVE_STANDBY.'
        required: false
        choices:
            - PREEMPTIVE
            - NON_PREEMPTIVE
        default: NON_PREEMPTIVE 
    ha_mode:
        description: 'Specify high-availability mode for Tier-0. Default is ACTIVE_ACTIVE.'
        required: false
        choices:
            - ACTIVE_ACTIVE
            - ACTIVE_STANDBY
        default: ACTIVE_ACTIVE
    internal_transit_subnets:
        description: 'Specify subnets that are used to assign addresses to logical links connecting service routers and 
                      distributed routers. Only IPv4 addresses are supported. When not specified, subnet 169.254.0.0/24 
                      is assigned by default in ACTIVE_ACTIVE HA mode or 169.254.0.0/28 in ACTIVE_STANDBY mode.'
        required: false
        type: str
    ipv6_profile_paths:
        description: 'IPv6 NDRA and DAD profiles configuration on Tier0. Either or both NDRA and/or DAD profiles can be 
                      configured.'
        required: false
        type: 'array of strings'
    transit_subnets:
        description: 'Specify transit subnets that are used to assign addresses to logical links connecting tier-0 and 
                      tier-1s. Both IPv4 and IPv6 addresses are supported. When not specified, subnet 100.64.0.0/16 is 
                      configured by default.'
        required: false
        type: array of string
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
- name: Create T0 GW Prefix Lists
  nsxt_t0_gw_prefix_lists::
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-TEST-PEFIX-LIST"
    description: "T0 prefix-list deployment test"
    prefixes:
      - action: PERMIT
        le: 32
        ge: 12
        network: 172.16.0.0/12
      - action: PERMIT
        le: 32
        ge: 16
        network: 192.168.0.0/16
      - action: PERMIT
        le: 32
        ge: 8
        network: 10.0.0.0/8
    tier0: "T0-TEST"
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
                         tier0=dict(required=True, type='str'),
                         prefixes=dict(required=True, type='list'),
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
    tier0 = module.params['tier0']
    display_name = node_params['display_name']
    validate_certs = module.params["validate_certs"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{tier0}/prefix-lists'.format(tier0=tier0)
    resource_type = "PrefixList"

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   module=module,
                   client=client,
                   api_version=api_version
                   )

    # Check T0 exists
    tier0_endpoint = '/infra/tier-0s'
    get_data(endpoint=tier0_endpoint,
             name=tier0,
             error_on_missing=True,
             **session)

    # check if the neigbor exists
    current_prefix = get_data(endpoint=endpoint,
                              name=display_name,
                              **session)

    # Handle Object
    if state == "present":

        if current_prefix:
            module.exit_json(changed=False,
                             message="{resource_type} {display_name} already exists".format(
                                 resource_type=resource_type,
                                 display_name=display_name)
                             )

        request = create_data(endpoint=endpoint,
                              resource_type=resource_type,
                              payload=node_params,
                              add_name=True,
                              update=True,
                              **session)
    elif state == "absent":

        if not current_prefix:
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
