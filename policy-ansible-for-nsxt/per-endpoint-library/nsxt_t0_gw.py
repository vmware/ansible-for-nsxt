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
module: nsxt_t0_gw
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
- name: Create T0 GW
  nsxt_t0_gw:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-TEST"
    description: "T0 deployment test"
    failover_mode: "PREEMPTIVE"
    transit_subnets:
      - "100.64.0.0/16"
    internal_transit_subnets:
      - "169.254.0.0/28"
    ha_mode: "ACTIVE_STANDBY"
    state: "present"
'''

RETURN = '''# '''


def get_data(module, error_on_missing=False, **session):
    get_status, response = get_nsxt_object(**session)
    data = response["data"]
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
                         failover_mode=dict(required=False, choices=['PREEMPTIVE', 'NON_PREEMPTIVE']),
                         ha_mode=dict(required=False, choices=['ACTIVE_ACTIVE', 'ACTIVE_STANDBY']),
                         internal_transit_subnets=dict(required=False, type='list'),
                         ipv6_profile_paths=dict(required=False, type='list'),
                         transit_subnets=dict(required=False, type='list'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    display_name = module.params['display_name']
    validate_certs = module.params["validate_certs"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s'
    resource_type = "Tier0"

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   module=module,
                   client=client,
                   api_version=api_version,
                   )

    # check if the neigbor exists
    current_t0 = get_data(endpoint=endpoint,
                          name=display_name,
                          **session)

    # Handle Object
    if state == "present":

        if current_t0:
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

        if not current_t0:
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
