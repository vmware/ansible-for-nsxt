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
module: nsxt_t0_gw_bgp
short_description: 'Creates a T-0 Gateway BGP via the Policy API endpoint.'
description: "Deploys a T-0 Gateway BGP as specified by the deployment config using the Policy API endpoint."
version_added: ''
author: 'Juan Artiles <juan.artiles@virtustream.com>'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: 'string'
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: 'string'
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: 'string'
    display_name:
        description: 'Identifier to use when displaying entity in logs or GUI. '
        required: true
        type: 'string'
    description:
        description: 'Description of this resource'
        required: false
        type: 'string'
    _revision:
        description: 'The _revision property describes the current revision of the resource. To prevent clients from 
                      overwriting each other's changes, PUT operations must include the current _revision of the 
                      resource, which clients should obtain by issuing a GET operation. If the _revision provided in 
                      a PUT request is missing or stale, the operation will be rejected.'
        required: false
        type: int
    ecmp:
        description: 'Flag to enable ECMP'
        required: false
        type: 'bool'
        default: True
     enabled:
        description: 'Flag to enable BGP configuration. Disabling will stop feature and BGP peering'
        required: false
        type: 'bool'
        default: True
    graceful_restart_config:
        description: 'Configuration field to hold BGP Restart mode and timer.'
        required: false
        type: 'dictionary'
        options: 
            restart_timer:
                description: 'Maximum time taken (in seconds) for a BGP session to be established after a restart.
                             This can be used to speed up routing convergence by its peer in case the BGP speaker
                             does not come back up after a restart. If the session is not re-established within this
                             timer, the receiving speaker will delete all the stale routes from that peer.'
                required: false
                type: 'integer'
            stale_route_timer:
                description: 'Maximum time (in seconds) before stale routes are removed from the RIB 
                             (Routing Information Base) when BGP restarts.'
                required: false
                type: 'integer'
    inter_sr_ibgp:
        description: 'Flag to enable inter SR IBGP configuration. When not specified, inter SR IBGP is automatically 
                     enabled if Tier-0 is created in ACTIVE_ACTIVE ha_mode.' 
        required: false
        type: 'boolean'
    local_as_num:
        description: 'Specify BGP AS number for Tier-0 to advertize to BGP peers. AS number can be specified in ASPLAIN 
                     (e.g., "65546") or ASDOT (e.g., "1.10") format. Empty string disables BGP feature.'
        required: True
        type: 'string'
    multipath_relax:
        description: 'Flag to enable BGP multipath relax option.'
        required: False
        type: 'boolean'
        default: True
    route_aggregations:
        description: 'List of routes to be aggregated'
        required: False
        type: 'array of RouteAggregationEntry'
    tags:
        description: Opaque identifiers meaningful to the API user
        type: array of Tag
        required: false  
'''

EXAMPLES = '''
---
- name: Create T0 GW BGP
  nsxt_t0_gw_bgp:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-BGP-TEST"
    description: "T0 BGP deployment test"
    tier0: "T0-TEST"
    locale_service: "T0-TEST-LOCALE-SERVICES"
    local_as_num: "65000"
    graceful_restart_config:
      mode: "GR_AND_HELPER"
    enabled: true
    ecmp: true
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
                         local_as_num=dict(required=True, type='str'),
                         ecmp=dict(required=False, type='bool'),
                         enabled=dict(required=False, type='bool'),
                         graceful_restart_config=dict(required=False, type='dict',
                                                      mode=dict(required=False, choices=["DISABLE", "GR_AND_HELPER",
                                                                                         "HELPER_ONLY"]),
                                                      timer=dict(required=False, type='dict',
                                                                 restart_timer=dict(required=False, type='int'),
                                                                 stale_route_timer=dict(required=False, type='int')
                                                                 )

                                                      ),
                         inter_sr_ibgp=dict(required=False, type='bool'),
                         multipath_relax=dict(required=False, type='bool'),
                         route_aggregations=dict(required=False, type='list'),
                         tier0=dict(required=True, type='str'),
                         locale_service=dict(required=True, type='str'),
                         tags=dict(required=False, type='list'),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['tier0', 'locale_service'])
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    tier0 = module.params['tier0']
    locale_service = module.params['locale_service']
    display_name = node_params['display_name']
    validate_certs = module.params["validate_certs"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{tier0}/locale-services/{locale_service}/bgp' \
        .format(tier0=tier0, locale_service=locale_service)
    resource_type = "BgpRoutingConfig"

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

    # Check Local Service exists
    locale_service_endpoint = '/infra/tier-0s/{}/locale-services'.format(tier0)
    get_data(endpoint=locale_service_endpoint,
             name=locale_service,
             error_on_missing=True,
             **session)

    object_response = create_data(endpoint=endpoint,
                                  resource_type=resource_type,
                                  payload=node_params,
                                  update=True,
                                  add_name=False,
                                  **session)

    module.exit_json(changed=True,
                     debug_out="{resource_type} {display_name} has been successfully created"
                     .format(resource_type=resource_type, display_name=display_name),
                     response=object_response)


if __name__ == "__main__":
    main()
