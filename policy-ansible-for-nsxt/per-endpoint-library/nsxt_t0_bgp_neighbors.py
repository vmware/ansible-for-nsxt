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
module: nsxt_t0_interface
short_description: 'Creates a T-0 BGP neighbor entry via the Policy API endpoint.'
description: "Deploys a T-0 BGP Neighbor as specified by the deployment config using the Policy API endpoint."
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
        type: 'str
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
    tier0:
        description: 'Name of the Tier-0 Router'
        required: true
        type: 'str'
    locale_service:
        description: 'Locale Service attached to Tier-0'
        required: true
        type: 'str'
    allow_as_in:
        description: 'Flag to enable allowas_in option for BGP neighbor'
        required: false
        type: 'boolean'
        default: True
    bfd:
        description: 'BFD configuration for failure detection. BFD is enabled with default values when not configured.'
        required: false
        type: 'dictionary'
        options:
            enabled: 
                description: 'Flag to enable BFD cofiguration.'
                type: 'boolean'
                required: false
                default: True
            interval:
                description: 'Time interval between heartbeat packets in milliseconds.'
                type: 'int'
                required: false
                minimum: 300
                maximum: 60000
                default: 1000
            multiple:
                description: 'Declare dead multiple. Number of times heartbeat packet is missed before BFD declares the
                             neighbor is down.'
                type: 'int'
                required: false
                minimum: 2
                maximum: 16
                default: 3
    graceful_restart_mode:
        description: 'If mode is DISABLE, then graceful restart and helper modes are disabled. If mode is 
        GR_AND_HELPER, 
                     then both graceful restart and helper modes are enabled. If mode is HELPER_ONLY, then helper mode 
                     is enabled. HELPER_ONLY mode is the ability for a BGP speaker to indicate its abilit to preserve 
                     forwarding state during BGP restart. GRACEFUL_RESTART mode is the ability of a BGP speaker to 
                     advertise its restart to its peers.'
        required: false
        type: 'string'
        choices:
            - DISABLE
            - GR_AND_HELPER
            - HELPER_ONLY
    hold_down_time:
        description: 'Wait time in seconds before declaring peer dead.'
        required: false
        type: 'int'
        minimum: 1
        maximum: 65535
        default: 180
    keep_alive_time:
        description: 'Interval (in seconds) between keep alive messages sent to peer.'
        required: false
        type: 'int'
        minimum: 1
        maximum: 65535
        default: 60
    maximum_hop_limit:
        description: 'Maximum number of hops allowed to reach BGP neighbor'
        required: false
        type: 'int'
        minimum: 1
        maximum: 255
        default: 1
    neighbor_address:
        description: 'Neighbor IP Address'
        required: true
        type: IPAddress
    bgp_password:
        description: 'Specify password for BGP neighbor authentication. Empty string ("") clears existing password.'
        required: false
        type: "string
    remote_as_num:
        description: '4 Byte ASN of the neighbor in ASPLAIN Format'
        required: true
        type: 'string'
    route_filtering:
        description: 'Enable address families and route filtering in each direction.'
        required: false
        type: 'array of BgpRouteFiltering'
        Maximum items: 1
    source_addresses:
        description: 'Source addresses should belong to Tier0 external or loopback interface IP Addresses . BGP peering 
                     is formed from all these addresses. This property is mandatory when maximum_hop_limit is greater 
                     than 1.'
        required: false
        type: 'array of IPAddress'
        Maximum items: 8         
    tags:
        description: 'Opaque identifiers meaningful to the API user'
        required: false
        type: 'array of Tag'
        maximum: 30
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'. 'present' is used to create or update resource.
                     'absent' is used to delete resource."
        required: true
    
'''

EXAMPLES = '''
  ---
- name: Create T0 Interfaces
  nsxt_t0_bgp_neighbors:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-BGP-NEIGHBOR-TEST"
    description: "T0 BGP Neighbor deployment test"
    tier0: "T0-TEST"
    locale_service: "T0-TEST-LOCALE-SERVICES"
    remote_as_num: "65000"
    neighbor_address: "10.1.1.3"
    source_addresses:
      - "10.1.1.1"
      - "10.1.1.2"
    route_filtering:
      - address_family: IPV4
        out_route_filters:
          - RMAP-ALLOW-RFC1918
        enabled: true
    enabled: true
    state: present
'''


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
    get_status, neighbors = create_nsxt_object(**session)
    if not get_status:

        if neighbors["type"] == "error":
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                status_code=neighbors["response"].status_code,
                text=neighbors["response"].text,
                url=neighbors["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                error=neighbors["response"]
            )
    return neighbors["data"]


def delete_data(module, **session):
    delete_status, neighbors = delete_nsxt_object(**session)
    if not delete_status:
        if neighbors["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=neighbors["response"].status_code,
                text=neighbors["response"].text,
                url=neighbors["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=neighbors["response"]
            )
    return neighbors["data"]


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         tier0=dict(required=True, type='str'),
                         locale_service=dict(required=True, type='str'),
                         allow_as_in=dict(required=False, type='bool'),
                         bfd=dict(required=False, type='dict',
                                  enabled=dict(required=False, type='bool'),
                                  interval=dict(required=False, type='int'),
                                  multiple=dict(required=False, type='int')
                                  ),
                         graceful_restart_mode=dict(required=False, choices=['DISABLE',
                                                                             'GR_AND_HELPER',
                                                                             'HELPER_ONLY'
                                                                             ]
                                                    ),
                         hold_down_time=dict(required=False, type='int'),
                         keep_alive_time=dict(required=False, type='int'),
                         maximum_hop_limit=dict(required=False, type='int'),
                         neighbor_address=dict(required=True, type='str'),
                         bgp_password=dict(required=False, type='str', no_log=True),
                         remote_as_num=dict(required=True, type='str'),
                         route_filtering=dict(required=False, type='list'),
                         source_addresses=dict(required=False, type='list'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['tier0', 'locale_service'])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    resource_type = "Tier0Interface"
    locale_service = module.params["locale_service"]
    tier0 = module.params["tier0"]
    route_filtering = module.params["route_filtering"]
    validate_certs = module.params["validate_certs"]
    display_name = module.params["display_name"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{tier0}/locale-services/{locale_service}/bgp/neighbors' \
        .format(tier0=tier0, locale_service=locale_service)

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

    prefix_list_endpoint = '/infra/tier-0s/{tier0}/prefix-lists'.format(tier0=tier0)
    route_maps_endpoint = '/infra/tier-0s/{tier0}/route-maps'.format(tier0=tier0)

    # Check if each route_filtering prefix_list or route_map exists
    for entry in route_filtering:

        if entry.get("out_route_filters"):

            out_route_filters = []
            for prefix in entry.get("out_route_filters"):

                prefix_list_data = get_data(endpoint=prefix_list_endpoint,
                                            name=prefix,
                                            **session)

                if prefix_list_data:
                    out_route_filters.append("/infra/tier-0s/{}/prefix-lists/{}".format(tier0, prefix))
                else:
                    route_map_data = get_data(endpoint=route_maps_endpoint,
                                              name=prefix,
                                              **session)
                    if route_map_data:
                        out_route_filters.append("/infra/tier-0s/{}/route-maps/{}".format(tier0, prefix))

            node_params["route_filtering"][route_filtering.index(entry)]["out_route_filters"] = out_route_filters

        if entry.get("in_route_filters"):

            in_route_filters = []
            for prefix in entry.get("in_route_filters"):

                prefix_list_data = get_data(endpoint=prefix_list_endpoint,
                                            name=prefix,
                                            **session)

                if prefix_list_data:
                    in_route_filters.append("/infra/tier-0s/{}/prefix-lists/{}".format(tier0, prefix))
                else:
                    route_map_data = get_data(endpoint=route_maps_endpoint,
                                              name=prefix,
                                              **session)
                    if route_map_data:
                        in_route_filters.append("/infra/tier-0s/{}/route-maps/{}".format(tier0, prefix))

            node_params["route_filtering"][route_filtering.index(entry)]["in_route_filters"] = in_route_filters

    # check if the neigbor exists
    current_neighbors = get_data(endpoint=endpoint,
                                 name=display_name,
                                 **session)

    # Handle Object
    if state == "present":

        if current_neighbors:
            module.exit_json(changed=False,
                             message="{resource_type} {display_name} already exists".format(
                                 resource_type=resource_type,
                                 display_name=display_name)
                             )

        create_neighbor = create_data(endpoint=endpoint,
                                      resource_type=resource_type,
                                      payload=node_params,
                                      add_name=True,
                                      update=True,
                                      **session)
    elif state == "absent":

        if not current_neighbors:
            module.exit_json(changed=False,
                             message="{} with name {} not found".format(resource_type,
                                                                        display_name)
                             )
        delete_data(endpoint=endpoint,
                    name=display_name,
                    **session
                    )

    module.exit_json(changed=True,
                     msg="{resource_type} {display_name} is now {state}"
                     .format(resource_type=resource_type, display_name=display_name,
                             state=state),
                     )


if __name__ == "__main__":
    main()
