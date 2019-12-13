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
from ansible.module_utils.nsxt_utils import get_params, get_nsxt_object, create_nsxt_object, \
    delete_nsxt_object
from ansible.module_utils.rest_functions import Rest
from ansible.module_utils.vmware_nsxt import vmware_argument_spec

__metaclass__ = type
__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_segments
short_description: 'Creates a Segment via the Policy API endpoint.'
description: "Deploys a Segment as specified by the deployment config using the Policy API endpoint."
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
    advanced_config:
        description: Advanced configuration for Segment.
        type: dictionary
        required: false
        options:
            address_pool_paths:
                description: Policy path to IP address pools
                required: false
                type: array of string
            connectivity: 
                description: Connectivity configuration to manually connect (ON) or disconnect (OFF) a logical entity 
                             from network topology
                required: false
                type: string
                choices:
                    - ON
                    - OFF
                default: OFF
            hybrid:
                description: When set to true, all the ports created on this segment will behave in a hybrid fashion. 
                             The hybrid port indicates to NSX that the VM intends to operate in underlay mode, but 
                             retains the ability to forward egress traffic to the NSX overlay network. This property is 
                             only applicable for segment created with transport zone type OVERLAY_STANDARD. This 
                             property cannot be modified after segment is created.
                type: boolean
                required: false
                default: false
            local_egress: 
                description: This property is used to enable proximity routing with local egress. When set to true, 
                             logical router interface (downlink) connecting Segment to Tier0/Tier1 gateway is 
                             configured with prefix-length 32.
                required: false
                type: boolean
                default: false
    connectivity_path:
        description: Policy path to the connecting Tier-0 or Tier-1. Valid only for segments created under Infra.
        type: string
        required: false
    domain_name:
        description: DNS domain name
        type: string
        required: false
    l2_extension:
        description: Configuration for extending Segment through L2 VPN.
        type: dictionary
        required: false
        options:
            l2vpn_paths:
                description: Policy paths corresponding to the associated L2 VPN sessions
                type: array of string
                required: false
            tunnel_id:
                description: Tunnel ID
                type: integer
                required: false
    overlay_id:
        description: Used for overlay connectivity of segments. The overlay_id should be allocated from the pool as 
                     definied by enforcement-point. If not provided, it is auto-allocated from the default pool on the 
                     enforcement-point.
        type: int
        required: false
    subnets:
        description: Subnet configuration. Max 1 subnet
        type: array of SegmentSubnet
        required: false
    tags:
        description: Opaque identifiers meaningful to the API user
        type: array of Tag
        required: false
    transport_zone: 
        description: Supported for VLAN backed segments as well as Overlay Segments. This field is required for VLAN 
                     backed Segments. Auto assigned if only one transport zone exists in the enforcement point. Default 
                     transport zone is auto assigned for overlay segments if none specified.
        type: string
        required: false
    vlan_ids:
        description: VLAN ids for a VLAN backed Segment. Can be a VLAN id or a range of VLAN ids specified with '-' 
                     in between.
        type: array of string
        required: false     
'''

EXAMPLES = '''
- name: Create Segment
  nsxt_segments:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: "test-segment"
    subnets: 
    - gateway_address: "40.1.1.1/16"
      dhcp_ranges:
      - "40.1.2.0/24"
    vlan_ids:
    - 100
    - 200
    state: "present"
'''

RETURN = '''# '''


def get_data(module, error_on_missing=False, **session):
    get_status, segments = get_nsxt_object(**session)
    data = segments["data"]
    if not get_status and error_on_missing:
        if segments["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=segments["response"].status_code,
                text=segments["response"].text,
                url=segments["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=segments["response"]
            )

    return data


def create_data(module, **session):
    get_status, segments = create_nsxt_object(**session)
    if not get_status:

        if segments["type"] == "error":
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                status_code=segments["response"].status_code,
                text=segments["response"].text,
                url=segments["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                error=segments["response"]
            )
    return segments["data"]


def delete_data(module, **session):
    delete_status, segments = delete_nsxt_object(**session)
    if not delete_status:
        if segments["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=segments["response"].status_code,
                text=segments["response"].text,
                url=segments["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=segments["response"]
            )
    return segments["data"]


def get_transport_zone_path(**session):
    transport_zone_api_version = '/api/v1'
    transport_zone_endpoint = '/transport-zones'
    session["api_version"] = transport_zone_api_version
    transport_zone_response = get_data(endpoint=transport_zone_endpoint,
                                       **session)
    if transport_zone_response:
        return "/infra/sites/default/enforcement-points/default/transport-zones/" + \
               transport_zone_response["id"]


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         advanced_config=dict(required=False, type='dict',
                                              address_pool_paths=dict(required=False, type='list'),
                                              connectivity=dict(required=False, choices=['ON', 'OFF']),
                                              hybrid=dict(required=False, type='bool'),
                                              local_egress=dict(required=False, type='bool')
                                              ),
                         connectivity_path=dict(required=False, type='str'),
                         domain_name=dict(required=False, type='str'),
                         l2_extension=dict(required=False, type='dict',
                                           l2vpn_paths=dict(required=False, type='list'),
                                           tunnel_id=dict(required=False, type='int')
                                           ),
                         overlay_id=dict(required=False, type='int'),
                         subnets=dict(required=False, type='list'),
                         tags=dict(required=False, type='list'),
                         transport_zone=dict(required=False, type='str'),
                         vlan_ids=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['transport_zone'])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    display_name = module.params["display_name"]
    validate_certs = module.params["validate_certs"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/segments'
    resource_type = "Segment"
    transport_zone = module.params['transport_zone']

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   api_version=api_version,
                   module=module,
                   client=client,
                   )

    # check if the segment exists
    current_segments = get_data(endpoint=endpoint,
                                name=display_name,
                                **session)

    if state == "present":

        if current_segments:
            module.exit_json(changed=False,
                             message="Segment with name {} already exists".format(display_name)
                             )
        node_params["transport_zone_path"] = get_transport_zone_path(name=transport_zone,
                                                                     **session)

        create_segment = create_data(endpoint=endpoint,
                                     resource_type=resource_type,
                                     payload=node_params,
                                     add_name=True,
                                     update=True,
                                     **session)
    elif state == "absent":

        if not current_segments:
            module.exit_json(changed=False,
                             message="Segment with name {} not found".format(display_name)
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
