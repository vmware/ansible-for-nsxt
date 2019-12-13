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
short_description: 'Creates a T-0 Interface via the Policy API endpoint.'
description: "Deploys a T-0 Interface as specified by the deployment config using the Policy API endpoint."
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
    edge:
        description: 'Transport Node name to attach the interface'
        required: false
        type: str
    ipv6_profile_paths:
        description: 'Configuration IPv6 NDRA profile. Only one NDRA profile can be configured.'
        required: false
        type: array of string
    mtu:
        description: 'Maximum transmission unit (MTU) specifies the size of the largest packet that a network protocol 
                      can transmit.'
        required: false
        type: 'int'
        minimum: 64
    segment:
        description: 'Specify Segment to which this interface is connected to.'
        required: true
        type: str
    subnets:
        description: 'Specify IP address and network prefix for interface.'
        required: true
        type: array of InterfaceSubnet
    tags:
        description: 'Opaque identifiers meaningful to the API user'
        required: false
        type: array of Tag
        maximum: 30
    type:
        description: 'Interface type'
        required: false
        choices:
            - EXTERNAL
            - SERVICE
            - LOOPBACK
        default: EXTERNAL
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
- name: Create T0 Interfaces
  nsxt_t0_interfaces:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-INTERFACE-TEST"
    description: "T0 Interface deployment test"
    tier0: "T0-TEST"
    locale_service: "T0-TEST-LOCALE-SERVICES"
    mtu: 1500
    segment: SEGEMENT-TEST
    edge: EDGE-TEST 
    subnets:
      - ip_addresses:
          - "10.1.1.1"
        prefix_len: 24
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


def get_segment_path(**session):
    segment_api_version = '/policy/api/v1'
    segment_endpoint = '/infra/segments'
    session["api_version"] = segment_api_version
    segment_response = get_data(endpoint=segment_endpoint,
                                **session)
    if segment_response:
        return "/infra/segments/" + segment_response["id"]


def get_edge_node_path(name=None, **session):
    edge_node_api_version = '/api/v1'
    edge_node_endpoint = '/transport-nodes'

    session["api_version"] = edge_node_api_version

    edge_node_response = get_data(
        endpoint=edge_node_endpoint,
        **session)
    if edge_node_response:
        edge_cluster_endpoint = '/edge-clusters'

        edge_cluster_response = get_data(endpoint=edge_cluster_endpoint,
                                         **session)
        if edge_cluster_response:
            for edge in edge_node_response["results"]:
                if edge["node_deployment_info"]["display_name"] == name and \
                        edge["node_deployment_info"]["resource_type"] == "EdgeNode":

                    edge_id = edge["node_deployment_info"]["id"]

                    for cluster in edge_cluster_response["results"]:
                        cluster_edges = [cluster_edge["transport_node_id"] for cluster_edge in cluster["members"]]
                        if edge_id in cluster_edges:
                            cluster_id = cluster["id"]
                            edge_path = "/infra/sites/default/enforcement-points/default/edge-clusters/{cluster_id}/" \
                                        "edge-nodes/{edge_id}".format(cluster_id=cluster_id, edge_id=edge_id)
                            return edge_path


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
                         edge=dict(required=False, type='str'),
                         ipv6_profile_paths=dict(required=False, type='list'),
                         mtu=dict(required=True, type='int'),
                         segment=dict(required=True, type='str'),
                         subnets=dict(required=True, type='list'),
                         tags=dict(required=False, type='list'),
                         type=dict(required=False, choices=['EXTERNAL', 'SERVICE', 'LOOPBACK']),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['segment', 'tier0', 'locale_service', 'edge'])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    resource_type = "Tier0Interface"
    locale_service = module.params["locale_service"]
    validate_certs = module.params["validate_certs"]
    tier0 = module.params["tier0"]
    segment = module.params["segment"]
    edge = module.params["edge"]
    display_name = module.params["display_name"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{tier0}/locale-services/{locale_service}/interfaces' \
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

    # check if the interface exists
    current_interfaces = get_data(endpoint=endpoint,
                                  name=display_name,
                                  **session)
    # Handle Object
    if state == "present":

        node_params["segment_path"] = get_segment_path(name=segment,
                                                       **session)
        if module.params.get("edge"):
            node_params["edge_path"] = get_edge_node_path(name=edge,
                                                          **session)

        if current_interfaces:
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

        if not current_interfaces:
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
