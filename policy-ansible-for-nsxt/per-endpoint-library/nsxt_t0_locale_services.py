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
module: nsxt_t0_locale_services
short_description: 'Creates a T-0 Locale Service via the Policy API endpoint.'
description: "Deploys a T-0 Locale Service as specified by the deployment config using the Policy API endpoint."
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
    edge_cluster_path:
        description: 'Policy path to edge cluster. Auto-assigned on Tier0 if associated enforcement-point has only one 
                      edge cluster.'
        required: false
        type: 'string'
    ha_vip_configs:
        description: 'This configuration can be defined only for Active-Standby Tier0 gateway to provide redundancy. 
                      For mulitple external interfaces, multiple HA VIP configs must be defined and each config will 
                      pair exactly two external interfaces. The VIP will move and will always be owned by the Active 
                      node. When this property is configured, configuration of dynamic-routing is not allowed.'
        required: false
        type: array of Tier0HaVipConfig
    preferred_edge_paths:
        description: 'Policy paths to edge nodes. Specified edge is used as preferred edge cluster member when failover 
                      mode is set to PREEMPTIVE, not applicable otherwise.'
        required: false
        type: array of string
    route_redistribution_types:
        description: 'Enable redistribution of different types of routes on Tier-0. This property is only valid for 
                      locale-service under Tier-0.'
        required: false
        type: array of Tier0RouteRedistributionTypes
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
- name: Create T0 Locale Services
  nsxt_t0_locale_services:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    tier0: "TEST-T0"
    display_name: "TEST-T0-LOCALE-SERVICES"
    edge_cluster: "TEST-CLSTR"
    route_redistribution_types:
      - TIER0_STATIC
      - TIER0_CONNECTED
      - TIER0_EXTERNAL_INTERFACE
      - TIER0_SEGMENT
      - TIER0_ROUTER_LINK
      - TIER0_SERVICE_INTERFACE
      - TIER0_LOOPBACK_INTERFACE
      - TIER0_DNS_FORWARDER_IP
      - TIER0_IPSEC_LOCAL_IP
      - TIER0_NAT
      - TIER1_NAT
      - TIER1_STATIC
      - TIER1_LB_VIP
      - TIER1_LB_SNAT
      - TIER1_DNS_FORWARDER_IP
      - TIER1_CONNECTED
      - TIER1_SERVICE_INTERFACE
      - TIER1_SEGMENT
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


def get_edge_cluster_path(**session):
    api_version = '/api/v1'
    endpoint = '/edge-clusters'
    edge_cluster_response = get_data(endpoint=endpoint,
                                     api_version=api_version,
                                     error_on_missing=True,
                                     **session)
    if edge_cluster_response:
        return "/infra/sites/default/enforcement-points/default/edge-clusters/" + \
               edge_cluster_response["id"]


def get_edge_node_paths(cluster, edge_nodes, **session):
    edge_node_endpoint = '/transport-nodes'
    edge_cluster_endpoint = '/edge-clusters'

    edge_cluster_response = get_nsxt_object(endpoint=edge_cluster_endpoint,
                                            name=cluster,
                                            error_on_missing=True,
                                            **session)

    edge_node_response = get_nsxt_object(endpoint=edge_node_endpoint,
                                         error_on_missing=True,
                                         **session
                                         )

    if edge_cluster_response:
        cluster_edges = [cluster_edge["transport_node_id"] for cluster_edge in edge_cluster_response["data"]["members"]]

        if edge_node_response:
            edge_node_paths = []
            for edge in edge_node_response["response"]:
                if edge["node_deployment_info"]["display_name"] in edge_nodes and \
                        edge["node_deployment_info"]["resource_type"] == "EdgeNode":
                    edge_id = edge["node_deployment_info"]["id"]

                    if edge_id in cluster_edges:
                        cluster_id = edge_cluster_response["data"]["id"]
                        edge_path = "/infra/sites/default/enforcement-points/default/edge-clusters/{cluster_id}/" \
                                    "edge-nodes/{edge_id}".format(cluster_id=cluster_id, edge_id=edge_id)
                        edge_node_paths.append(edge_path)
            return edge_node_paths


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         tier0=dict(required=True, type='str'),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         edge_cluster=dict(required=False, type='str'),
                         ha_vip_configs=dict(required=False, type='list'),
                         preferred_edges=dict(required=False, type='list'),
                         route_redistribution_types=dict(required=False, type='list'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['tier0', 'edge_cluster', "preferred_edges"])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    resource_type = "LocaleServices"
    tier0 = module.params['tier0']
    cluster = module.params.get("edge_cluster")
    edge_cluster = module.params.get('edge_cluster')
    validate_certs = module.params["validate_certs"]
    display_name = module.params["display_name"]
    preferred_edges = module.params.get('preferred_edges')
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{}/locale-services'.format(tier0)

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

    # check if the locale_services exists
    current_locale_services = get_data(endpoint=endpoint,
                                       name=display_name,
                                       api_version=api_version,
                                       **session)

    # Handle Object
    if state == "present":

        if edge_cluster:
            node_params["edge_cluster_path"] = get_edge_cluster_path(name=cluster,
                                                                     **session
                                                                     )

            if preferred_edges:
                node_params["preferred_edge_paths"] = get_edge_node_paths(cluster=edge_cluster,
                                                                          edge_nodes=preferred_edges,
                                                                          **session)

        elif not edge_cluster and preferred_edges:
            module.fail_json(
                msg="Edge Cluster is required when defining a Preferred Edges"
            )

        if current_locale_services:
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

        if not current_locale_services:
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
