#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_policy_l2_bridge_ep_profile
short_description: Create or Delete a Policy L2 Bridge Endpoint Profile
description:
    Creates or deletes a Policy L2 Bridge Endpoint Profile
    Required attributes include id and display_name.
version_added: "2.9"
author: Gautam Verma
extends_documentation_fragment:
    - vmware.ansible_for_nsxt.vmware_nsxt
options:
    id:
        description: The id of the Policy L2 Bridge Endpoint Profile
        required: false
        type: str
    description:
        description: Resource description.
        type: str
    edge_nodes_info:
        description:
            - List of dicts that comprise of information to form policy paths
              to edge nodes. Edge allocation for L2 bridging
            - Minimim 1 and Maximum 2 list elements
        type: list
        element: dict
        suboptions:
            site_id:
                description: site_id where edge node is located
                default: default
                type: str
            enforcementpoint_id:
                description: enforcementpoint_id where edge node is
                            located
                default: default
                type: str
            edge_cluster_id:
                description: edge_cluster_id where edge node is located
                type: str
            edge_cluster_display_name:
                description:
                    - display name of the edge cluster
                    - either this or edge_cluster_id must be specified. If both
                      are specified, edge_cluster_id takes precedence
                type: str
            edge_node_id:
                description: ID of the edge node
                type: str
            edge_node_display_name:
                description:
                    - Display name of the edge node.
                    - either this or edge_node_id must be specified. If both
                     are specified, edge_node_id takes precedence
                type: str
    failover_mode:
        description: Failover mode for the edge bridge cluster
        type: str
        default: PREEMPTIVE
        choices:
            - PREEMPTIVE
            - NON_PREEMPTIVE
    ha_mode:
        description: High avaialability mode can be active-active or
                     active-standby. High availability mode cannot be modified
                     after realization
        type: str
        default: ACTIVE_STANDBY
        choices:
            - ACTIVE_STANDBY
'''

EXAMPLES = '''
- name: create L2 Bridge Endpoint Profile
  nsxt_policy_l2_bridge_ep_profile:
    hostname: "10.10.10.10"
    nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
    nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
    validate_certs: False
    id: test-ep-profile
    display_name: test-ep-profile
    state: present
    edge_nodes_info:
        - edge_cluster_display_name: edge-cluster-1
          edge_node_id: 123471da-3823-11ea-9170-000c291a8262
    failover_mode: PREEMPTIVE
    ha_mode: ACTIVE_STANDBY
    tags:
    - tag: "my-tag"
      scope: "my-scope"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import (
    EDGE_CLUSTER_URL, EDGE_NODE_URL, L2_BRIDGE_EP_PROFILE_URL)
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.policy_resource_specs.l2_bridge_ep_profile import SPEC as L2BridgeEpProfileSpec
from ansible.module_utils._text import to_native


class NSXTL2BridgeEpProfile(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        return L2BridgeEpProfileSpec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return L2_BRIDGE_EP_PROFILE_URL.format(
            baseline_args['site_id'], baseline_args['enforcementpoint_id'])

    def update_resource_params(self, nsx_resource_params):
        nsx_resource_params.pop('site_id')
        nsx_resource_params.pop('enforcementpoint_id')

        edge_nodes_info = nsx_resource_params.pop(
            "edge_nodes_info")
        nsx_resource_params["edge_paths"] = []
        for edge_node_info in edge_nodes_info:
            site_id = edge_node_info['site_id']
            enforcementpoint_id = edge_node_info['enforcementpoint_id']
            edge_cluster_base_url = (
                EDGE_CLUSTER_URL.format(site_id, enforcementpoint_id))
            edge_cluster_id = self.get_id_using_attr_name_else_fail(
                "edge_cluster", edge_node_info,
                edge_cluster_base_url, "Edge Cluster")
            edge_node_base_url = EDGE_NODE_URL.format(
                site_id, enforcementpoint_id, edge_cluster_id)
            edge_node_id = self.get_id_using_attr_name_else_fail(
                "edge_node", edge_node_info,
                edge_node_base_url, "Edge Node")
            nsx_resource_params["edge_paths"].append(
                edge_node_base_url + "/" + edge_node_id)


if __name__ == '__main__':
    l2_bridge_ep_profile = NSXTL2BridgeEpProfile()
    l2_bridge_ep_profile.realize(baseline_arg_names=[
        'site_id', 'enforcementpoint_id'])
