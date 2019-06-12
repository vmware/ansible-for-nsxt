#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
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
module: nsxt_tier0
short_description: 'Create/Update/Delete a Tier-0 and associated resources'
description: Creates/Updates/Deletes a Tier-0 resource using the Policy API.
             Assocaited resources include 'Tier-0 Locale Service' and
             'Tier-0 Interface'. 'Tier-0 Locale Service' and 'Tier-0 Interface'
             attributes must be prepended with 't0ls' and 't0iface'
             respectively.
version_added: '2.8'
author: 'Gautam Verma'
options:
    hostname:
        description: Deployed NSX manager hostname.
        required: true
        type: str
    username:
        description: The username to authenticate with the NSX manager.
        required: true
        type: str
    password:
        description: The password to authenticate with the NSX manager.
        required: true
        type: str
    id:
        description: Tier-0 ID
        required: true
        type: str
    description:
        description: Tier-0 description
        type: str
    display_name:
        description: Tier-0 display name
        type: str
        default: id
    state:
        description: State can be either 'present' or 'absent'.
                     'present' is used to create or update resource.
                     'absent' is used to delete resource.
        choices:
            - present
            - absent
        required: true
    tags:
        description: Opaque identifiers meaningful to the API user
        type: str
    validate_certs:
        description: Enable server certificate verification.
        type: bool
        default: False
    default_rule_logging:
        description: Enable logging for whitelisted rule.
                     Indicates if logging should be enabled for the default
                     whitelisting rule.
        type: str
        default: false
        type: bool
    ha_mode:
        description: High-availability Mode for Tier-0
        choices:
            - 'ACTIVE_STANDBY'
            - 'ACTIVE_ACTIVE'
        default: 'ACTIVE_ACTIVE'
        type: str
    disable_firewall:
        description: Disable or enable gateway fiewall.
        default: False
        type: bool
    failover_mode:
        description: Determines the behavior when a Tier-0 instance in
                     ACTIVE-STANDBY high-availability mode restarts
                     after a failure. If set to PREEMPTIVE, the preferred node
                     will take over, even if it causes
                     another failure. If set to NON_PREEMPTIVE, then
                     the instance that restarted will remain secondary.
                     This property must not be populated unless the
                     ha_mode property is set to ACTIVE_STANDBY.
        choices:
            - 'NON_PREEMPTIVE'
            - 'PREEMPTIVE'
        default: 'NON_PREEMPTIVE'
        type: str
    force_whitelisting:
        description: Flag to add whitelisting FW rule during
                     realization.
        default: False
        type: bool
    internal_transit_subnets:
        description: Internal transit subnets in CIDR format.
                     Specify subnets that are used to assign addresses
                     to logical links connecting service routers and
                     distributed routers. Only IPv4 addresses are
                     supported. When not specified, subnet 169.254.0.0/
                     24 is assigned by default in ACTIVE_ACTIVE HA mode
                     or 169.254.0.0/28 in ACTIVE_STANDBY mode.
        default: False
        type: list
    ipv6_ndra_profile_id:
        description: IPv6 NDRA profile configuration on Tier0.
                     Either or both NDRA and/or DAD profiles can be
                     configured. Related attribute ipv6_dad_profile_id.
        type: str
    ipv6_dad_profile_id:
        description: IPv6 DRA profile configuration on Tier0.
                     Either or both NDRA and/or DAD profiles can be
                     configured. Related attribute ipv6_ndra_profile_id.
        type: str
    transit_subnets:
        description: Transit subnets in CIDR format.
                     Specify transit subnets that are used to assign
                     addresses to logical links connecting tier-0 and
                     tier-1s. Both IPv4 and IPv6 addresses are
                     supported.
                     When not specified, subnet 100.64.0.0/16 is
                     configured by default.
        type: list
    dhcp_config_id:
        description: DHCP configuration for Segments connected to
                     Tier-0. DHCP service is configured in relay mode.
        type: str
    t0ls_id:
        description: Tier-0 Locale Service ID
        required: false
        type: str
    t0ls_description:
        description: Tier-0 Locale Service  description
        type: str
    t0ls_display_name:
        description: Tier-0 Locale Service display name
        type: str
        default: t0ls_id
    t0ls_state:
        description: State can be either 'present' or 'absent'.
                     'present' is used to create or update resource.
                     'absent' is used to delete resource.
                     Required if t0ls_id is specified.
        choices:
            - present
            - absent
    t0ls_tags:
        description: Opaque identifiers meaningful to the API user
        type: str
    t0ls_edge_cluster_info:
        description: Used to create path to edge cluster. Auto-assigned
                     if associated enforcement-point has only one edge
                     cluster.
        type: dict
        suboptions:
            site_id:
                description: site_id where edge cluster is located
                required: true
                type: str
            enforcementpoint_id:
                description: enforcementpoint_id where edge cluster is
                             located
                required: true
                type: str
            edge_cluster_id:
                description: ID of the edge cluster
                required: true
                type: str
    t0ls_preferred_edge_nodes_info:
        description: Used to create paths to edge nodes. Specified edge
                     is used as preferred edge cluster member when
                     failover mode is set to PREEMPTIVE, not
                     applicable otherwise.
        type: list
        suboptions:
            site_id:
                description: site_id where edge node is located
                required: true
                type: str
            enforcementpoint_id:
                description: enforcementpoint_id where edge node is
                             located
                required: true
                type: str
            edge_cluster_id:
                description: edge_cluster_id where edge node is
                             located
                required: true
                type: str
            edge_id:
                description: ID of the edge node
                required: true
                type: str
    t0ls_route_redistribution_types:
        description: Enable redistribution of different types of routes
                     on Tier-0.
        choices:
            - TIER0_STATIC: Redistribute user added static routes.
            - TIER0_CONNECTED: Redistribute all subnets configured on
                               Interfaces and routes related to
                               TIER0_ROUTER_LINK, TIER0_SEGMENT,
                               TIER0_DNS_FORWARDER_IP,
                               TIER0_IPSEC_LOCAL_IP, TIER0_NAT types.
            - TIER1_STATIC: Redistribute all subnets and static routes
                            advertised by Tier-1s.
            - TIER0_EXTERNAL_INTERFACE: Redistribute external interface
                                        subnets on Tier-0.
            - TIER0_LOOPBACK_INTERFACE: Redistribute loopback interface
                                        subnets on Tier-0. 
            - TIER0_SEGMENT: Redistribute subnets configured on
                             Segments connected to Tier-0.
            - TIER0_ROUTER_LINK: Redistribute router link port subnets
                                 on Tier-0.
            - TIER0_SERVICE_INTERFACE: Redistribute Tier0 service
                                       interface subnets.
            - TIER0_DNS_FORWARDER_IP: Redistribute DNS forwarder
                                      subnets.
            - TIER0_IPSEC_LOCAL_IP: Redistribute IPSec subnets.
            - TIER0_NAT: Redistribute NAT IPs owned by Tier-0.
            - TIER1_NAT: Redistribute NAT IPs advertised by Tier-1
                         instances.
            - TIER1_LB_VIP: Redistribute LB VIP IPs advertised by
                            Tier-1 instances.
            - TIER1_LB_SNAT: Redistribute LB SNAT IPs advertised by
                             Tier-1 instances.
            - TIER1_DNS_FORWARDER_IP: Redistribute DNS forwarder
                                      subnets on Tier-1 instances.
            - TIER1_CONNECTED: Redistribute all subnets configured on
                               Segments and Service Interfaces.
            - TIER1_SERVICE_INTERFACE: Redistribute Tier1 service
                                       interface subnets.
            - TIER1_SEGMENT: Redistribute subnets configured on
                             Segments connected to Tier1.
            - TIER1_IPSEC_LOCAL_ENDPOINT: Redistribute IPSec VPN
                                          local-endpoint  subnets
                                          advertised by TIER1.
        type: list
    t0iface_id:
        description: Tier-0 Interface ID
        required: false
        type: str
    t0iface_description:
        description: Tier-0 Interface  description
        type: str
    t0iface_display_name:
        description: Tier-0 Interface display name
        type: str
        default: t0iface_id
    t0iface_state:
        description: State can be either 'present' or 'absent'.
                     'present' is used to create or update resource.
                     'absent' is used to delete resource.
                     Required if t0iface_id is specified.
        choices:
            - present
            - absent
    t0iface_tags:
        description: Opaque identifiers meaningful to the API user
        type: str
    t0iface_segment_id:
        description: Specify Segment to which this interface is
                     connected to.
                     Required if t0iface_id is specified.
        type: str
    t0iface_type:
        description: Interface type
        choices:
            - "EXTERNAL"
            - "LOOPBACK"
            - "SERVICE"
        default: "EXTERNAL"
        type: str
    t0iface_edge_node_info:
        description: Info to create policy path to edge node to handle
                     externalconnectivity.
                     Required when interface type is EXTERNAL and
                     t0iface_id is specified.
        type: dict
        suboptions:
            site_id:
                description: site_id where edge node is located
                required: true
                type: str
            enforcementpoint_id:
                description: enforcementpoint_id where edge node is
                             located
                required: true
                type: str
            edge_cluster_id:
                description: edge_cluster_id where edge node is
                             located
                required: true
                type: str
            edge_id:
                description: ID of the edge node
                required: true
                type: str
    t0iface_subnets:
        description: IP address and subnet specification for interface.
                     Specify IP address and network prefix for
                     interface.
                     Required if t0iface_id is specified.
        type: list
'''

EXAMPLES = '''
- name: create Tier0
  nsxt_tier0:
    hostname: "10.160.84.49"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    id: test-tier0
    display_name: test-tier0
    state: "present"
    ha_mode: "ACTIVE_STANDBY"
    failover_mode: "PREEMPTIVE"
    disable_firewall: True
    force_whitelisting: True
    tags:
      - scope: "a"
      tag: "b"
    t0ls_id: test-t0ls
    t0ls_state: "present"
    t0ls_display_name: "test-t0ls"
    t0ls_route_redistribution_types: ["TIER0_STATIC", "TIER0_NAT"]
    t0ls_edge_cluster_info:
      site_id: "default"
      enforcementpoint_id: "nsx"
      edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
    t0ls_preferred_edge_nodes_info:
      - site_id: "default"
        enforcementpoint_id: "nsx"
        edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
        edge_id: "940f1f4b-0317-45d4-84e2-b8c2394e7405"
    t0iface_id: "test-t0-t0ls-iface"
    t0iface_display_name: "test-t0-t0ls-iface"
    t0iface_state: "present"
    t0iface_subnets:
      - ip_addresses: ["35.1.1.1"]
        prefix_len: 24
    t0iface_segment_id: "sg-uplink"
    t0iface_edge_node_info:
      site_id: "default"
      enforcementpoint_id: "nsx"
      edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
      edge_id: "940f1f4b-0317-45d4-84e2-b8c2394e7405"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils._text import to_native

from ansible.module_utils.policy_ipv6_profiles import PolicyIpv6DadProfiles
from ansible.module_utils.policy_ipv6_profiles import PolicyIpv6NdraProfiles
from ansible.module_utils.policy_dhcp import PolicDhcpRelayConfig
from ansible.module_utils.policy_edge_cluster import PolicyEdgeCluster
from ansible.module_utils.policy_edge_node import PolicyEdgeNode

from ansible.module_utils.logger import Logger
logger = Logger.getInstance()

import os, sys
sys.path.append(os.getcwd())

from library.nsxt_segment import NSXTSegment

class NSXTTier0(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        tier0_arg_spec = {}
        tier0_arg_spec.update(
            default_rule_logging=dict(
                required=False,
                type='bool'
            ),
            ha_mode=dict(
                required=False,
                type='str',
                default="ACTIVE_ACTIVE",
                choices=['ACTIVE_STANDBY', 'ACTIVE_ACTIVE']
            ),
            disable_firewall=dict(
                required=False,
                type='bool',
                default=False
            ),
            failover_mode=dict(
                required=False,
                type='str',
                default='NON_PREEMPTIVE',
                choices=['NON_PREEMPTIVE', 'PREEMPTIVE']
            ),
            force_whitelisting=dict(
                required=False,
                type='bool',
                default=False
            ),
            internal_transit_subnets=dict(
                required=False,
                type='list'
            ),
            ipv6_ndra_profile_id=dict(
                required=False,
                type='str'
            ),
            ipv6_dad_profile_id=dict(
                required=False,
                type='str'
            ),
            transit_subnets=dict(
                required=False,
                type='list'
            ),
            dhcp_config_id=dict(
                required=False,
                type='str'
            )
        )
        return tier0_arg_spec

    @staticmethod
    def get_resource_base_url(parent_info):
        return '/infra/tier-0s'

    def update_resource_params(self):
        ipv6_profile_paths = []
        if "ipv6_ndra_profile_id" in self.resource_params:
            ipv6_ndra_profile_id = self.resource_params\
                .pop("ipv6_ndra_profile_id")
            ipv6_profile_paths\
                .append(PolicyIpv6NdraProfiles.get_resource_base_url() +\
                    "/" + ipv6_ndra_profile_id)
        if "ipv6_dad_profile_id" in self.resource_params:
            ipv6_dad_profile_id = self.resource_params\
                .pop("ipv6_dad_profile_id")
            ipv6_profile_paths\
                .append(PolicyIpv6DadProfiles.get_resource_base_url() +\
                    "/" + ipv6_dad_profile_id)
        if ipv6_profile_paths:
            self.resource_params["ipv6_profile_paths"] = ipv6_profile_paths

        if "dhcp_config_id" in self.resource_params:
            dhcp_config_id = self.resource_params.pop("dhcp_config_id")
            self.resource_params["dhcp_config_paths"] = \
                [PolicDhcpRelayConfig.get_resource_base_url() + "/" + dhcp_config_id]
    
    def update_parent_info(self, parent_info):
        parent_info["tier0_id"] = self.id

    class NSXTTier0LocaleService(NSXTBaseRealizableResource):
        def get_unique_arg_identifier(self):
            return NSXTTier0.NSXTTier0LocaleService.get_unique_arg_identifier()

        @staticmethod
        def get_unique_arg_identifier():
            return "t0ls"

        @staticmethod
        def get_resource_spec():
            tier0_ls_arg_spec = {}
            tier0_ls_arg_spec.update(
                edge_cluster_info=dict(
                    required=False,
                    type=dict,
                    options=dict(
                        site_id=dict(
                            required=True,
                            type='str'
                        ),
                        enforcementpoint_id=dict(
                            required=True,
                            type='str'
                        ),
                        edge_cluster_id=dict(
                            required=True,
                            type='str'
                        )
                    )
                ),
                preferred_edge_nodes_info=dict(
                    required=False,
                    type=list,
                    options=dict(
                        site_id=dict(
                            required=True,
                            type='str'
                        ),
                        enforcementpoint_id=dict(
                            required=True,
                            type='str'
                        ),
                        edge_cluster_id=dict(
                            required=True,
                            type='str'
                        ),
                        edge_id=dict(
                            required=True,
                            type='str'
                        )
                    )
                ),
                route_redistribution_types=dict(
                    required=False,
                    type=list
                )
            )
            return tier0_ls_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier0_id = parent_info.get("tier0_id", 'default')
            return '/infra/tier-0s/{}/locale-services'.format(tier0_id)

        def update_resource_params(self):
            if "edge_cluster_info" in self.resource_params:
                edge_cluster_info = self.resource_params.pop("edge_cluster_info")
                site_id = edge_cluster_info["site_id"]
                enforcementpoint_id = edge_cluster_info["enforcementpoint_id"]
                edge_cluster_id = edge_cluster_info["edge_cluster_id"]
                self.resource_params["edge_cluster_path"] = \
                PolicyEdgeCluster.get_resource_base_url(site_id, enforcementpoint_id) + "/" + edge_cluster_id

            if "preferred_edge_nodes_info" in self.resource_params:
                preferred_edge_nodes_info = self.resource_params.pop("preferred_edge_nodes_info")
                self.resource_params["preferred_edge_paths"] = []
                for preferred_edge_node_info in preferred_edge_nodes_info:
                    site_id = preferred_edge_node_info["site_id"]
                    enforcementpoint_id = preferred_edge_node_info["enforcementpoint_id"]
                    edge_cluster_id = preferred_edge_node_info["edge_cluster_id"]
                    edge_id = preferred_edge_node_info["edge_id"]
                    self.resource_params["preferred_edge_paths"].append(PolicyEdgeNode.get_resource_base_url(site_id, enforcementpoint_id, edge_cluster_id) + "/" + edge_id)

        def update_parent_info(self, parent_info):
            parent_info["t0ls_id"] = self.id
    
        class NSXTTier0Interface(NSXTBaseRealizableResource):
            def get_unique_arg_identifier(self):
                return NSXTTier0.NSXTTier0LocaleService.NSXTTier0Interface.get_unique_arg_identifier()

            @staticmethod
            def get_unique_arg_identifier():
                return "t0iface"

            @staticmethod
            def get_resource_spec():
                tier0_ls_int_arg_spec = {}
                tier0_ls_int_arg_spec.update(
                    segment_id=dict(
                        required=True,
                        type='str'
                    ),
                    edge_node_info=dict(
                        required=True,
                        type=dict,
                        options=dict(
                            site_id=dict(
                                required=True,
                                type='str'
                            ),
                            enforcementpoint_id=dict(
                                required=True,
                                type='str'
                            ),
                            edge_cluster_id=dict(
                                required=True,
                                type='str'
                            ),
                            edge_id=dict(
                                required=True,
                                type='str'
                            )
                        )
                    ),
                    subnets=dict(
                        required=True,
                        type=list
                    ),
                    type=dict(
                        required=False,
                        type=str,
                        default="EXTERNAL",
                        choices=["EXTERNAL", "SERVICE", "LOOPBACK"]
                    )
                )
                return tier0_ls_int_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier0_id = parent_info.get("tier0_id", 'default')
                locale_service_id = parent_info.get("t0ls_id", 'default')
                return '/infra/tier-0s/{}/locale-services/{}/interfaces'.format(tier0_id, locale_service_id)

            def update_resource_params(self):
                # segment_id is a required attr
                segment_id = self.resource_params.pop("segment_id")
                self.resource_params["segment_path"] = \
                NSXTSegment.get_resource_base_url() + "/" + segment_id

                # edge_node_info is a required attr
                edge_node_info = self.resource_params.pop("edge_node_info")
                site_id = edge_node_info["site_id"]
                enforcementpoint_id = edge_node_info["enforcementpoint_id"]
                edge_cluster_id = edge_node_info["edge_cluster_id"]
                edge_id = edge_node_info["edge_id"]
                self.resource_params["edge_path"] = \
                PolicyEdgeNode.get_resource_base_url(site_id, enforcementpoint_id, edge_cluster_id) + "/" + edge_id


if __name__ == '__main__':
    nsxt_tier0 = NSXTTier0()
    nsxt_tier0.realize()
