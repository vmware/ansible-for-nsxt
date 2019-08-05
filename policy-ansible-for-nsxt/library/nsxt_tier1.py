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
module: nsxt_tier1
short_description: 'Create/Update/Delete a Tier-1 and associated resources'
description: Creates/Updates/Deletes a Tier-1 resource using the Policy API.
             Assocaited resources include 'Tier-1 Locale Service' and
             'Tier-1 Interface'. 'Tier-1 Locale Service' and 'Tier-1 Interface'
             attributes must be prepended with 't1ls' and 't1iface'
             respectively.
version_added: '2.8'
author: 'Gautam Verma'
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: Tier-1 ID
        required: true
        type: str
    description:
        description: Tier-1 description
        type: str
    default_rule_logging:
        description: Enable logging for whitelisted rule.
                     Indicates if logging should be enabled for the default
                     whitelisting rule.
        type: str
        default: false
        type: bool
    disable_firewall:
        description: Disable or enable gateway fiewall.
        default: False
        type: bool
    failover_mode:
        description: Determines the behavior when a Tier-1 instance in
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
    ipv6_ndra_profile_id:
        description: IPv6 NDRA profile configuration on Tier1.
                     Either or both NDRA and/or DAD profiles can be
                     configured. Related attribute ipv6_dad_profile_id.
        type: str
    ipv6_ndra_profile_display_name:
        description: Same as ipv6_ndra_profile_id. Either one can be specified.
                     If both are specified, ipv6_ndra_profile_id takes
                     precedence.
        type: str
    ipv6_dad_profile_id:
        description: IPv6 DRA profile configuration on Tier1.
                     Either or both NDRA and/or DAD profiles can be
                     configured. Related attribute ipv6_ndra_profile_id.
        type: str
    ipv6_dad_profile_display_name:
        description: Same as ipv6_dad_profile_id. Either one can be specified.
                     If both are specified, ipv6_dad_profile_id takes
                     precedence.
        type: str
    dhcp_config_id:
        description: DHCP configuration for Segments connected to
                     Tier-1. DHCP service is configured in relay mode.
        type: str
    dhcp_config_display_name:
        description: Same as dhcp_config_id. Either one can be specified.
                     If both are specified, dhcp_config_id takes precedence.
        type: str
    route_advertisement_rules:
        description: Route advertisement rules and filtering
        type: list
        suboptions:
            action:
                description:
                    - Action to advertise filtered routes to the connected
                      Tier0 gateway.
                choices:
                    - PERMIT: Enables the advertisment
                    - DENY: Disables the advertisement
                type: str
                required: true
            name:
                description: Display name for rule
                type: str
                required: true
            prefix_operator:
                description:
                    - Prefix operator to filter subnets.
                    - GE prefix operator filters all the routes with prefix
                      length greater than or equal to the subnets configured.
                    - EQ prefix operator filter all the routes with prefix
                      length equal to the subnets configured.
                type: str
                choices:
                    - GE
                    - EQ
            route_advertisement_types:
                description:
                    - Enable different types of route advertisements.
                    - By default, Routes to IPSec VPN local-endpoint subnets
                      (TIER1_IPSEC_LOCAL_ENDPOINT) are advertised if no value
                      is supplied here.
                type: list
                choices:
                    - 'TIER1_STATIC_ROUTES'
                    - 'TIER1_CONNECTED'
                    - 'TIER1_NAT'
                    - 'TIER1_LB_VIP'
                    - 'TIER1_LB_SNAT'
                    - 'TIER1_DNS_FORWARDER_IP'
                    - 'TIER1_IPSEC_LOCAL_ENDPOINT'
            subnets:
                description: Network CIDRs to be routed.
                type: list
    route_advertisement_types:
        description:
            - Enable different types of route advertisements.
            - By default, Routes to IPSec VPN local-endpoint subnets
              (TIER1_IPSEC_LOCAL_ENDPOINT) are advertised if no value is
              supplied here.
        type: list
        choices:
            - 'TIER1_STATIC_ROUTES'
            - 'TIER1_CONNECTED'
            - 'TIER1_NAT'
            - 'TIER1_LB_VIP'
            - 'TIER1_LB_SNAT'
            - 'TIER1_DNS_FORWARDER_IP'
            - 'TIER1_IPSEC_LOCAL_ENDPOINT'
    tier0_id:
        description: Tier-1 connectivity to Tier-0
        type: str
    tier0_display_name:
        description: Same as tier0_id. Either one can be specified.
                     If both are specified, tier0_id takes precedence.
        type: str
    t1ls_id:
        description: Tier-1 Locale Service ID
        required: false
        type: str
    t1ls_display_name:
        description:
            - Tier-1 Locale Service display name.
            - Either this or t1ls_id must be specified. If both are specified,
              t1ls_id takes precedence.
        required: false
        type: str
    t1ls_description:
        description: Tier-1 Locale Service  description
        type: str
    t1ls_state:
        description:
            - "State can be either 'present' or 'absent'. 'present' is used to
              create or update resource. 'absent' is used to delete resource."
            - Required if I(segp_id != null)."
        choices:
            - present
            - absent
    t1ls_tags:
        description: Opaque identifiers meaningful to the API user.
        type: dict
        suboptions:
            scope:
                description: Tag scope.
                required: true
                type: str
            tag:
                description: Tag value.
                required: true
                type: str
    t1ls_edge_cluster_info:
        description: Used to create path to edge cluster. Auto-assigned
                     if associated enforcement-point has only one edge
                     cluster.
        type: dict
        suboptions:
            site_id:
                description: site_id where edge cluster is located
                default: default
                type: str
            enforcementpoint_id:
                description: enforcementpoint_id where edge cluster is
                             located
                default: default
                type: str
            edge_cluster_id:
                description: ID of the edge cluster
                required: true
                type: str
            edge_cluster_display_name:
                description:
                    - display name of the edge cluster.
                    - Either this or edge_cluster_id must be specified. If
                      both are specified, edge_cluster_id takes precedence
                type: str
    t1ls_preferred_edge_nodes_info:
        description: Used to create paths to edge nodes. Specified edge
                     is used as preferred edge cluster member when
                     failover mode is set to PREEMPTIVE, not
                     applicable otherwise.
        type: list
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
                description: edge_cluster_id where edge node is
                             located
                required: true
                type: str
            edge_cluster_display_name:
                description:
                    - display name of the edge cluster.
                    - either this or edge_cluster_id must be specified. If
                      both are specified, edge_cluster_id takes precedence
                type: str
            edge_node_id:
                description: ID of the edge node
                type: str
            edge_node_display_name:
                description:
                    - Display name of the edge node.
                    - either this or edge_node_id must be specified. If
                      both are specified, edge_node_id takes precedence.
                type: str
    t1ls_route_redistribution_types:
        description: Enable redistribution of different types of routes
                     on Tier-1.
        choices:
            - TIER1_STATIC: Redistribute all subnets and static routes
                            advertised by Tier-1s.
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
    t1iface_id:
        description: Tier-1 Interface ID
        required: false
        type: str
    t1iface_description:
        description: Tier-1 Interface  description
        type: str
    t0iface_display_name:
        description:
            - Tier-1 Interface display name
            - Either this or t1iface_id must be specified. If both are
              specified, t1iface_id takes precedence.
        required: false
        type: str
    t1iface_state:
        description:
            - "State can be either 'present' or 'absent'. 'present' is used to
              create or update resource. 'absent' is used to delete resource."
            - Required if I(segp_id != null)."
        choices:
            - present
            - absent
    t1iface_tags:
        description: Opaque identifiers meaningful to the API user.
        type: dict
        suboptions:
            scope:
                description: Tag scope.
                required: true
                type: str
            tag:
                description: Tag value.
                required: true
                type: str
    t1iface_ipv6_ndra_profile_id:
        description:
            - "Configrue IPv6 NDRA profile. Only one NDRA profile can be
               configured."
            - Required if I(t1iface_id != null).
        type: str
    t1iface_segment_id:
        description:
            - Specify Segment to which this interface is connected to.
            - Required if I(t1iface_id != null).
        type: str
    t0iface_segment_display_name:
        description:
            - Same as t1iface_segment_id
            - Either this or t1iface_segment_id must be specified. If
              both are specified, t1iface_segment_id takes precedence.
        type: str
    t1iface_subnets:
        description:
            - IP address and subnet specification for interface.
            - Specify IP address and network prefix for interface.
            - Required if I(t1iface_id != null).
        type: list
'''

EXAMPLES = '''
- name: create Tier1
  nsxt_tier1:
    hostname: "10.160.84.49"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    id: test-tier1
    display_name: test-tier1
    state: "present"
    failover_mode: "PREEMPTIVE"
    disable_firewall: True
    force_whitelisting: True
    tags:
      - scope: "a"
      tag: "b"
    t1ls_id: test-t1ls
    t1ls_state: "present"
    t1ls_display_name: "test-t1ls"
    t1ls_route_redistribution_types: ["TIER0_STATIC", "TIER0_NAT"]
    t1ls_edge_cluster_info:
      edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
    t1ls_preferred_edge_nodes_info:
      - edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
        edge_id: "940f1f4b-0317-45d4-84e2-b8c2394e7405"
    t1iface_id: "test-t0-t1ls-iface"
    t1iface_display_name: "test-t0-t1ls-iface"
    t1iface_state: "present"
    t1iface_subnets:
      - ip_addresses: ["35.1.1.1"]
        prefix_len: 24
    t1iface_segment_id: "sg-uplink"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource

if __name__ == '__main__':
    from ansible.module_utils.policy_ipv6_profiles import PolicyIpv6DadProfiles
    from ansible.module_utils.policy_ipv6_profiles import (
        PolicyIpv6NdraProfiles)
    from ansible.module_utils.policy_dhcp import PolicyDhcpRelayConfig
    from ansible.module_utils.policy_edge_cluster import PolicyEdgeCluster
    from ansible.module_utils.policy_edge_node import PolicyEdgeNode

    import os
    import sys
    sys.path.append(os.getcwd())

    from library.nsxt_segment import NSXTSegment
    from library.nsxt_tier0 import NSXTTier0


class NSXTTier1(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        tier1_arg_spec = {}
        tier1_arg_spec.update(
            default_rule_logging=dict(
                required=False,
                type='bool'
            ),
            dhcp_config_id=dict(
                required=False,
                type='str'
            ),
            dhcp_config_display_name=dict(
                required=False,
                type='str'
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
            ipv6_ndra_profile_id=dict(
                required=False,
                type='str'
            ),
            ipv6_ndra_profile_display_name=dict(
                required=False,
                type='str'
            ),
            ipv6_dad_profile_id=dict(
                required=False,
                type='str'
            ),
            ipv6_dad_profile_display_name=dict(
                required=False,
                type='str'
            ),
            route_advertisement_rules=dict(
                required=False,
                type='list',
                options=dict(
                    action=dict(
                        required=False,
                        type='str',
                        default='PERMIT',
                        choices=['PERMIT', 'DENY']
                    ),
                    name=dict(
                        required=True,
                        type='str'
                    ),
                    prefix_operator=dict(
                        required=False,
                        type='str',
                        default='GE',
                        choices=['GE', 'EQ']
                    ),
                    route_advertisement_types=dict(
                        required=False,
                        type='list',
                        choices=['TIER1_STATIC_ROUTES', 'TIER1_CONNECTED',
                                 'TIER1_NAT', 'TIER1_LB_VIP', 'TIER1_LB_SNAT',
                                 'TIER1_DNS_FORWARDER_IP',
                                 'TIER1_IPSEC_LOCAL_ENDPOINT']
                    ),
                    subnets=dict(
                        required=True,
                        type='list'
                    )
                )
            ),
            route_advertisement_types=dict(
                required=False,
                type='list',
                choices=['TIER1_STATIC_ROUTES', 'TIER1_CONNECTED', 'TIER1_NAT',
                         'TIER1_LB_VIP', 'TIER1_LB_SNAT',
                         'TIER1_DNS_FORWARDER_IP', 'TIER1_IPSEC_LOCAL_ENDPOINT'
                         ]
            ),
            tier0_id=dict(
                required=False,
                type='str'
            ),
            tier0_display_name=dict(
                required=False,
                type='str'
            )
        )
        return tier1_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return '/infra/tier-1s'

    def update_resource_params(self):
        ipv6_profile_paths = []
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "ipv6_ndra_profile"):
            ipv6_ndra_profile_base_url = (PolicyIpv6NdraProfiles.
                                          get_resource_base_url())
            ipv6_ndra_profile_id = self.get_id_using_attr_name_else_fail(
                    "ipv6_ndra_profile", self.resource_params,
                    ipv6_ndra_profile_base_url, "Ipv6NdraProfile")
            ipv6_profile_paths.append(
                ipv6_ndra_profile_base_url + "/" + ipv6_ndra_profile_id)
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "ipv6_dad_profile"):
            ipv6_dad_profile_base_url = (PolicyIpv6DadProfiles.
                                         get_resource_base_url())
            ipv6_dad_profile_id = self.get_id_using_attr_name_else_fail(
                    "ipv6_dad_profile", self.resource_params,
                    ipv6_dad_profile_base_url, "Ipv6DadProfile")
            ipv6_profile_paths.append(
                ipv6_dad_profile_base_url + "/" + ipv6_dad_profile_id)
        if ipv6_profile_paths:
            self.resource_params["ipv6_profile_paths"] = ipv6_profile_paths

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "dhcp_config"):
            dhcp_config_base_url = (
                PolicyDhcpRelayConfig.get_resource_base_url())
            dhcp_config_id = self.get_id_using_attr_name_else_fail(
                "dhcp_config", self.resource_params,
                dhcp_config_base_url, "DhcpRelayConfig")
            self.resource_params["dhcp_config_paths"] = [
                dhcp_config_base_url + "/" + dhcp_config_id]

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "tier0"):
            tier0_base_url = NSXTTier0.get_resource_base_url()
            tier0_id = self.get_id_using_attr_name_else_fail(
                "tier0", self.resource_params,
                tier0_base_url, "Tier0")
            self.resource_params["tier0_path"] = (
                tier0_base_url + "/" + tier0_id)

    def update_parent_info(self, parent_info):
        parent_info["tier1_id"] = self.id

    class NSXTTier1LocaleService(NSXTBaseRealizableResource):
        def get_unique_arg_identifier(self):
            return NSXTTier1.NSXTTier1LocaleService.get_unique_arg_identifier()

        @staticmethod
        def get_unique_arg_identifier():
            return "t1ls"

        @staticmethod
        def get_resource_spec():
            tier1_ls_arg_spec = {}
            tier1_ls_arg_spec.update(
                edge_cluster_info=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        # Note that only default site_id and
                        # enforcementpoint_id are used
                        site_id=dict(
                            type='str',
                            default="default"
                        ),
                        enforcementpoint_id=dict(
                            type='str',
                            default="default"
                        ),
                        edge_cluster_id=dict(
                            type='str'
                        ),
                        edge_cluster_display_name=dict(
                            type='str'
                        )
                    )
                ),
                preferred_edge_nodes_info=dict(
                    required=False,
                    type='list',
                    options=dict(
                        # Note that only default site_id and
                        # enforcementpoint_id are used
                        site_id=dict(
                            type='str',
                            default="default"
                        ),
                        enforcementpoint_id=dict(
                            type='str',
                            default="default"
                        ),
                        edge_cluster_id=dict(
                            type='str'
                        ),
                        edge_cluster_display_name=dict(
                            type='str'
                        ),
                        edge_node_id=dict(
                            type='str'
                        ),
                        edge_node_display_name=dict(
                            type='str'
                        )
                    )
                ),
                route_redistribution_types=dict(
                    required=False,
                    type='list'
                )
            )
            return tier1_ls_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier1_id = parent_info.get("tier1_id", 'default')
            return '/infra/tier-1s/{}/locale-services'.format(tier1_id)

        def update_resource_params(self):
            if "edge_cluster_info" in self.resource_params:
                edge_cluster_info = self.resource_params.pop(
                    "edge_cluster_info")
                site_id = edge_cluster_info["site_id"]
                enforcementpoint_id = edge_cluster_info["enforcementpoint_id"]
                edge_cluster_base_url = (
                    PolicyEdgeCluster.get_resource_base_url(
                        site_id, enforcementpoint_id))
                edge_cluster_id = self.get_id_using_attr_name_else_fail(
                    "edge_cluster", edge_cluster_info, edge_cluster_base_url,
                    PolicyEdgeCluster.__name__)
                self.resource_params["edge_cluster_path"] = (
                    edge_cluster_base_url + "/" + edge_cluster_id)

            if "preferred_edge_nodes_info" in self.resource_params:
                preferred_edge_nodes_info = self.resource_params.pop(
                    "preferred_edge_nodes_info")
                self.resource_params["preferred_edge_paths"] = []
                for preferred_edge_node_info in preferred_edge_nodes_info:
                    site_id = preferred_edge_node_info.get(
                        "site_id", "default")
                    enforcementpoint_id = preferred_edge_node_info.get(
                        "enforcementpoint_id", "default")
                    edge_cluster_base_url = (
                        PolicyEdgeCluster.get_resource_base_url(
                            site_id, enforcementpoint_id))
                    edge_cluster_id = self.get_id_using_attr_name_else_fail(
                        "edge_cluster", preferred_edge_node_info,
                        edge_cluster_base_url, PolicyEdgeCluster.__name__)
                    edge_node_base_url = PolicyEdgeNode.get_resource_base_url(
                        site_id, enforcementpoint_id, edge_cluster_id)
                    edge_node_id = self.get_id_using_attr_name_else_fail(
                        "edge_node", preferred_edge_node_info,
                        edge_node_base_url, PolicyEdgeNode.__name__)
                    self.resource_params["preferred_edge_paths"].append(
                        edge_node_base_url + "/" + edge_node_id)

        def update_parent_info(self, parent_info):
            parent_info["t1ls_id"] = self.id

        class NSXTTier1Interface(NSXTBaseRealizableResource):
            def get_unique_arg_identifier(self):
                return (NSXTTier1.NSXTTier1LocaleService.NSXTTier1Interface
                        .get_unique_arg_identifier())

            @staticmethod
            def get_unique_arg_identifier():
                return "t1iface"

            @staticmethod
            def get_resource_spec():
                tier1_ls_int_arg_spec = {}
                tier1_ls_int_arg_spec.update(
                    ipv6_ndra_profile_id=dict(
                        required=False,
                        type='str'
                    ),
                    segment_id=dict(
                        required=False,
                        type='str'
                    ),
                    segment_display_name=dict(
                        required=False,
                        type='str'
                    ),
                    subnets=dict(
                        required=True,
                        type='list'
                    )
                )
                return tier1_ls_int_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier1_id = parent_info.get("tier1_id", 'default')
                locale_service_id = parent_info.get("t1ls_id", 'default')
                return ('/infra/tier-1s/{}/locale-services/{}/interfaces'
                        .format(tier1_id, locale_service_id))

            def update_resource_params(self):
                # segment_id is a required attr
                segment_base_url = NSXTSegment.get_resource_base_url()
                segment_id = self.get_id_using_attr_name_else_fail(
                    "segment", self.resource_params,
                    segment_base_url,
                    "Segment")
                self.resource_params["segment_path"] = (
                    segment_base_url + "/" + segment_id)

                if self.do_resource_params_have_attr_with_id_or_display_name(
                        "ipv6_ndra_profile"):
                    ipv6_ndra_profile_url = (
                        PolicyIpv6NdraProfiles.get_resource_base_url())
                    ipv6_ndra_profile_id = (
                        self.get_id_using_attr_name_else_fail(
                            "ipv6_ndra_profile", self.resource_params,
                            ipv6_ndra_profile_url, "Ipv6 NDRA Profile"))
                    self.resource_params["ipv6_profile_paths"] = [
                        ipv6_ndra_profile_url + "/" + ipv6_ndra_profile_id]


if __name__ == '__main__':
    nsxt_tier1 = NSXTTier1()
    nsxt_tier1.realize()
