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
    static_routes:
        type: list
        element: dict
        description: This is a list of Static Routes that need to be created,
                     updated, or deleted
        suboptions:
            id:
                description: Tier-1 Static Route ID.
                required: false
                type: str
            display_name:
                description:
                    - Tier-1 Static Route display name.
                    - Either this or id must be specified. If both are
                      specified, id takes precedence.
                required: false
                type: str
            description:
                description:
                    - Tier-1 Static Route description.
                type: str
            state:
                description:
                    - State can be either 'present' or 'absent'. 'present' is
                      used to create or update resource. 'absent' is used to
                      delete resource.
                    - Must be specified in order to modify the resource
                choices:
                    - present
                    - absent
            network:
                description: Network address in CIDR format
                required: true
                type: str
            next_hops:
                description: Next hop routes for network
                type: list
                elements: dict
                suboptions:
                    admin_distance:
                        description: Cost associated with next hop route
                        type: int
                        default: 1
                ip_address:
                    description: Next hop gateway IP address
                    type: str
                scope:
                    description:
                        - Interface path associated with current route
                        - For example, specify a policy path referencing the
                          IPSec VPN Session
                    type: list
            tags:
                description: Opaque identifiers meaningful to the API user
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
    locale_services:
        type: list
        element: dict
        description: This is a list of Locale Services that need to be created,
                     updated, or deleted
        suboptions:
            id:
                description: Tier-1 Locale Service ID
                type: str
            display_name:
                description:
                    - Tier-1 Locale Service display name.
                    - Either this or id must be specified. If both are
                      specified, id takes precedence.
                required: false
                type: str
            description:
                description: Tier-1 Locale Service  description
                type: str
            state:
                description:
                    - State can be either 'present' or 'absent'. 'present' is
                      used to create or update resource. 'absent' is used to
                      delete resource.
                    - Required if I(segp_id != null)
                choices:
                    - present
                    - absent
            tags:
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
            edge_cluster_info:
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
                            - Either this or edge_cluster_id must be specified.
                              If both are specified, edge_cluster_id takes
                              precedence
                        type: str
            preferred_edge_nodes_info:
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
                            - either this or edge_cluster_id must be specified.
                              If both are specified, edge_cluster_id takes
                              precedence
                        type: str
                    edge_node_id:
                        description: ID of the edge node
                        type: str
                    edge_node_display_name:
                        description:
                            - Display name of the edge node.
                            - either this or edge_node_id must be specified. If
                              both are specified, edge_node_id takes precedence
                        type: str
            route_redistribution_types:
                description: Enable redistribution of different types of routes
                             on Tier-1.
                choices:
                    - TIER1_STATIC - Redistribute all subnets and static routes
                                    advertised by Tier-1s.
                    - TIER1_NAT - Redistribute NAT IPs advertised by Tier-1
                                instances.
                    - TIER1_LB_VIP - Redistribute LB VIP IPs advertised by
                                    Tier-1 instances.
                    - TIER1_LB_SNAT - Redistribute LB SNAT IPs advertised by
                                    Tier-1 instances.
                    - TIER1_DNS_FORWARDER_IP - Redistribute DNS forwarder
                                            subnets on Tier-1 instances.
                    - TIER1_CONNECTED - Redistribute all subnets configured on
                                    Segments and Service Interfaces.
                    - TIER1_SERVICE_INTERFACE - Redistribute Tier1 service
                                            interface subnets.
                    - TIER1_SEGMENT - Redistribute subnets configured on
                                    Segments connected to Tier1.
                    - TIER1_IPSEC_LOCAL_ENDPOINT - Redistribute IPSec VPN
                                                local-endpoint  subnets
                                                advertised by TIER1.
                type: list
            ha_vip_configs:
                type: list
                elements: dict
                description:
                    - Array of HA VIP Config.
                    - This configuration can be defined only for Active-Standby
                      Tier0 gateway to provide redundancy. For mulitple
                      external interfaces, multiple HA VIP configs must be
                      defined and each config will pair exactly two external
                      interfaces. The VIP will move and will always be owned by
                      the Active node. When this property is configured,
                      configuration of dynamic-routing is not allowed.
                suboptions:
                    enabled:
                        description: Flag to enable this HA VIP config.
                        default: true
                        type: bool
                    external_interface_paths:
                        description:
                            - Policy paths to Tier0 external interfaces for
                              providing redundancy
                            - Policy paths to Tier0 external interfaces which
                              are to be paired to provide redundancy. Floating
                              IP will be owned by one of these interfaces
                              depending upon which edge node is Active.
                        type: list
                    vip_subnets:
                        description:
                            - VIP floating IP address subnets
                            - Array of IP address subnets which will be used as
                              floating IP addresses.
                        type: list
                        suboptions:
                            ip_addresses:
                                description: IP addresses assigned to interface
                                type: list
                                required: true
                            prefix_len:
                                description: Subnet prefix length
                                type: int
                                required: true
            interfaces:
                type: list
                element: dict
                description: Specify the interfaces associated with the Gateway
                             in this section that need to be created, updated,
                             or deleted
                suboptions:
                    id:
                        description: Tier-1 Interface ID
                        required: false
                        type: str
                    description:
                        description: Tier-1 Interface  description
                        type: str
                    display_name:
                        description:
                            - Tier-1 Interface display name
                            - Either this or id must be specified. If both are
                              specified, id takes precedence.
                        required: false
                        type: str
                    state:
                        description:
                            - State can be either 'present' or 'absent'.
                              'present' is used to create or update resource.
                              'absent' is used to delete resource.
                            - Required if I(segp_id != null).
                        choices:
                            - present
                            - absent
                    tags:
                        description: Opaque identifiers meaningful to the API
                                     user
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
                    ipv6_ndra_profile_id:
                        description:
                            - Configrue IPv6 NDRA profile. Only one NDRA
                              profile can be configured
                            - Required if I(id != null)
                        type: str
                    segment_id:
                        description:
                            - Specify Segment to which this interface is
                              connected to.
                            - Required if I(id != null)
                        type: str
                    t0iface_segment_display_name:
                        description:
                            - Same as segment_id
                            - Either this or segment_id must be specified. If
                              both are specified, segment_id takes precedence.
                        type: str
                    subnets:
                        description:
                            - IP address and subnet specification for interface
                            - Specify IP address and network prefix for
                              interface
                            - Required if I(id != null)
                        type: list
'''

EXAMPLES = '''
- name: create Tier1
  nsxt_tier1:
    hostname: "10.10.10.10"
    username: "username"
    password: "password"
    validate_certs: False
    display_name: test-tier22222
    state: present
    failover_mode: "PREEMPTIVE"
    disable_firewall: True
    force_whitelisting: True
    tags:
      - scope: "a"
        tag: "b"
    route_advertisement_rules:
      - name: "test-route-advertisement-rules"
        route_advertisement_types: ['TIER1_STATIC_ROUTES', 'TIER1_CONNECTED']
        subnets: ["35.1.1.1/23"]
    route_advertisement_types:
        - "TIER1_STATIC_ROUTES"
        - "TIER1_CONNECTED"
        - "TIER1_NAT"
    tier0_display_name: "node-t0"
    locale_services:
      - state: present
        display_name: test-t1ls-1
        route_redistribution_types: ["TIER0_STATIC", "TIER0_NAT"]
      - state: present
        display_name: test-t1ls-2
        route_redistribution_types: ["TIER0_STATIC", "TIER0_NAT"]
        interfaces:
          - id: "test-t1-t1ls-iface-2"
            display_name: "test-t1-t1ls-iface"
            state: present
            subnets:
              - ip_addresses: ["35.1.1.1"]
                prefix_len: 24
            segment_id: "test-seg-2"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import _ANSIBLE_ARGS as ANSIBLE_ARGS
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

    def update_resource_params(self, nsx_resource_params):
        ipv6_profile_paths = []
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "ipv6_ndra_profile"):
            ipv6_ndra_profile_base_url = (PolicyIpv6NdraProfiles.
                                          get_resource_base_url())
            ipv6_ndra_profile_id = self.get_id_using_attr_name_else_fail(
                    "ipv6_ndra_profile", nsx_resource_params,
                    ipv6_ndra_profile_base_url, "Ipv6NdraProfile")
            ipv6_profile_paths.append(
                ipv6_ndra_profile_base_url + "/" + ipv6_ndra_profile_id)
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "ipv6_dad_profile"):
            ipv6_dad_profile_base_url = (PolicyIpv6DadProfiles.
                                         get_resource_base_url())
            ipv6_dad_profile_id = self.get_id_using_attr_name_else_fail(
                    "ipv6_dad_profile", nsx_resource_params,
                    ipv6_dad_profile_base_url, "Ipv6DadProfile")
            ipv6_profile_paths.append(
                ipv6_dad_profile_base_url + "/" + ipv6_dad_profile_id)
        if ipv6_profile_paths:
            nsx_resource_params["ipv6_profile_paths"] = ipv6_profile_paths

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "dhcp_config"):
            dhcp_config_base_url = (
                PolicyDhcpRelayConfig.get_resource_base_url())
            dhcp_config_id = self.get_id_using_attr_name_else_fail(
                "dhcp_config", nsx_resource_params,
                dhcp_config_base_url, "DhcpRelayConfig")
            nsx_resource_params["dhcp_config_paths"] = [
                dhcp_config_base_url + "/" + dhcp_config_id]

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "tier0"):
            tier0_base_url = NSXTTier0.get_resource_base_url()
            tier0_id = self.get_id_using_attr_name_else_fail(
                "tier0", nsx_resource_params,
                tier0_base_url, "Tier0")
            nsx_resource_params["tier0_path"] = (
                tier0_base_url + "/" + tier0_id)

    def update_parent_info(self, parent_info):
        parent_info["tier1_id"] = self.id

    class NSXTTier1StaticRoutes(NSXTBaseRealizableResource):
        def get_spec_identifier(self):
            return NSXTTier1.NSXTTier1StaticRoutes.get_spec_identifier()

        @classmethod
        def get_spec_identifier(cls):
            return "static_routes"

        @staticmethod
        def get_resource_spec():
            tier1_sr_arg_spec = {}
            tier1_sr_arg_spec.update(
                network=dict(
                    required=True,
                    type='str'
                ),
                next_hops=dict(
                    required=True,
                    type='list',
                    elements='dict',
                    options=dict(
                        admin_distance=dict(
                            type='int',
                            default=1
                        ),
                        ip_address=dict(
                            type='str'
                        ),
                        scope=dict(
                            type='list',
                            elements='str'
                        )
                    )
                ),
            )
            return tier1_sr_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier1_id = parent_info.get("tier1_id", 'default')
            return '/infra/tier-1s/{}/static-routes'.format(tier1_id)

    class NSXTTier1LocaleService(NSXTBaseRealizableResource):
        def get_spec_identifier(self):
            return NSXTTier1.NSXTTier1LocaleService.get_spec_identifier()

        @classmethod
        def get_spec_identifier(cls):
            return "locale_services"

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
                ),
                ha_vip_configs=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        enabled=dict(
                            default=True,
                            type='bool'
                        ),
                        external_interface_display_names=dict(
                            required=True,
                            type='list',
                            elements='str'
                        ),
                        vip_subnets=dict(
                            type='list',
                            elements='dict',
                            required=True,
                            options=dict(
                                ip_addresses=dict(
                                    type='list',
                                    required=True
                                ),
                                prefix_len=dict(
                                    type='int',
                                    rqeuired=True
                                )
                            )
                        ),
                    )
                )
            )
            return tier1_ls_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier1_id = parent_info.get("tier1_id", 'default')
            return '/infra/tier-1s/{}/locale-services'.format(tier1_id)

        def update_resource_params(self, nsx_resource_params):
            if "edge_cluster_info" in nsx_resource_params:
                edge_cluster_info = nsx_resource_params.pop(
                    "edge_cluster_info")
                site_id = edge_cluster_info["site_id"]
                enforcementpoint_id = edge_cluster_info["enforcementpoint_id"]
                edge_cluster_base_url = (
                    PolicyEdgeCluster.get_resource_base_url(
                        site_id, enforcementpoint_id))
                edge_cluster_id = self.get_id_using_attr_name_else_fail(
                    "edge_cluster", edge_cluster_info, edge_cluster_base_url,
                    PolicyEdgeCluster.__name__)
                nsx_resource_params["edge_cluster_path"] = (
                    edge_cluster_base_url + "/" + edge_cluster_id)

            if "preferred_edge_nodes_info" in nsx_resource_params:
                preferred_edge_nodes_info = nsx_resource_params.pop(
                    "preferred_edge_nodes_info")
                nsx_resource_params["preferred_edge_paths"] = []
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
                    nsx_resource_params["preferred_edge_paths"].append(
                        edge_node_base_url + "/" + edge_node_id)

            if 'ha_vip_configs' in nsx_resource_params:
                for ha_vip_config in nsx_resource_params['ha_vip_configs']:
                    external_interface_info = ha_vip_config.pop(
                        'external_interface_info')
                    external_interface_paths = []
                    for external_interface in (
                            external_interface_info):
                        interface_base_url = (
                            NSXTTier1.NSXTTier0LocaleService.
                            NSXTTier1Interface.get_resource_base_url(
                                self.get_parent_info()))
                        external_interface_paths.append(
                            interface_base_url + "/" +
                            self.get_id_using_attr_name_else_fail(
                                None, external_interface,
                                interface_base_url,
                                NSXTTier1.NSXTTier1LocaleService.
                                NSXTTier1Interface,
                                ignore_not_found_error=False))
                    ha_vip_config[
                        'external_interface_paths'] = external_interface_paths

        def update_parent_info(self, parent_info):
            parent_info["ls_id"] = self.id

        class NSXTTier1Interface(NSXTBaseRealizableResource):
            def get_spec_identifier(self):
                return (NSXTTier1.NSXTTier1LocaleService.NSXTTier1Interface
                        .get_spec_identifier())

            @classmethod
            def get_spec_identifier(cls):
                return "interfaces"

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
                locale_service_id = parent_info.get("ls_id", 'default')
                return ('/infra/tier-1s/{}/locale-services/{}/interfaces'
                        .format(tier1_id, locale_service_id))

            def update_resource_params(self, nsx_resource_params):
                # segment_id is a required attr
                segment_base_url = NSXTSegment.get_resource_base_url()
                segment_id = self.get_id_using_attr_name_else_fail(
                    "segment", nsx_resource_params,
                    segment_base_url,
                    "Segment")
                nsx_resource_params["segment_path"] = (
                    segment_base_url + "/" + segment_id)

                if self.do_resource_params_have_attr_with_id_or_display_name(
                        "ipv6_ndra_profile"):
                    ipv6_ndra_profile_url = (
                        PolicyIpv6NdraProfiles.get_resource_base_url())
                    ipv6_ndra_profile_id = (
                        self.get_id_using_attr_name_else_fail(
                            "ipv6_ndra_profile", nsx_resource_params,
                            ipv6_ndra_profile_url, "Ipv6 NDRA Profile"))
                    nsx_resource_params["ipv6_profile_paths"] = [
                        ipv6_ndra_profile_url + "/" + ipv6_ndra_profile_id]


if __name__ == '__main__':
    nsxt_tier1 = NSXTTier1()
    nsxt_tier1.realize()
