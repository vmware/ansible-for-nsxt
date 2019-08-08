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
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: Tier-0 ID
        required: true
        type: str
    description:
        description: Tier-0 description
        type: str
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
    ipv6_ndra_profile_display_name:
        description: Same as ipv6_ndra_profile_id. Either one can be specified.
                     If both are specified, ipv6_ndra_profile_id takes
                     precedence.
        type: str
    ipv6_dad_profile_id:
        description: IPv6 DRA profile configuration on Tier0.
                     Either or both NDRA and/or DAD profiles can be
                     configured. Related attribute ipv6_ndra_profile_id.
        type: str
    ipv6_dad_profile_display_name:
        description: Same as ipv6_dad_profile_id. Either one can be specified.
                     If both are specified, ipv6_dad_profile_id takes
                     precedence.
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
    dhcp_config_display_name:
        description: Same as dhcp_config_id. Either one can be specified.
                     If both are specified, dhcp_config_id takes precedence.
        type: str
    t0ls_id:
        description: Tier-0 Locale Service ID.
        required: false
        type: str
    t0ls_display_name:
        description:
            - Tier-0 Locale Service display name.
            - Either this or t0ls_id must be specified. If both are specified,
              t0ls_id takes precedence.
        required: false
        type: str
    t0ls_description:
        description:
            - Tier-0 Locale Service  description.
        type: str
    t0ls_state:
        description:
            - "State can be either 'present' or 'absent'. 'present' is used to
               create or update resource. 'absent' is used to delete resource."
            - Required if t0ls_id is specified.
        choices:
            - present
            - absent
    t0ls_tags:
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
    t0ls_edge_cluster_info:
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
                type: str
            edge_cluster_display_name:
                description:
                    - display name of the edge cluster.
                    - Either this or edge_cluster_id must be specified. If
                      both are specified, edge_cluster_id takes precedence
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
            - TIER1_NAT: Redistribute NAT IPs advertised by Tier-1 instances.
            - TIER1_LB_VIP: Redistribute LB VIP IPs advertised by Tier-1
              instances.
            - TIER1_LB_SNAT: Redistribute LB SNAT IPs advertised by Tier-1
              instances.
            - TIER1_DNS_FORWARDER_IP: Redistribute DNS forwarder subnets on
              Tier-1 instances.
            - TIER1_CONNECTED: Redistribute all subnets configured on Segments
              and Service Interfaces.
            - TIER1_SERVICE_INTERFACE: Redistribute Tier1 service interface
              subnets.
            - TIER1_SEGMENT: Redistribute subnets configured on Segments
              connected to Tier1.
            - TIER1_IPSEC_LOCAL_ENDPOINT: Redistribute IPSec VPN local-endpoint
              subnets advertised by TIER1.
        type: list
    t0ls_bgp_ecmp:
        description: Flag to enable ECMP.
        type: bool
        required: False
        default: True
    t0ls_bgp_enabled:
        description: Flag to enable BGP configuration. Disabling will stop
                     feature and BGP peering.
        type: bool
        required: False
        default: True
    t0ls_bgp_graceful_restart_config:
        description: Configuration field to hold BGP Restart mode and timer.
        type: dict
        required: False
        suboptions:
            mode:
                description: BGP Graceful Restart Configuration Mode
                    - If mode is DISABLE, then graceful restart and helper
                      modes are disabled.
                    - If mode is GR_AND_HELPER, then both graceful restart and
                      helper modes are enabled.
                    - If mode is HELPER_ONLY, then helper mode is enabled.
                      HELPER_ONLY mode is the ability for a BGP speaker to
                      indicate its ability to preserve forwarding state during
                      BGP restart.
                    - GRACEFUL_RESTART mode is the ability of a BGP speaker to
                      advertise its restart to its peers.
                type: str
                required: False
                default: 'HELPER_ONLY'
                choices:
                    - DISABLE
                    - GR_AND_HELPER
                    - HELPER_ONLY
            timer:
                description: BGP Graceful Restart Timer
                type: dict
                required: False
                suboptions:
                    restart_timer:
                        description:
                            - BGP Graceful Restart Timer
                            - Maximum time taken (in seconds) for a BGP session
                              to be established after a restart. This can be
                              used to speed up routing convergence by its peer
                              in case the BGP speaker does not come back up
                              after a restart. If the session is not
                              re-established within this timer, the receiving
                              speaker will delete all the stale routes from
                              that peer. Min 1 and Max 3600
                        type: int
                        default: 180
                    stale_route_timer:
                        description:
                            - BGP Stale Route Timer
                            - Maximum time (in seconds) before stale routes are
                              removed from the RIB (Routing Information Base)
                              when BGP restarts. Min 1 and Max 3600
                        type: int
                        default: 600
    t0ls_bgp_inter_sr_ibgp:
        description: Flag to enable inter SR IBGP configuration. When not
                     specified, inter SR IBGP is automatically enabled if
                     Tier-0 is created in ACTIVE_ACTIVE ha_mode.
        type: bool
        required: False
    t0ls_bgp_local_as_num:
        description:
            - BGP AS number in ASPLAIN/ASDOT Format.
            - Specify BGP AS number for Tier-0 to advertize to BGP peers.
              AS number can be specified in ASPLAIN (e.g., "65546") or
              ASDOT (e.g., "1.10") format. Empty string disables BGP feature.
        type: str
        required: True
    t0ls_bgp_multipath_relax:
        description: Flag to enable BGP multipath relax option.
        type: bool
        default: True
    t0ls_bgp_route_aggregations:
        description: List of routes to be aggregated
        type: dict
        required: False
        suboptions:
            prefix:
                description: CIDR of aggregate address
                type: str
                required: True
            summary_only:
                description:
                    - Send only summarized route.
                    - Summarization reduces number of routes advertised by
                      representing multiple related routes with prefix
                      property.
                type: bool
                default: True
    t0ls_bgp_neighbor_allow_as_in:
        description: Flag to enable allowas_in option for BGP neighbor
        type: bool
        default: False
    t0ls_bgp_neighbor_bfd:
        description:
            - BFD configuration for failure detection.
            - BFD is enabled with default values when not configured.
        type: dict
        required: False
        suboptions:
            enabled:
                description: Flag to enable BFD cofiguration
                type: bool
                required: False
            interval:
                description: Time interval between heartbeat packets in
                             milliseconds. Min 300 and Max 60000
                type: int
                default: 1000
            multiple:
                description:
                    - Declare dead multiple.
                    - Number of times heartbeat packet is missed before BFD
                      declares the neighbor is down. Min 2 and Max 16
                type: int
                default: 3
    t0ls_bgp_neighbor_graceful_restart_mode:
        description:
            - BGP Graceful Restart Configuration Mode
            - If mode is DISABLE, then graceful restart and helper modes are
              disabled.
            - If mode is GR_AND_HELPER, then both graceful restart and helper
              modes are enabled.
            - If mode is HELPER_ONLY, then helper mode is enabled. HELPER_ONLY
              mode is the ability for a BGP speaker to indicate its ability
              to preserve forwarding state during BGP restart.
            - GRACEFUL_RESTART mode is the ability of a BGP speaker to
              advertise its restart to its peers.
        type: str
        choices:
            - DISABLE
            - GR_AND_HELPER
            - HELPER_ONLY
    t0ls_bgp_neighbor_hold_down_time:
        description: Wait time in seconds before declaring peer dead. Min 1 and
                     Max 65535
        type: int
        default: 180
    t0ls_bgp_neighbor_keep_alive_time:
        description: Interval between keep alive messages sent to peer. Min 1
                     and Max 65535.
        type: int
        default: 60
    t0ls_bgp_neighbor_maximum_hop_limit:
        description: Maximum number of hops allowed to reach BGP neighbor.
                     Min 1 and Max 255
        type: int
        default: 1
    t0ls_bgp_neighbor_neighbor_address:
        description: Neighbor IP Address
        type: str
        required: True
    t0ls_bgp_neighbor_remote_as_num:
        description: 4 Byte ASN of the neighbor in ASPLAIN Format
        type: str
        required: True
    t0ls_bgp_neighbor_route_filtering:
        description: Enable address families and route filtering in each
                     direction
        type: dict
        required: False
        suboptions:
            address_family:
                description:
                type: str
                required: False
                choices:
                    - 'IPV4'
                    - 'IPV6'
                    - 'VPN'
            enabled:
                description: Flag to enable address family.
                type: bool
                default: True
            in_route_filters:
                description:
                    - Prefix-list or route map path for IN direction
                    - Specify path of prefix-list or route map to filter routes
                      for IN direction.
                type: list
                required: False
            out_route_filters:
                description:
                    - Prefix-list or route map path for OUT direction
                    - Specify path of prefix-list or route map to filter routes
                      for OUT direction. When not specified, a built-in
                      prefix-list named 'prefixlist-out-default' is
                      automatically applied.
                type: list
                required: False
    t0ls_bgp_neighbor_source_addresses:
        description:
            - Source IP Addresses for BGP peering
            - Source addresses should belong to Tier0 external or loopback
              interface IP Addresses. BGP peering is formed from all these
              addresses. This property is mandatory when maximum_hop_limit is
              greater than 1.
        type: list
        required: False
    t0iface_id:
        description: Tier-0 Interface ID
        type: str
    t0iface_display_name:
        description:
            - Tier-0 Interface display name
            - Either this or t0iface_id must be specified. If both are
              specified, t0iface_id takes precedence.
        required: false
        type: str
    t0iface_description:
        description: Tier-0 Interface  description
        type: str
    t0iface_state:
        description:
            - "State can be either 'present' or 'absent'. 'present' is used to
              create or update resource. 'absent' is used to delete resource."
            - Required if I(segp_id != null)."
        choices:
            - present
            - absent
    t0iface_tags:
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
    t0iface_segment_id:
        description: Specify Segment to which this interface is
                     connected to.
                     Required if t0iface_id is specified.
        type: str
    t0iface_segment_display_name:
        description:
            - Same as t0iface_segment_id
            - Either this or t0iface_segment_id must be specified. If
              both are specified, t0iface_segment_id takes precedence.
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
        description:
            - "Info to create policy path to edge node to handle
               externalconnectivity."
            - "Required if interface type is EXTERNAL and
               I(t0iface_id != null)."
        type: dict
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
    t0iface_subnets:
        description:
            - IP address and subnet specification for interface.
            - Specify IP address and network prefix for interface.
            - Required if I(t0iface_id != null).
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
    t0ls_state: "present"
    t0ls_display_name: "test-t0ls"
    t0ls_route_redistribution_types: ["TIER0_STATIC", "TIER0_NAT"]
    t0ls_edge_cluster_info:
      edge_cluster_display_name: "edgecluster1"
    t0ls_preferred_edge_nodes_info:
      - edge_cluster_id: "95196903-6b8a-4276-a7c4-387263e834fd"
        edge_node_id: "940f1f4b-0317-45d4-84e2-b8c2394e7405"
    t0ls_bgp_state: "present"
    t0ls_bgp_local_as_num: 1211
    t0ls_bgp_inter_sr_ibgp: False
    t0ls_bgp_graceful_restart_config:
      mode: "GR_AND_HELPER"
      timer:
        restart_timer: 12
    t0ls_bgp_route_aggregations:
      - prefix: "10.1.1.0/24"
      - prefix: "11.1.0.0/16"
        summary_only: False
    t0ls_bgp_neighbor_display_name: "neigh1"
    t0ls_bgp_neighbor_neighbor_address: "1.2.3.4"
    t0ls_bgp_neighbor_remote_as_num: "12"
    t0ls_bgp_neighbor_state: "absent"
    t0iface_id: "test-t0-t0ls-iface"
    t0iface_display_name: "test-t0-t0ls-iface"
    t0iface_state: "present"
    t0iface_subnets:
      - ip_addresses: ["35.1.1.1"]
        prefix_len: 24
    t0iface_segment_display_name: "sg-uplink"
    t0iface_edge_node_info:
      edge_cluster_display_name: "edgecluster1"
      edge_node_id: "0"
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
            transit_subnets=dict(
                required=False,
                type='list'
            ),
            dhcp_config_id=dict(
                required=False,
                type='str'
            ),
            dhcp_config_display_name=dict(
                required=False,
                type='str'
            )
        )
        return tier0_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return '/infra/tier-0s'

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
            return tier0_ls_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier0_id = parent_info.get("tier0_id", 'default')
            return '/infra/tier-0s/{}/locale-services'.format(tier0_id)

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
            parent_info["t0ls_id"] = self.id

        class NSXTTier0Interface(NSXTBaseRealizableResource):
            def get_unique_arg_identifier(self):
                return (
                    NSXTTier0.NSXTTier0LocaleService.NSXTTier0Interface.
                    get_unique_arg_identifier())

            @staticmethod
            def get_unique_arg_identifier():
                return "t0iface"

            @staticmethod
            def get_resource_spec():
                tier0_ls_int_arg_spec = {}
                tier0_ls_int_arg_spec.update(
                    segment_id=dict(
                        required=False,
                        type='str'
                    ),
                    segment_display_name=dict(
                        required=False,
                        type='str'
                    ),
                    edge_node_info=dict(
                        required=True,
                        type='dict',
                        options=dict(
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
                    subnets=dict(
                        required=True,
                        type='list'
                    ),
                    type=dict(
                        required=False,
                        type='str',
                        default="EXTERNAL",
                        choices=["EXTERNAL", "SERVICE", "LOOPBACK"]
                    )
                )
                return tier0_ls_int_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier0_id = parent_info.get("tier0_id", 'default')
                locale_service_id = parent_info.get("t0ls_id", 'default')
                return ('/infra/tier-0s/{}/locale-services/{}/interfaces'
                        .format(tier0_id, locale_service_id))

            def update_resource_params(self):
                # segment_id is a required attr
                segment_base_url = NSXTSegment.get_resource_base_url()
                segment_id = self.get_id_using_attr_name_else_fail(
                    "segment", self.resource_params,
                    segment_base_url,
                    "Segment")
                self.resource_params["segment_path"] = (
                    segment_base_url + "/" + segment_id)

                # edge_node_info is a required attr
                edge_node_info = self.resource_params.pop("edge_node_info")
                site_id = edge_node_info.get("site_id", "default")
                enforcementpoint_id = edge_node_info.get(
                    "enforcementpoint_id", "default")
                edge_cluster_base_url = (
                    PolicyEdgeCluster.get_resource_base_url(
                        site_id, enforcementpoint_id))
                edge_cluster_id = self.get_id_using_attr_name_else_fail(
                    "edge_cluster", edge_node_info,
                    edge_cluster_base_url, PolicyEdgeCluster.__name__)
                edge_node_base_url = PolicyEdgeNode.get_resource_base_url(
                    site_id, enforcementpoint_id, edge_cluster_id)
                edge_node_id = self.get_id_using_attr_name_else_fail(
                    "edge_node", edge_node_info, edge_node_base_url,
                    PolicyEdgeNode.__name__)
                self.resource_params["edge_path"] = (
                    edge_node_base_url + "/" + edge_node_id)

        class NSXTTier0LocaleServiceBGP(NSXTBaseRealizableResource):
            def __init__(self):
                self.id = 'bgp'
                super().__init__()

            def skip_delete(self):
                return True

            def get_unique_arg_identifier(self):
                return (
                    NSXTTier0.NSXTTier0LocaleService.NSXTTier0LocaleServiceBGP.
                    get_unique_arg_identifier())

            @staticmethod
            def get_unique_arg_identifier():
                return "t0ls_bgp"

            @staticmethod
            def get_resource_spec():
                tier0_ls_bgp_arg_spec = {}
                tier0_ls_bgp_arg_spec.update(
                    ecmp=dict(
                        required=False,
                        default=True,
                        type='bool'
                    ),
                    enabled=dict(
                        required=False,
                        default=True,
                        type='bool'
                    ),
                    graceful_restart_config=dict(
                        required=False,
                        type='dict',
                        options=dict(
                            mode=dict(
                                required=False,
                                type='str',
                                choices=['DISABLE', 'GR_AND_HELPER',
                                         'HELPER_ONLY'],
                                default='HELPER_ONLY'
                            ),
                            timer=dict(
                                required=False,
                                type='dict',
                                options=dict(
                                    restart_timer=dict(
                                        required=False,
                                        type='int',
                                        default=180
                                    ),
                                    stale_route_timer=dict(
                                        required=False,
                                        type='int',
                                        default=600
                                    ),
                                )
                            )
                        )
                    ),
                    inter_sr_ibgp=dict(
                        required=False,
                        type='bool'
                    ),
                    local_as_num=dict(
                        required=True,
                        type='str'
                    ),
                    multipath_relax=dict(
                        required=False,
                        type='bool',
                        default=True
                    ),
                    route_aggregations=dict(
                        required=False,
                        type='list',
                        options=dict(
                            prefix=dict(
                                required=True,
                                type='str'
                            ),
                            summary_only=dict(
                                required=False,
                                type='bool',
                                default=True
                            )
                        )
                    )
                )
                return tier0_ls_bgp_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier0_id = parent_info.get("tier0_id", 'default')
                locale_service_id = parent_info.get("t0ls_id", 'default')
                return ('/infra/tier-0s/{}/locale-services/{}'
                        .format(tier0_id, locale_service_id))

            class NSXTTier0LocaleServiceBGPNeighbor(
                    NSXTBaseRealizableResource):
                def get_unique_arg_identifier(self):
                    return (
                        NSXTTier0.NSXTTier0LocaleService.
                        NSXTTier0LocaleServiceBGP.
                        get_unique_arg_identifier())

                @staticmethod
                def get_unique_arg_identifier():
                    return "t0ls_bgp_neighbor"

                @staticmethod
                def get_resource_spec():
                    tier0_ls_bgp_neighbor_arg_spec = {}
                    tier0_ls_bgp_neighbor_arg_spec.update(
                        allow_as_in=dict(
                            required=False,
                            default=False,
                            type='bool'
                        ),
                        bfd=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                enabled=dict(
                                    required=False,
                                    default=False,
                                    type='bool'
                                ),
                                interval=dict(
                                    required=False,
                                    type='int',
                                    default=1000
                                ),
                                multiple=dict(
                                    required=False,
                                    type='int',
                                    default=3
                                )
                            )
                        ),
                        graceful_restart_mode=dict(
                            type='str',
                            required=False,
                            choices=['DISABLE', 'GR_AND_HELPER', 'HELPER_ONLY']
                        ),
                        hold_down_time=dict(
                            required=False,
                            type='int',
                            default=180
                        ),
                        keep_alive_time=dict(
                            required=False,
                            type='int',
                            default=60
                        ),
                        maximum_hop_limit=dict(
                            required=False,
                            type='int',
                            default=1
                        ),
                        neighbor_address=dict(
                            required=True,
                            type='str'
                        ),
                        remote_as_num=dict(
                            required=True,
                            type='str'
                        ),
                        route_filtering=dict(
                            required=False,
                            type=dict,
                            options=dict(
                                address_family=dict(
                                    required=False,
                                    type='str',
                                    choices=['IPV4', 'IPV6', 'VPN']
                                ),
                                enabled=dict(
                                    type='bool',
                                    default=True,
                                    required=False
                                ),
                                in_route_filters=dict(
                                    type='list',
                                    required=False
                                ),
                                out_route_filters=dict(
                                    type='list',
                                    required=False
                                )
                            )
                        ),
                        source_addresses=dict(
                            required=False,
                            type='list'
                        )
                    )
                    return tier0_ls_bgp_neighbor_arg_spec

                @staticmethod
                def get_resource_base_url(parent_info):
                    tier0_id = parent_info.get("tier0_id", 'default')
                    locale_service_id = parent_info.get("t0ls_id", 'default')
                    return ('/infra/tier-0s/{}/locale-services/{}'
                            '/bgp/neighbors'.format(tier0_id,
                                                    locale_service_id))


if __name__ == '__main__':
    nsxt_tier0 = NSXTTier0()
    nsxt_tier0.realize()
