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

from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource

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

    def update_parent_info(self, parent_info):
        parent_info["tier0_id"] = self.id

    class NSXTTier0StaticRoutes(NSXTBaseRealizableResource):
        def get_spec_identifier(self):
            return NSXTTier0.NSXTTier0StaticRoutes.get_spec_identifier()

        @classmethod
        def get_spec_identifier(cls):
            return "static_routes"

        @staticmethod
        def get_resource_spec():
            tier0_sr_arg_spec = {}
            tier0_sr_arg_spec.update(
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
            return tier0_sr_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier0_id = parent_info.get("tier0_id", 'default')
            return '/infra/tier-0s/{}/static-routes'.format(tier0_id)

    class NSXTTier0LocaleService(NSXTBaseRealizableResource):
        def get_spec_identifier(self):
            return NSXTTier0.NSXTTier0LocaleService.get_spec_identifier()

        @classmethod
        def get_spec_identifier(cls):
            return "locale_services"

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
                    elements='dict',
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
                        external_interface_info=dict(
                            required=True,
                            type='list',
                            elements='dict',
                            options=dict(
                                id=dict(
                                    type='str'
                                ),
                                display_name=dict(
                                    type='str'
                                )
                            )
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
            return tier0_ls_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            tier0_id = parent_info.get("tier0_id", 'default')
            return '/infra/tier-0s/{}/locale-services'.format(tier0_id)

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
                            NSXTTier0.NSXTTier0LocaleService.
                            NSXTTier0Interface.get_resource_base_url(
                                self.get_parent_info()))
                        external_interface_paths.append(
                            interface_base_url + "/" +
                            self.get_id_using_attr_name_else_fail(
                                None, external_interface,
                                interface_base_url,
                                NSXTTier0.NSXTTier0LocaleService.
                                NSXTTier0Interface,
                                ignore_not_found_error=False))
                    ha_vip_config[
                        'external_interface_paths'] = external_interface_paths

        def update_parent_info(self, parent_info):
            parent_info["ls_id"] = self.id

        class NSXTTier0Interface(NSXTBaseRealizableResource):
            def get_spec_identifier(self):
                return (
                    NSXTTier0.NSXTTier0LocaleService.NSXTTier0Interface.
                    get_spec_identifier())

            @classmethod
            def get_spec_identifier(cls):
                return "interfaces"

            @staticmethod
            def get_resource_spec():
                tier0_ls_int_arg_spec = {}
                tier0_ls_int_arg_spec.update(
                    segment_id=dict(
                        type='str'
                    ),
                    segment_display_name=dict(
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
                        type='str',
                        default="EXTERNAL",
                        choices=["EXTERNAL", "SERVICE", "LOOPBACK"]
                    )
                )
                return tier0_ls_int_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier0_id = parent_info.get("tier0_id", 'default')
                locale_service_id = parent_info.get("ls_id", 'default')
                return ('/infra/tier-0s/{}/locale-services/{}/interfaces'
                        .format(tier0_id, locale_service_id))

            def update_resource_params(self, nsx_resource_params):
                # segment_id is a required attr
                segment_base_url = NSXTSegment.get_resource_base_url()
                segment_id = self.get_id_using_attr_name_else_fail(
                    "segment", nsx_resource_params,
                    segment_base_url,
                    "Segment")
                nsx_resource_params["segment_path"] = (
                    segment_base_url + "/" + segment_id)

                # edge_node_info is a required attr
                edge_node_info = nsx_resource_params.pop("edge_node_info")
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
                nsx_resource_params["edge_path"] = (
                    edge_node_base_url + "/" + edge_node_id)

        class NSXTTier0LocaleServiceBGP(NSXTBaseRealizableResource):
            def __init__(self):
                self.id = 'bgp'
                super().__init__()

            def skip_delete(self):
                return True

            def get_spec_identifier(self):
                return (
                    NSXTTier0.NSXTTier0LocaleService.NSXTTier0LocaleServiceBGP.
                    get_spec_identifier())

            @classmethod
            def get_spec_identifier(cls):
                return "BGP"

            @staticmethod
            def get_resource_spec():
                tier0_ls_arg_spec = {}
                tier0_ls_arg_spec.update(
                    ecmp=dict(
                        default=True,
                        type='bool'
                    ),
                    enabled=dict(
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
                        type='str'
                    ),
                    multipath_relax=dict(
                        type='bool',
                        default=True
                    ),
                    route_aggregations=dict(
                        required=False,
                        type='list',
                        elements='dict',
                        options=dict(
                            prefix=dict(
                                required=True,
                                type='str'
                            ),
                            summary_only=dict(
                                type='bool',
                                default=True
                            )
                        )
                    )
                )
                return tier0_ls_arg_spec

            @staticmethod
            def get_resource_base_url(parent_info):
                tier0_id = parent_info.get("tier0_id", 'default')
                locale_service_id = parent_info.get("ls_id", 'default')
                return ('/infra/tier-0s/{}/locale-services/{}'
                        .format(tier0_id, locale_service_id))

            @classmethod
            def allows_multiple_resource_spec(cls):
                return False

            class NSXTTier0LocaleServiceBGPNeighbor(
                    NSXTBaseRealizableResource):
                def get_spec_identifier(self):
                    return (
                        NSXTTier0.NSXTTier0LocaleService.
                        NSXTTier0LocaleServiceBGP.
                        get_spec_identifier())

                @classmethod
                def get_spec_identifier(cls):
                    return "neighbors"

                @staticmethod
                def get_resource_spec():
                    tier0_ls_arg_spec = {}
                    tier0_ls_arg_spec.update(
                        allow_as_in=dict(
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
                            type='int',
                            default=180
                        ),
                        keep_alive_time=dict(
                            type='int',
                            default=60
                        ),
                        maximum_hop_limit=dict(
                            type='int',
                            default=1
                        ),
                        password=dict(
                            type='str',
                            required=False
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
                        ),
                        neighbor_address=dict(
                            required=True,
                            type='str'
                        )
                    )
                    return tier0_ls_arg_spec

                @staticmethod
                def get_resource_base_url(parent_info):
                    tier0_id = parent_info.get("tier0_id", 'default')
                    locale_service_id = parent_info.get("ls_id", 'default')
                    return ('/infra/tier-0s/{}/locale-services/{}'
                            '/bgp/neighbors'.format(tier0_id,
                                                    locale_service_id))
