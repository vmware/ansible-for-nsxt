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
