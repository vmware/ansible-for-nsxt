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

class NSXTSegment(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        segment_arg_spec = {}
        segment_arg_spec.update(
            subnets=dict(
                required=False,
                type='list',
                options=dict(
                    dhcp_ranges=dict(
                        required=False,
                        type='list'
                    ),
                    gateway_address=dict(
                        required=True,
                        type='str'
                    )
                )
            ),
            tier0_id=dict(
                required=False,
                type='str'
            ),
            tier0_display_name=dict(
                required=False,
                type='str'
            ),
            tier1_id=dict(
                required=False,
                type='str'
            ),
            tier1_display_name=dict(
                required=False,
                type='str'
            ),
            domain_name=dict(
                required=False,
                type='str'
            ),
            vlan_ids=dict(
                required=False,
                type='list'
            ),
            transport_zone_id=dict(
                required=False,
                type='str'
            ),
            transport_zone_display_name=dict(
                required=False,
                type='str'
            ),
            site_id=dict(
                required=False,
                type='str',
                default="default"
            ),
            enforcementpoint_id=dict(
                required=False,
                type='str',
                default="default"
            )
        )
        return segment_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return '/infra/segments'

    def update_resource_params(self, nsx_resource_params):
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "tier0"):
            tier0_base_url = NSXTTier0.get_resource_base_url()
            tier0_id = self.get_id_using_attr_name_else_fail(
                "tier0", nsx_resource_params,
                tier0_base_url, "Tier0")
            nsx_resource_params["connectivity_path"] = (
                tier0_base_url + "/" + tier0_id)
        elif self.do_resource_params_have_attr_with_id_or_display_name(
                "tier1"):
            tier1_base_url = NSXTTier1.get_resource_base_url()
            tier1_id = self.get_id_using_attr_name_else_fail(
                "tier1", nsx_resource_params,
                tier1_base_url, "Tier1")
            nsx_resource_params["connectivity_path"] = (
                tier1_base_url + "/" + tier1_id)

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "transport_zone"):
            site_id = nsx_resource_params.pop("site_id")
            enforcementpoint_id = nsx_resource_params.pop(
                "enforcementpoint_id")
            transport_zone_base_url = (
                NSXTPolicyTransportZone.get_resource_base_url(
                    site_id, enforcementpoint_id))
            transport_zone_id = self.get_id_using_attr_name_else_fail(
                "transport_zone", nsx_resource_params,
                transport_zone_base_url, "Transport Zone")
            nsx_resource_params["transport_zone_path"] = (
                transport_zone_base_url + "/" + transport_zone_id)

    def update_parent_info(self, parent_info):
        parent_info["segment_id"] = self.id

    class NSXTSegmentPort(NSXTBaseRealizableResource):
        def get_spec_identifier(self):
            return NSXTSegment.NSXTSegmentPort.get_spec_identifier()

        @classmethod
        def get_spec_identifier(cls):
            return "segment_ports"

        @staticmethod
        def get_resource_spec():
            segment_port_arg_spec = {}
            segment_port_arg_spec.update(
                address_bindings=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        ip_address=dict(
                            required=False,
                            type='str'
                        ),
                        mac_address=dict(
                            required=False,
                            type='str'
                        ),
                        vlan_id=dict(
                            required=False,
                            type='int'
                        )
                    )
                ),
                attachment=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        allocate_addresses=dict(
                            required=False,
                            type='str',
                            choices=['IP_POOL', 'MAC_POOL', 'BOTH', 'NONE']
                        ),
                        app_id=dict(
                            required=False,
                            type='str',
                        ),
                        context_id=dict(
                            required=False,
                            type='str',
                        ),
                        id=dict(
                            required=False,
                            type='str',
                        ),
                        traffic_tag=dict(
                            required=False,
                            type='int'
                        ),
                        type=dict(
                            required=False,
                            type='str',
                            choices=['PARENT', 'CHILD', 'INDEPENDENT']
                        )
                    )
                )
            )
            return segment_port_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            segment_id = parent_info.get("segment_id", 'default')
            return '/infra/segments/{}/ports'.format(segment_id)
