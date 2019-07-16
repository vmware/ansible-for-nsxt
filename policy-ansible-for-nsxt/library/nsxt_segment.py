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
---
module: nsxt_segment
short_description: Create or Delete a Policy Segment
description:
    Creates or deletes a Policy Segment.
    Required attributes include id and display_name.
    If the specified TransportZone is of VLAN type, a vlan_id is also required.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: The id of the Policy Segment.
        required: true
        type: str
    description:
        description: Segment description.
        type: str
    tier0_id:
        description: The Uplink of the Policy Segment.
                     Mutually exclusive with tier_1_id.
        type: str
    tier0_display_name:
        description: Same as tier_0_id. Either one can be specified.
                     If both are specified, tier_0_id takes
                     precedence.
        type: str
    tier1_id:
        description: The Uplink of the Policy Segment.
                     Mutually exclusive with tier_0_id but takes precedence.
        type: str
    tier1_display_name:
        description: Same as tier_1_id. Either one can be specified.
                     If both are specified, tier_1_id takes
                     precedence.
        type: str
    domain_name:
        description: Domain name associated with the Policy Segment.
        type: str
    transport_zone_id:
        description: The TZ associated with the Policy Segment.
        type: str
    transport_zone_display_name:
        description: Same as transport_zone_id. Either one can be specified.
                     If both are specified, transport_zone_id takes
                     precedence.
        type: str
    enforcementpoint_id:
        description: The EnforcementPoint ID where the TZ is located.
                     Required if transport_zone_id is specified.
        default: default
        type: str
    site_id:
        description: The site ID where the EnforcementPoint is located.
                     Required if transport_zone_id is specified.
        default: default
        type: str
    vlan_ids:
        description: VLAN ids for a VLAN backed Segment.
                     Can be a VLAN id or a range of VLAN ids specified with '-'
                     in between.
        type: list
    subnets:
        description: Subnets that belong to this Policy Segment.
        type: dict
        suboptions:
            dhcp_ranges:
                description: DHCP address ranges for dynamic IP allocation.
                             DHCP address ranges are used for dynamic IP
                             allocation. Supports address range and CIDR
                             formats. First valid host address from the first
                             value is assigned to DHCP server IP address.
                             Existing values cannot be deleted or modified, but
                             additional DHCP ranges can be added.
                             Formats, e.g. 10.12.2.64/26, 10.12.2.2-10.12.2.50
                type: list
            gateway_address:
                description: Gateway IP address.
                             Gateway IP address in CIDR format for both IPv4
                             and IPv6.
                required: True
                type: str
    segp_id:
        description: The id of the Policy Segment Port.
        required: false
        type: str
    segp_display_name:
        description:
            - Segment Port display name.
            - Either this or segp_id must be specified. If both are specified,
              segp_id takes precedence.
        required: false
        type: str
    segp_description:
        description:
            - Segment description.
        type: str
    segp_tags:
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
    segp_state:
        choices:
            - present
            - absent
        description:
            - "State can be either 'present' or 'absent'. 'present' is used to
              create or update resource. 'absent' is used to delete resource."
            - Required if I(segp_id != null)."
        required: true
    segp_address_bindings:
        description: Static address binding used for the port.
        type: dict
        suboptions:
            ip_address:
                description: IP Address for port binding.
                type: str
            mac_address:
                description: Mac address for port binding.
                type: str
            vlan_id:
                description: VLAN ID for port binding.
                type: str
    segp_attachment:
        description: VIF attachment.
        type: dict
        suboptions:
            allocate_addresses:
                description: Indicate how IP will be
                             allocated for the port.
                type: str
                choices:
                    - IP_POOL
                    - MAC_POOL
                    - BOTH
                    - NONE
            app_id:
                description: ID used to identify/look up a
                             child attachment behind a
                             parent attachment.
                type: str
            context_id:
                description: Parent VIF ID if type is CHILD,
                             Transport node ID if type is
                             INDEPENDENT.
                type: str
            id:
                description: VIF UUID on NSX Manager.
                type: str
            traffic_tag:
                description: VLAN ID
                             Not valid when type is INDEPENDENT, mainly used to
                             identify traffic from different ports in container
                             use case.
                type: int
            type:
                description: Type of port attachment.
                type: str
                choices:
                    - PARENT
                    - CHILD
                    - INDEPENDENT
'''

EXAMPLES = '''
- name: create Segment
  nsxt_segment:
    hostname: "10.178.14.49"
    username: "uname"
    password: "password"
    state: "present"
    validate_certs: False
    id: test-seg1
    display_name: test-seg3
    tier1_id: "k8s-node-lr"
    domain_name: "dn1"
    transport_zone_id: "5f0ea34b-7549-4303-be1e-2ef7ea3155e2"
    subnets:
    - gateway_address: "40.1.1.1/16"
      dhcp_ranges: [ "40.1.2.0/24" ]
    segp_id: "test-sp"
    segp_display_name: "test-sp"
    segp_state: "present"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils._text import to_native

if __name__ == '__main__':
    from ansible.module_utils.nsxt_policy_transport_zone import (
        NSXTPolicyTransportZone)

    import os
    import sys
    sys.path.append(os.getcwd())

    from library.nsxt_tier0 import NSXTTier0
    from library.nsxt_tier1 import NSXTTier1


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

    def update_resource_params(self):
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "tier0"):
            tier0_base_url = NSXTTier0.get_resource_base_url()
            tier0_id = self.get_id_using_attr_name_else_fail(
                "tier0", self.resource_params,
                tier0_base_url, "Tier0")
            self.resource_params["connectivity_path"] = (
                tier0_base_url + "/" + tier0_id)
        elif self.do_resource_params_have_attr_with_id_or_display_name(
                "tier1"):
            tier1_base_url = NSXTTier1.get_resource_base_url()
            tier1_id = self.get_id_using_attr_name_else_fail(
                "tier1", self.resource_params,
                tier1_base_url, "Tier1")
            self.resource_params["connectivity_path"] = (
                tier1_base_url + "/" + tier1_id)

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "transport_zone"):
            site_id = self.resource_params.pop("site_id")
            enforcementpoint_id = self.resource_params.pop(
                "enforcementpoint_id")
            transport_zone_base_url = (
                NSXTPolicyTransportZone.get_resource_base_url(
                    site_id, enforcementpoint_id))
            transport_zone_id = self.get_id_using_attr_name_else_fail(
                "transport_zone", self.resource_params,
                transport_zone_base_url, "Transport Zone")
            self.resource_params["transport_zone_path"] = (
                transport_zone_base_url + "/" + transport_zone_id)

    def update_parent_info(self, parent_info):
        parent_info["segment_id"] = self.id

    class NSXTSegmentPort(NSXTBaseRealizableResource):
        def get_unique_arg_identifier(self):
            return NSXTSegment.NSXTSegmentPort.get_unique_arg_identifier()

        @staticmethod
        def get_unique_arg_identifier():
            return "segp"

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


if __name__ == '__main__':
    segment = NSXTSegment()
    segment.realize()
