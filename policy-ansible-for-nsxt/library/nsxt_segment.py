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
    display_name:
        description:
            - Display name.
            - If resource ID is not specified, display_name will be used as ID.
        required: false
        type: str
    state:
        choices:
        - present
        - absent
        description: "State can be either 'present' or 'absent'.
                    'present' is used to create or update resource.
                    'absent' is used to delete resource."
        required: true
    validate_certs:
        description: Enable server certificate verification.
        type: bool
        default: False
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
    create_or_update_subresource_first:
        type: bool
        default: false
        description:
            - Can be used to create subresources first.
            - Can be specified for each subresource.
    delete_subresource_first:
        type: bool
        default: true
        description:
            - Can be used to delete subresources first.
            - Can be specified for each subresource.
    achieve_subresource_state_if_del_parent:
        type: bool
        default: false
        description:
            - Can be used to achieve the state of subresources even if
              the parent(base) resource's state is absent.
            - Can be specified for each subresource.
    do_wait_till_create:
        type: bool
        default: false
        description:
            - Can be used to wait for the realization of subresource before the
              request to create the next resource is sent to the Manager.
            - Can be specified for each subresource.
    id:
        description: The id of the Policy Segment.
        required: false
        type: str
    description:
        description: Segment description.
        type: str
    address_bindings:
        description: Address bindings for the Segment
        type: list
        elements: dict
        suboptions:
            ip_address:
                description: IP Address for port binding
                type: str
            mac_address:
                description: Mac address for port binding
                type: str
            vlan_id:
                description: VLAN ID for port binding
                type: int
    advanced_config:
        description: Advanced configuration for Segment.
        type: dict
        suboptions:
            address_pool_display_name:
                description:
                    - IP address pool display name
                    - Either this or address_pool_id must be specified. If both
                      are specified, address_pool_id takes precedence
                type: str
            address_pool_id:
                description:
                    - IP address pool ID
                    - Either this or address_pool_display_name must be
                      specified. If both are specified, address_pool_id takes
                      precedence
                type: str
            connectivity:
                description: Connectivity configuration to manually connect
                             (ON) or disconnect (OFF) a logical entity from
                             network topology. Only valid for Tier1 Segment
                type: str
            hybrid:
                description:
                    - Flag to identify a hybrid logical switch
                    - When set to true, all the ports created on this segment
                      will behave in a hybrid fashion. The hybrid port
                      indicates to NSX that the VM intends to operate in
                      underlay mode, but retains the ability to forward egress
                      traffic to the NSX overlay network. This property is only
                      applicable for segment created with transport zone type
                      OVERLAY_STANDARD. This property cannot be modified after
                      segment is created.
                type: bool
            local_egress:
                description:
                    - Flag to enable local egress
                    - This property is used to enable proximity routing with
                      local egress. When set to true, logical router interface
                      (downlink) connecting Segment to Tier0/Tier1 gateway is
                      configured with prefix-length 32.
                type: bool
            local_egress_routing_policies:
                description: An ordered list of routing policies to forward
                             traffic to the next hop.
                type: list
                elements: dict
                suboptions:
                    nexthop_address:
                        required: true
                        description: Next hop address for proximity routing
                        type: str
                    prefix_list_paths:
                        required: true
                        description:
                            - Policy path to prefix lists
                            - max 1 element
                            - The destination address of traffic matching a
                              prefix-list is forwarded to the nexthop_address.
                              Traffic matching a prefix list with Action DENY
                              will be dropped. Individual prefix-lists
                              specified could have different actions.
                        type: list
                        elements: str
            multicast:
                description:
                    - Enable multicast on the downlink
                    - Enable multicast for a segment. Only applicable for
                      segments connected to Tier0 gateway.
                type: bool
            uplink_teaming_policy_name:
                description:
                    - Uplink Teaming Policy Name
                    - The name of the switching uplink teaming policy for the
                      Segment. This name corresponds to one of the switching
                      uplink teaming policy names listed in TransportZone
                      associated with the Segment. When this property is
                      not specified, the segment will not have a teaming policy
                      associated with it and the host switch's default teaming
                      policy will be used by MP.
                type: str
    replication_mode:
        description: Replication mode of the Segment
        type: str
        default: MTEP
        choices:
            - MTEP
            - SOURCE
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
    segment_ports:
        type: list
        description:
            - Add the Segment Ports to be create, updated, or deleted in this
              section
        element: dict
        suboptions:
            address_bindings:
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
            attachment:
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
                        description:
                            - VLAN ID
                            - Not valid when type is INDEPENDENT, mainly
                              used to identify traffic from different ports
                              in container use case
                        type: int
                    type:
                        description: Type of port attachment.
                        type: str
                        choices:
                            - PARENT
                            - CHILD
                            - INDEPENDENT
            display_name:
                description:
                    - Segment Port display name.
                    - Either this or id must be specified. If both are
                      specified, id takes precedence.
                required: false
                type: str
            description:
                description:
                    - Segment description.
                type: str
            do_wait_till_create:
                type: bool
                default: false
                description: Can be used to wait for the realization of
                             subresource before the request to create the next
                             resource is sent to the Manager
            extra_configs:
                description:
                    - Extra configs on segment port
                    - This property could be used for vendor specific
                      configuration in key value string pairs. Segment port
                      setting will override segment setting if the same key was
                      set on both segment and segment port.
                type: list
                element: dict
                suboptions:
                    config_pair:
                        description: Key value pair in string for the
                                     configuration
                        type: dict
                        required: true
                        suboptions:
                            key:
                                description: Key
                                type: str
                                required: true
                            value:
                                description: Value
                                type: str
                                required: true
            id:
                description: The id of the Policy Segment Port.
                required: false
                type: str
            ignored_address_bindings:
                description:
                    - Address bindings to be ignored by IP Discovery module
                      IP Discovery module uses various mechanisms to discover
                      address bindings being used on each segment port. If a
                      user would like to ignore any specific discovered address
                      bindings or prevent the discovery of a particular set of
                      discovered bindings, then those address bindings can be
                      provided here. Currently IP range in CIDR format is not
                      supported.
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
            init_state:
                description:
                    - Initial state of this logical ports
                    - Set initial state when a new logical port is created.
                      'UNBLOCKED_VLAN' means new port will be unblocked on
                      traffic in creation, also VLAN will be set with
                      corresponding logical switch setting. This port setting
                      can only be configured at port creation, and cannot be
                      modified.
                type: str
                choices:
                    - UNBLOCKED_VLAN
                default: UNBLOCKED_VLAN
            state:
                choices:
                    - present
                    - absent
                description:
                    - State can be either 'present' or 'absent'. 'present' is
                      used to create or update resource. 'absent' is used to
                      delete resource
                    - Required if I(id != null)
                required: true
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
'''

EXAMPLES = '''
- name: create Segment
  nsxt_segment:
    hostname: "10.10.10.10"
    username: "username"
    password: "password"
    validate_certs: False
    display_name: test-seg-4
    state: present
    domain_name: dn1
    transport_zone_display_name: "1-transportzone-730"
    replication_mode: "SOURCE"
    address_bindings:
      - ip_address: "10.1.2.11"
    advanced_config:
      address_pool_display_name: small-2-pool
      connectivity: "OFF"
      hybrid: True
      local_egress: True
    subnets:
      - gateway_address: "40.1.1.1/16"
    segment_ports:
      - display_name: test-sp-1
        state: present
        tags:
          - scope: "scope-1"
            tag: "tag-2"
        extra_configs:
          - config_pair:
              key: key
              value: value
        ignored_address_bindings:
          - ip_address: "10.1.2.122"
      - display_name: test-sp-2
        state: present
      - display_name: test-sp-3
        state: present
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils.nsxt_resource_urls import (
    SEGMENT_PORT_URL, SEGMENT_URL, TIER_0_URL, TIER_1_URL, TRANSPORT_ZONE_URL,
    IP_POOL_URL)
from ansible.module_utils._text import to_native


class NSXTSegment(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        segment_arg_spec = {}
        segment_arg_spec.update(
            address_bindings=dict(
                required=False,
                type='list',
                elements='dict',
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
            advanced_config=dict(
                required=False,
                type='dict',
                options=dict(
                    address_pool_id=dict(
                        required=False,
                        type='str'
                    ),
                    address_pool_display_name=dict(
                        required=False,
                        type='str'
                    ),
                    connectivity=dict(
                        default="ON",
                        type='str',
                        choices=["ON", "OFF"],
                    ),
                    hybrid=dict(
                        required=False,
                        type='bool',
                        default=False
                    ),
                    local_egress=dict(
                        required=False,
                        type='bool',
                        default=False
                    ),
                    local_egress_routing_policies=dict(
                        required=False,
                        type='list',
                        elements='dict',
                        options=dict(
                            nexthop_address=dict(
                                required=True,
                                type='str'
                            ),
                            prefix_list_paths=dict(
                                required=True,
                                type='list',
                                elements='str'
                            ),
                        )
                    ),
                    multicast=dict(
                        required=False,
                        type='bool'
                    ),
                    uplink_teaming_policy_name=dict(
                        required=False,
                        type='str'
                    ),
                )
            ),
            replication_mode=dict(
                type='str',
                default="MTEP",
                choices=["MTEP", "SOURCE"]
            ),
            subnets=dict(
                required=False,
                type='list',
                elements='dict',
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
        return SEGMENT_URL

    def update_resource_params(self, nsx_resource_params):
        if self.do_resource_params_have_attr_with_id_or_display_name(
                "tier0"):
            tier0_id = self.get_id_using_attr_name_else_fail(
                "tier0", nsx_resource_params,
                TIER_0_URL, "Tier0")
            nsx_resource_params["connectivity_path"] = (
                TIER_0_URL + "/" + tier0_id)
        elif self.do_resource_params_have_attr_with_id_or_display_name(
                "tier1"):
            tier1_id = self.get_id_using_attr_name_else_fail(
                "tier1", nsx_resource_params,
                TIER_1_URL, "Tier1")
            nsx_resource_params["connectivity_path"] = (
                TIER_1_URL + "/" + tier1_id)

        if self.do_resource_params_have_attr_with_id_or_display_name(
                "transport_zone"):
            site_id = nsx_resource_params.pop("site_id")
            enforcementpoint_id = nsx_resource_params.pop(
                "enforcementpoint_id")
            transport_zone_base_url = (
                TRANSPORT_ZONE_URL.format(site_id, enforcementpoint_id))
            transport_zone_id = self.get_id_using_attr_name_else_fail(
                "transport_zone", nsx_resource_params,
                transport_zone_base_url, "Transport Zone")
            nsx_resource_params["transport_zone_path"] = (
                transport_zone_base_url + "/" + transport_zone_id)

        if nsx_resource_params['advanced_config']:
            if nsx_resource_params['advanced_config'][
                    'address_pool_id']:
                address_pool_id = nsx_resource_params['advanced_config'].pop(
                    'address_pool_id')
                nsx_resource_params['advanced_config'].pop(
                    'address_pool_display_name')
            else:
                address_pool_id = self.get_id_from_display_name(
                    IP_POOL_URL, nsx_resource_params['advanced_config'][
                        'address_pool_display_name'], "Ip Pool",
                    ignore_not_found_error=False)
                nsx_resource_params['advanced_config'].pop(
                    'address_pool_display_name')
                nsx_resource_params['advanced_config'].pop(
                    'address_pool_id')
            if address_pool_id:
                address_pool_paths = [IP_POOL_URL + "/" + address_pool_id]
                nsx_resource_params['advanced_config'][
                    'address_pool_paths'] = address_pool_paths

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
                admin_state=dict(
                    required=False,
                    type='str',
                    default='UP',
                    choices=['UP', 'DOWN']
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
                ),
                extra_configs=dict(
                    required=False,
                    type='list',
                    elements='dict',
                    options=dict(
                        config_pair=dict(
                            required=True,
                            type='dict',
                            options=dict(
                                key=dict(
                                    required=True,
                                    type='str'
                                ),
                                value=dict(
                                    required=True,
                                    type='str'
                                )
                            )
                        ),
                    )
                ),
                ignored_address_bindings=dict(
                    required=False,
                    type='list',
                    elements='dict',
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
                init_state=dict(
                    type='str',
                    default='UNBLOCKED_VLAN',
                    choices=['UNBLOCKED_VLAN']
                )
            )
            return segment_port_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            segment_id = parent_info.get("segment_id", 'default')
            return SEGMENT_PORT_URL.format(segment_id)


if __name__ == '__main__':
    segment = NSXTSegment()
    segment.realize()
