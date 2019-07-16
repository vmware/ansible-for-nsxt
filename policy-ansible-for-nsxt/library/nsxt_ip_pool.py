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
module: nsxt_ip_pool
short_description: Create or Delete a Policy IP Pool
description:
    Creates or deletes a Policy IP Pool.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: The id of the Policy IP Pool.
        required: true
        type: str
    description:
        description: IP Pool description.
        type: str
    ip_block_id:
        description: The ID of the IpAddressBlock from which the subnet is to
                     be created.
        type: str
        required=false
    ip_block_display_name:
        description: Same as ip_block_id. Either one must be specified.
                     If both are specified, ip_block_id takes
                     precedence.
        required: false
        type: str
    auto_assign_gateway:
        description:
            - Indicate whether default gateway is to be reserved from the range
            - If this property is set to true, the first IP in the range will
              be reserved for gateway.
        type: bool
        default: true
    size:
        description:
            - Represents the size or number of IP addresses in the subnet
            - The size parameter is required for subnet creation. It must be
              specified during creation but cannot be changed later.
        type: int
'''

EXAMPLES = '''
- name: create IP Pool
  nsxt_ip_pool:
    hostname: "10.160.84.49"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      id: test-ip-pool
      display_name: test-ip-pool
      state: "absent"
      tags:
      - tag: "a"
        scope: "b"
      ip_subnet_id: test-ip-subnet
      ip_subnet_display_name: test-ip-subnet
      ip_subnet_state: "present"
      ip_subnet_ip_block_display_neme: "test-ip-blk"
      ip_subnet_size: 16
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils._text import to_native


if __name__ == '__main__':
    import os
    import sys
    sys.path.append(os.getcwd())

    from library.nsxt_ip_block import NSXTIpBlock


class NSXTIpPool(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        ip_pool_arg_spec = {}
        return ip_pool_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return '/infra/ip-pools'

    def update_parent_info(self, parent_info):
        parent_info["ip_pool_id"] = self.id

    class NSXTIpAddressPoolBlockSubnet(NSXTBaseRealizableResource):
        def get_unique_arg_identifier(self):
            return (NSXTIpPool.NSXTIpAddressPoolBlockSubnet.
                    get_unique_arg_identifier())

        @staticmethod
        def get_unique_arg_identifier():
            return "ip_subnet"

        @staticmethod
        def get_resource_spec():
            ip_addr_pool_blk_subnet_arg_spec = {}
            ip_addr_pool_blk_subnet_arg_spec.update(
                ip_block_id=dict(
                    required=False,
                    type='str'
                ),
                ip_block_display_name=dict(
                    required=False,
                    type='str'
                ),
                auto_assign_gateway=dict(
                    required=False,
                    type='bool'
                ),
                size=dict(
                    required=False,
                    type='int'
                )
            )
            return ip_addr_pool_blk_subnet_arg_spec

        @staticmethod
        def get_resource_base_url(parent_info):
            return '/infra/ip-pools/{}/ip-subnets'.format(
                parent_info["ip_pool_id"]
            )

        def update_resource_params(self):
            # ip_block is a required attr
            ip_block_base_url = NSXTIpBlock.get_resource_base_url()
            ip_block_id = self.get_id_using_attr_name_else_fail(
                "ip_block", self.resource_params,
                ip_block_base_url, "IP Block")
            self.resource_params["ip_block_path"] = (
                ip_block_base_url + "/" + ip_block_id)

            self.resource_params["resource_type"] = "IpAddressPoolBlockSubnet"


if __name__ == '__main__':
    ip_pool = NSXTIpPool()
    ip_pool.realize()
