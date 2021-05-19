#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
module: nsxt_policy_ip_block
short_description: Create or Delete a Policy IP Block
description:
    Creates or deletes a Policy IP Block.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment:
    - vmware.ansible_for_nsxt.vmware_nsxt
options:
    id:
        description: The id of the Policy IP Block.
        required: false
        type: str
    description:
        description: IP Block description.
        type: str
    cidr:
        description:
            - A contiguous IP address space represented by network address
              and prefix length
            - Represents a network address and the prefix length which will
              be associated with a layer-2 broadcast domain. Support only IPv4
              CIDR.
        required: true
        type: str
'''

EXAMPLES = '''
- name: create IP Block
  nsxt_policy_ip_block:
    hostname: "10.10.10.10"
    nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
    nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
    validate_certs: False
    id: test-ip-blk
    display_name: test-ip-blk
    state: "present"
    cidr: "192.168.0.0/16"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import IP_BLOCK_URL
from ansible.module_utils._text import to_native


class NSXTIpBlock(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        ip_block_arg_spec = {}
        ip_block_arg_spec.update(
            cidr=dict(
                required=True,
                type='str'
            )
        )
        return ip_block_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return IP_BLOCK_URL


if __name__ == '__main__':
    ip_block = NSXTIpBlock()
    ip_block.realize()
