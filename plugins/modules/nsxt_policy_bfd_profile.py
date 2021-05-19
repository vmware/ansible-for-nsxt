#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 VMware, Inc.
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
module: nsxt_policy_bfd_profile
short_description: Create or Delete a Policy BFD Profile
description:
    Creates or deletes a Policy BFD Profile.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment:
    - vmware.ansible_for_nsxt.vmware_nsxt
options:
    id:
        description: The id of the BFD Profile.
        required: true
        type: str
    description:
        description: BFD Profile description.
        type: str
    interval:
        description:
            - Time interval between heartbeat packets in milliseconds
            - Should be in the range [50-60000]
        type: int
        default: 500
    multiple:
        description:
            - Declare dead multiple.
            - Number of times heartbeat packet is missed before BFD declares
              the neighbor is down.
            - Should be in the range [2-16]
        type: int
        default: 3
'''

EXAMPLES = '''
- name: Update BFD Profile
  nsxt_policy_bfd_profile:
    hostname: "10.10.10.10"
    nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
    nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
    validate_certs: False
    display_name: test-bfd-profile
    state: present
    interval: 200
    multiple: 10
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import BFD_PROFILE_URL
from ansible.module_utils._text import to_native


class NSXTBFDProfile(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        bfd_profile_arg_spec = {}
        bfd_profile_arg_spec.update(
            interval=dict(
                default=500,
                type='int'
            ),
            multiple=dict(
                default=3,
                type='int'
            )
        )
        return bfd_profile_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return BFD_PROFILE_URL


if __name__ == '__main__':
    bfd_profile = NSXTBFDProfile()
    bfd_profile.realize()
