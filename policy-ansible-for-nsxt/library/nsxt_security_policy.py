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
module: nsxt_security_policy
short_description: Create or Delete a Policy Security Policy
description:
    Creates or deletes a Policy Security Policy.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: The id of the Policy Security Policy.
        required: true
        type: str
    description:
        description: Security Policy description.
        type: str
'''

EXAMPLES = '''
- name: create Security Policy
  nsxt_Security Policy:
    hostname: "10.178.14.49"
    username: "uname"
    password: "password"
    state: "present"
    validate_certs: False
    id: test-seg1
    display_name: test-seg3
    tier_1_id: "k8s-node-lr"
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

from ansible.module_utils.logger import Logger
logger=Logger.getInstance()

if __name__ == '__main__':
    from ansible.module_utils.nsxt_policy_transport_zone import (
        NSXTPolicyTransportZone)

    import os
    import sys
    sys.path.append(os.getcwd())

    from library.nsxt_tier0 import NSXTTier0
    from library.nsxt_tier1 import NSXTTier1


class NSXTSecurityPolicy(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        security_policy_arg_spec = {}
        security_policy_arg_spec.update(
            domain_id=dict(
                required=True,
                type='str'
            ),
            category=dict(
                required=False,
                type='str'
            ),
            rules=dict(
                required=False,
                type='list'
            ),
            scope=dict(
                required=False,
                type='list'
            ),
            sequence_number=dict(
                required=False,
                type='int'
            )
        )
        return security_policy_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args):
        logger.log("a"+str(baseline_args["domain_id"]))
        return '/infra/domains/{}/security-policies'.format(
            baseline_args["domain_id"])

if __name__ == '__main__':
    segment = NSXTSecurityPolicy()
    segment.realize(baseline_arg_names=["domain_id"])
