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
short_description: Create or Delete a Policy Load Balancer Service
description:
    Creates or deletes a Policy Load Balancer Service.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: The id of the Policy Load Balancer Service.
        required: true
        type: str
    description:
        description: Load Balancer Service description.
        type: str
    enabled:
        description: Flag to enable the load balancer service
        type: bool
        default: true
    error_log_level:
        description:
            - Error log level of load balancer service
            - Load balancer engine writes information about
              encountered issues of different severity levels to the
              error log. This setting is used to define the severity
              level of the error log.
        type: str
        choices:
            - "DEBUG"
            - "INFO"
            - "WARNING"
            - "ERROR"
            - "CRITICAL"
            - "ALERT"
            - "EMERGENCY"
    size:
        description: Load balancer service size
        type: str
        choices:
            - "SMALL"
            - "MEDIUM"
            - "LARGE"
            - "DLB"
    tier_1_id:
        description:
            - Tier1 UUID.
            - LBS could be instantiated (or created) on the Tier-1,
              etc. For now, only the Tier-1 object is supported.
        type: str
'''

EXAMPLES = '''
- name: create Load Balancer Service
  nsxt_security_policy:
  hostname: "10.160.84.49"
  username: "admin"
  password: "Admin!23Admin"
  validate_certs: False
  id: test-lb-service
  display_name: test-lb-service
  state: "present"
  tier_1_id: "test-tier1"
  size: "SMALL"
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

    from library.nsxt_tier1 import NSXTTier1


class NSXTLoadBalancerService(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        loadbalancer_service_arg_spec = {}
        loadbalancer_service_arg_spec.update(
            enabled=dict(
                required=False,
                type='bool',
                default=True
            ),
            error_log_level=dict(
                required=False,
                type='str',
                default="INFO"
            ),
            size=dict(
                rquired=False,
                type='str',
                default="SMALL"
            ),
            tier_1_id=dict(
                required=False,
                type='str'
            )
        )
        return loadbalancer_service_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args):
        return '/infra/lb-services'

    def update_resource_params(self):
        if "tier_1_id" in self.resource_params:
            tier_1_id = self.resource_params.pop("tier_1_id")
            self.resource_params["connectivity_path"] = (
                NSXTTier1.get_resource_base_url() + "/" + tier_1_id)


if __name__ == '__main__':
    loadbalancer_service = NSXTLoadBalancerService()
    loadbalancer_service.realize()
