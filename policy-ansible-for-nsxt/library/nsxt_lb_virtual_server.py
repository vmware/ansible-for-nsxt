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
short_description: Create or Delete a Policy Load Balancer Virtual Server
description:
    Creates or deletes a Policy Load Balancer Virtual Server.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment: vmware_nsxt
options:
    id:
        description: The id of the Policy Load Balancer Virtual Server.
        required: true
        type: str
    description:
        description: Load Balancer Virtual Server description.
        type: str
'''

EXAMPLES = '''
- name: create Load Balancer Virtual Server
  nsxt_security_policy:
  hostname: "10.160.84.49"
  username: "admin"
  password: "Admin!23Admin"
  validate_certs: False
  id: test-lb-service
  display_name: test-lb-service
  state: "present"
  ip_address: "30.1.1.1"
  ports: ["1019"]
  application_profile_id: "default-tcp-lb-app-profile"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils._text import to_native


if __name__ == '__main__':
    from ansible.module_utils.nsxt_application_profile import (
        PolicyApplicationProfile)
    from ansible.module_utils.nsxt_lb_pers_profile import (
        PolicyLBPersistenceProfile)

    import os
    import sys
    sys.path.append(os.getcwd())

    from library.nsxt_lb_service import NSXTLoadBalancerService


class NSXTLoadBalancerVirtualServer(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        loadbalancer_vs_arg_spec = {}
        loadbalancer_vs_arg_spec.update(
            application_profile_id=dict(
                required=True,
                type='str'
            ),
            access_log_enabled=dict(
                required=False,
                type='bool',
                default=False
            ),
            enabled=dict(
                required=False,
                type='bool',
                default=True
            ),
            ip_address=dict(
                required=True,
                type='str'
            ),
            lb_persistence_profile_id=dict(
                rquired=False,
                type='str'
            ),
            lb_service_id=dict(
                rquired=False,
                type='str'
            ),
            max_concurrent_connections=dict(
                required=False,
                type='int'
            ),
            max_new_connection_rate=dict(
                required=False,
                type='int'
            ),
            ports=dict(
                required=True,
                type='list'
            ),
            rules=dict(
                required=False,
                type='list'
            )
        )
        return loadbalancer_vs_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args):
        return '/infra/lb-virtual-servers'

    def update_resource_params(self):
        application_profile_id = self.resource_params.pop(
            "application_profile_id")
        self.resource_params["application_profile_path"] = (
            PolicyApplicationProfile.get_resource_base_url() + "/" +
            application_profile_id)

        if "lb_persistence_profile_id" in self.resource_params:
            lb_persistence_profile_id = self.resource_params.pop(
                "lb_persistence_profile_id")
            self.resource_params["lb_persistence_profile_path"] = (
                PolicyLBPersistenceProfile.get_resource_base_url() + "/"
                + lb_persistence_profile_id)

        if "lb_service_id" in self.resource_params:
            lb_service_id = self.resource_params.pop("lb_service_id")
            self.resource_params["lb_service_path"] = (
                NSXTLoadBalancerService.get_resource_base_url() + "/"
                + lb_service_id)


if __name__ == '__main__':
    loadbalancer_vs = NSXTLoadBalancerVirtualServer()
    loadbalancer_vs.realize()
