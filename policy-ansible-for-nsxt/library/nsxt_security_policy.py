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
    domain_id:
        description: The domain id where the Security Policy is realized.
        type: str
        required: true
    category:
        description:
            - A way to classify a security policy, if needed.
            - Distributed Firewall
                - Policy framework provides five pre-defined categories for
                classifying a security policy. They are "Ethernet",Emergency",
                "Infrastructure", "Environment" and "Application". There is a
                pre-determined order in which the policy framework manages the
                priority of these security policies. Ethernet category is for
                supporting layer 2 firewall rules. The other four categories
                are applicable for layer 3 rules. Amongst them, the Emergency
                category has the highest priority followed by Infrastructure,
                Environment and then Application rules. Administrator can
                choose to categorize a security policy into the above
                categories or can choose to leave it empty. If empty it will
                have the least precedence w.r.t the above four categories.
            - Edge Firewall
                - Policy Framework for Edge Firewall provides six pre-defined
                categories "Emergency", "SystemRules", "SharedPreRules",
                "LocalGatewayRules", "AutoServiceRules" and
                "Default", in order of priority of rules.
                All categories are allowed for Gatetway Policies
                that belong to 'default' Domain. However, for
                user created domains, category is restricted to
                "SharedPreRules" or "LocalGatewayRules" only.
                Also, the users can add/modify/delete rules from
                only the "SharedPreRules" and "LocalGatewayRules"
                categories. If user doesn't specify the category
                then defaulted to "Rules". System generated
                category is used by NSX created rules, for
                example BFD rules. Autoplumbed category used by
                NSX verticals to autoplumb data path rules.
                Finally, "Default" category is the placeholder
                default rules with lowest in the order of priority.
        type: str
    scope:
        description: The list of group paths where the rules in this
                     policy will get applied. This scope will take
                     precedence over rule level scope. Supported only
                     for security policies.
        type: list
    sequence_number:
        description: Sequence number to resolve conflicts across Domains
        type: int
    rules:
        description: Rules that are a part of this SecurityPolicy
        type: list
        suboptions:
            action:
                description: The action to be applied to all the
                             services
                type: str
                choices:
                    - "ALLOW"
                    - "DROP"
                    - "REJECT"
            description:
                description: Description of this resource
                type: str
            destination_groups:
                description: Destination group paths
                type: list
                required: true
            destinations_excluded:
                description: Negation of destination groups

                             If set to true, the rule gets applied on
                             all the groups that are NOT part of the
                             destination groups. If false, the rule
                             applies to the destination groups.
                type: bool
                default: false
            direction:
                description: Define direction of traffic.
                type: str
                choices:
                    - IN
                    - OUT
                    - IN_OUT
            disabled:
                description: Flag to disable the rule
                type: bool
                default: false
            display_name:
                description: Identifier to use when displaying entity
                             in logs or GUI.

                             Defaults to ID if not set
                type: str
            id:
                description: Unique identifier of this resource
                type: str
                required: true
            sequence_number:
                description: Sequence number of the this Rule
                type: int
            services:
                description: Paths of services
                             In order to specify all services, use the
                             constant "ANY". This is case insensitive.
                             If "ANY" is used, it should be the ONLY
                             element in the services array. Error will
                             be thrown if ANY is used in conjunction
                             with other values.
                type: list
                required: true
            source_groups:
                description: Source group paths
                type: list
                required: true
            sources_excluded:
                description: Negation of source groups

                             If set to true, the rule gets applied on
                             all the groups that are NOT part of the
                             source groups. If false, the rule applies
                             to the source groups
                type: bool
                default: false
'''

EXAMPLES = '''
- name: create Security Policy
  nsxt_security_policy:
  hostname: "10.160.84.49"
  username: "admin"
  password: "Admin!23Admin"
  validate_certs: False
  id: test-sec-pol
  display_name: test-sec-pol
  state: "present"
  domain_id: "default"
  rules:
    - action: "ALLOW"
      description: "example-rule"
      sequence_number: 1
      display_name: "test-example-rule"
      id: "test-example-rule"
      source_groups: ["/infra/domains/vmc/groups/dbgroup"]
      destination_groups: ["/infra/domains/vmc/groups/appgroup"]
      services: ["/infra/services/HTTP", "/infra/services/CIM-HTTP"]
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible.module_utils._text import to_native


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
                type='list',
                options=dict(
                    action=dict(
                        required=True,
                        type='str',
                        choices=["ALLOW", "DROP", "REJECT"]
                    ),
                    description=dict(
                        required=False,
                        type='str'
                    ),
                    destination_groups=dict(
                        required=True,
                        type='list'
                    ),
                    destinations_excluded=dict(
                        required=False,
                        type='bool',
                        default=False
                    ),
                    direction=dict(
                        required=False,
                        default="IN_OUT",
                        type='str',
                        choices=["IN_OUT", "IN", "OUT"]
                    ),
                    disabled=dict(
                        required=False,
                        type='bool',
                        default=False
                    ),
                    display_name=dict(
                        required=False,
                        type='str'
                    ),
                    id=dict(
                        required=True,
                        type='str'
                    ),
                    sequence_number=dict(
                        required=False,
                        type='int'
                    ),
                    services=dict(
                        required=True,
                        type='list'
                    ),
                    source_groups=dict(
                        required=True,
                        type='list'
                    ),
                    sources_excluded=dict(
                        required=False,
                        type='bool',
                        default=False
                    )
                )
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
        return '/infra/domains/{}/security-policies'.format(
            baseline_args["domain_id"])


if __name__ == '__main__':
    segment = NSXTSecurityPolicy()
    segment.realize(baseline_arg_names=["domain_id"])
