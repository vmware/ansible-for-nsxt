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
module: nsxt_policy_service


'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import (
    SERVICE_ENTRIES_URL, SERVICE_URL)
from ansible.module_utils._text import to_native


class NSXTService(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        service_arg_spec = {}
        service_arg_spec.update(
            service_entries=dict(
                type='list',
                elements='dict'
            ),
        )
        return service_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return SERVICE_URL

if __name__ == '__main__':
    svc = NSXTService()
    svc.realize()
