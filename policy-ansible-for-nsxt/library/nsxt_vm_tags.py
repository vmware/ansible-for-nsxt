#!/usr/bin/env python
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
module: nsxt_vm_tags
short_description: Update tags on NSXT VM
description:
    Update tags on NSXT VM
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
    validate_certs:
        description: Enable server certificate verification.
        type: bool
        default: False
    tags:
        required: true
        type: list
        element: dict
        description: List of tags to be applied to the virtual machine
        suboptions:
            scope:
                description: Tag scope.
                required: true
                type: str
            tag:
                description: Tag value.
                required: true
                type: str
    virtual_machine_id:
        description: The identifier that is used in the enforcement point that
                     uniquely identifies the virtual machine. In case of NSXT
                     it would be the value of the external_id of the virtual
                     machine.
        type: str
        required: true
    remove_other_tags:
        description: Remove the tags that are not specified in the Ansible
                     Playbook
        default: false
'''

EXAMPLES = '''
- name: Update VM Tags
  nsxt_vm_tags:
    hostname: "10.10.10.10"
    username: "username"
    password: "password"
    validate_certs: False
    virtual_machine_id: eaf6a927-552e-4285-8eaa-7b4f84bebca3
    remove_other_tags: False
    tags:
    - tag: "my-tag-value"
      scope: "my-tag-scope"
'''

RETURN = '''# '''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.policy_communicator import PolicyCommunicator
from ansible.module_utils._text import to_native


if __name__ == '__main__':
    import os
    import sys
    sys.path.append(os.getcwd())


class NSXTVMUpdateTags(object):
    @staticmethod
    def get_resource_spec():
        vm_tag_spec = PolicyCommunicator.get_vmware_argument_spec()
        vm_tag_spec.update(dict(
            virtual_machine_id=dict(type='str', required=True),
            tags=dict(required=True, type='list', elements='dict',
                      options=dict(
                          scope=dict(required=True, type='str'),
                          tag=dict(required=True, type='str'))),
            remove_other_tags=dict(
                required=False, default=False, type='bool')))
        return vm_tag_spec

    def realize(self):
        module = AnsibleModule(
            argument_spec=self.get_resource_spec(),
            supports_check_mode=False)

        virtual_machine_id = module.params['virtual_machine_id']

        mgr_hostname = module.params.pop('hostname')
        mgr_username = module.params.pop('username')
        mgr_password = module.params.pop('password')

        validate_certs = module.params.pop('validate_certs')

        try:
            # Each manager has an associated PolicyCommunicator
            policy_communicator = PolicyCommunicator.get_instance(
                mgr_username, mgr_hostname, mgr_password)

            existing_tags = []
            if not module.params.get('remove_other_tags'):
                # Get all the VMs
                _, resp = policy_communicator.request(
                    '/infra/realized-state/enforcement-points/default/'
                    'virtual-machines', validate_certs=validate_certs)
                vms = resp['results']
                for vm in vms:
                    if vm['external_id'] == virtual_machine_id:
                        existing_tags = vm.get('tags', [])
                        break

            tags_to_add = module.params.pop('tags')
            final_tags = existing_tags + tags_to_add

            post_body = {
                "virtual_machine_id": virtual_machine_id,
                "tags": final_tags
            }
            _, resp = policy_communicator.request(
                '/infra/realized-state/enforcement-points/default/' +
                'virtual-machines?action=update_tags', data=post_body,
                method="POST", validate_certs=validate_certs)
            module.exit_json(msg="Successfully updated tags on VM {}".format(
                virtual_machine_id))
        except Exception as err:
            module.fail_json(msg="Failed to update tags on VM {} as API "
                             "returned error: {}. Please try "
                             "again".format(virtual_machine_id, err))


if __name__ == '__main__':
    vm_update_tags = NSXTVMUpdateTags()
    vm_update_tags.realize()
