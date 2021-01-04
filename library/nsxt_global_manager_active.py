#!/usr/bin/env python
#
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_global_manager_active
short_description: 'Make the global manager as Active'
description: "Make the global manager as Active"
version_added: '3.2'
author: 'Kaushik Lele'
options:
    hostname:
        description: 'Deployed NSX Global manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: str
    display_name:
        description: 'Display name'
        required: true
        type: str

'''

EXAMPLES = '''
- name: Make the global manager as Active
  nsxt_global_manager_active:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "GM-1"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
import ssl
import socket
import hashlib


def get_global_managers(module, url, mgr_username, mgr_password, validate_certs):
    try:
        (rc, resp) = request(url, headers=dict(Accept='application/json'),
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                             ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing global manager. Error [%s]' % (to_native(err)))
    return resp


def get_global_manager_from_display_name(module, url, mgr_username, mgr_password, validate_certs, display_name):
    global_managers = get_global_managers(module, url, mgr_username, mgr_password, validate_certs)
    for global_manager in global_managers['results']:
        if global_manager.__contains__('display_name') and global_manager['display_name'] == display_name:
            return global_manager
    return None


def wait_till_switchover_complete(module, url, mgr_username, mgr_password, validate_certs):
    try:
        retry_count = 0
        while True:
            (rc, resp) = request(url, headers=dict(Accept='application/json'),
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                                 ignore_errors=True)
            if resp['overall_status'] == "ONGOING" and retry_count < 100:
                time.sleep(10)
            elif resp['overall_status'] == "COMPLETE":
                return
            else:
                all_erroes = ''
                if resp['errors'] is not None:
                    for e in resp['errors']:
                        all_erroes = all_erroes + e
                module.fail_json(msg='Switchover was not completed due to errors : %s' % all_erroes)
    except Exception as err:
        module.fail_json(msg='Error checking switchover status. Error [%s]' % (to_native(err)))


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']

    manager_url = 'https://{}/global-manager/api/v1'.format(mgr_hostname)
    global_manager_url = manager_url + '/global-infra/global-managers'
    switchover_api_url = 'https://{}/api/v1/sites/switchover-status'.format(mgr_hostname)

    existing_global_manager = get_global_manager_from_display_name(module, global_manager_url,
                                                                   mgr_username, mgr_password, validate_certs,
                                                                   display_name)
    global_manager_id, revision = None, None

    if existing_global_manager is None:
        module.fail_json(msg="Global_manager with disaplya name [%s] not found." % display_name)

    global_manager_id = existing_global_manager['id']
    revision = existing_global_manager['_revision']

    if existing_global_manager["mode"] == "ACTIVE":
        module.exit_json(changed=False, id=global_manager_id,
                         message="Global manager with display name %s is already in ACTIVE mode." %
                                 existing_global_manager["display_name"])
    else:
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        request_data_dict = {
            "id": global_manager_id,
            "resource_type": "GlobalManager",
            "display_name": existing_global_manager["display_name"],
            "mode": "ACTIVE",
            "_revision": revision

        }

        request_data = json.dumps(request_data_dict)

        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(request_data), id=global_manager_id)

        try:
            (rc, resp) = request(global_manager_url + '%s' % global_manager_id, data=request_data,
                                 headers=headers, method='PUT',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                                 ignore_errors=True)
        except Exception as err:
            module.fail_json(msg="Failed to set global_manager as active. Request body [%s]. Error[%s]." % (
                request_data, to_native(err)))

        wait_till_switchover_complete(module, switchover_api_url, mgr_username, mgr_password, validate_certs)

        module.exit_json(changed=True, id=resp["id"], body=str(resp),
                         message="Global manager with display name %s was requested to be made active." % module.params[
                             'display_name'])


if __name__ == '__main__':
    main()
