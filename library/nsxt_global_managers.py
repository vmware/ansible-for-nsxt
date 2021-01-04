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
module: nsxt_global_manager
short_description: 'Register a standby global manager cluster'
description: "Register a standby global manager cluster"
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
    connection_info:
        fqdn:
            description: 'IP address or hostname of global manager(cluster)'
            required: true
            type: str
        password:
            description: "Password for the user (optionally specified on PUT, unspecified on
                          GET)"
            no_log: 'True'
            required: false
            type: str
        required: false
        thumbprint:
            description: 'Hexadecimal SHA256 hash of the vIDM server''s X.509 certificate'
            no_log: 'True'
            required: false
            type: str
        username:
            description: 'Username value of the log'
            required: false
            type: str
    mode:
        choices:
            - ACTIVE
            - STANDBY
        description: "ACTIVE or STANDBY"
        required: true
        type: str
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true

    
'''

EXAMPLES = '''
- name: Register a standby global manager cluster with exisitng global manager
  nsxt_global_managers:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: "GM-1"
    mode: "STANDBY"
    connection_info:
      fqdn: "10.10.10.20"
      username: "admin"
      password: "Admin!23"
      thumbprint: "36:43:34:D9:C2:06:27:4B:EE:C3:4A:AE:23:BF:76:A0:0C:4D:D6:8A:D3:16:55:97:62:07:C2:84:0C:D8:BA:66"
    state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
import ssl
import socket
import hashlib


def get_global_manager_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)

    #   connection_info is an array
    args["connection_info"] = [args["connection_info"]]
    return args


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


def check_for_update(module, url, mgr_username, mgr_password, validate_certs, global_manager_with_ids):
    existing_global_manager = get_global_manager_from_display_name(module, url, mgr_username, mgr_password,
                                                                   validate_certs,
                                                                   global_manager_with_ids['display_name'])
    if existing_global_manager is None:
        return False

    return True


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'),
                         connection_info=dict(required=False, type='dict', no_log=True,
                                              username=dict(required=False, type='str'),
                                              password=dict(required=False, type='str'),
                                              thumbprint=dict(required=False, type='str'),
                                              fqdn=dict(required=True, type='str')),
                         mode=dict(required=False, choices=['ACTIVE', 'STANDBY']),
                         state=dict(required=True, choices=['present', 'absent']))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global_manager_params = get_global_manager_params(module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/global-manager/api/v1'.format(mgr_hostname)
    global_manager_api_url = manager_url + '/global-infra/global-managers'

    global_manager_dict = get_global_manager_from_display_name(module, global_manager_api_url, mgr_username, mgr_password,
                                                               validate_certs, display_name)
    global_manager_id, revision = None, None
    if global_manager_dict:
        global_manager_id = global_manager_dict['id']
        revision = global_manager_dict['_revision']

    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        updated = check_for_update(module, global_manager_api_url, mgr_username, mgr_password, validate_certs,
                                   global_manager_params)
        if not updated:
            # add the global_manager
            request_data = json.dumps(global_manager_params)
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(request_data), id='12345')
            try:
                if global_manager_id:
                    module.exit_json(changed=False, id=global_manager_id,
                                     message="Global manager with display_name %s already exist." % module.params[
                                         'display_name'])

                (rc, resp) = request(global_manager_api_url + '/%s' % module.params['display_name'], data=request_data,
                                     headers=headers, method='PUT',
                                     url_username=mgr_username, url_password=mgr_password,
                                     validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(
                    msg="Failed to add global_manager. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

            module.exit_json(changed=True, id=resp["id"], body=str(resp),
                             message="Global manager with display name %s is added." % module.params['display_name'])
        else:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(global_manager_params)), id=global_manager_id)
            global_manager_params['_revision'] = revision  # update current revision
            request_data = json.dumps(global_manager_params)
            id = global_manager_id
            try:
                (rc, resp) = request(global_manager_api_url + '/%s' % id, data=request_data, headers=headers, method='PUT',
                                     url_username=mgr_username, url_password=mgr_password,
                                     validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to update global manager with id %s. Request body [%s]. Error[%s]." % (
                id, request_data, to_native(err)))
            module.exit_json(changed=True, id=resp["id"], body=str(resp),
                             message="Global manager with id %s updated." % id)

    elif state == 'absent':
        # delete the array
        id = global_manager_id
        if id is None:
            module.exit_json(changed=False, msg='No global manager exists with display_name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(global_manager_params)), id=id)
        try:
            (rc, resp) = request(global_manager_api_url + "/%s" % id, method='DELETE',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete global manager with id %s. Error[%s]." % (id, to_native(err)))

        module.exit_json(changed=True, id=id, message="Global manager with id %s is deleted." % id)


if __name__ == '__main__':
    main()
