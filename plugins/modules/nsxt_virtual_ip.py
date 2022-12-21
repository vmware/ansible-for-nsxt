#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2019 VMware, Inc.
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
module: nsxt_virtual_ip
short_description: 'Sets and clears cluster virtual IP address'
description: "Sets the cluster virtual IP address. Note, all nodes in the management 
              cluster must be in the same subnet. If not, a 409 CONFLICT status is 
              returned. "
version_added: '2.7'
author: 'Rahul Raghuvanshi'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
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
    virtual_ip_address:
        description: 'Virtual IPv4 address to be set.'
        required: true
        type: str
    virtual_ip6_address:
        description: 'Virtual IPv6 address to be set.'
        required: true
        type: str
    action:
        choices:
            - clear_virtual_ip
            - clear_virtual_ip6
        description: "Action can be either 'clear_virtual_ip' or 'clear_virtual_ip6'.
                      'clear_virtual_ip' is used to clear Virtual IPv4.
                      'clear_virtual_ip6' is used to clear Virtual IPv6."
        required: true only if state is absent
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
- name: Adds cluster virtual IP address
  nsxt_virtual_ip:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      virtual_ip_address: "10.192.167.141"
      virtual_ip6_address: "2620:124:6020:c308::10"
      action: clear_virtual_ip
      state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import check_if_valid_ip, get_attribute_from_endpoint
from ansible.module_utils._text import to_native

def get_virtual_ip_params(args=None):
    args_to_remove = ['state','action', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, vip_params):
    if module.params['virtual_ip_address'] and module.params['virtual_ip6_address']:
        existing_vip = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username, mgr_password, validate_certs, 'ip_address')
        existing_vip6 = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username, mgr_password, validate_certs, 'ip6_address')
        if existing_vip != vip_params['virtual_ip_address'] and existing_vip6 != vip_params['virtual_ip6_address']:
            return True
    elif module.params['virtual_ip_address']:
        existing_vip = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username, mgr_password, validate_certs, 'ip_address')
        if existing_vip != vip_params['virtual_ip_address']:
            return True
    elif module.params['virtual_ip6_address']:
        existing_vip6 = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username, mgr_password, validate_certs, 'ip6_address')
        if existing_vip6 != vip_params['virtual_ip6_address']:
            return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(virtual_ip_address=dict(type='str'),
                       virtual_ip6_address=dict(type='str'),
                       action=dict(required_if=[('state', 'absent')], type='str', choices=['clear_virtual_ip', 'clear_virtual_ip6']),
                       state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,  required_one_of=[('virtual_ip_address', 'virtual_ip6_address')])
  virtual_ip_params = get_virtual_ip_params(module.params.copy())
  state = module.params['state']
  action = module.params['action']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'

  if state == 'present':
    # add virtual IP address
    if module.params['virtual_ip_address']:
        virtual_ip_address = virtual_ip_params['virtual_ip_address']
        if not check_if_valid_ip(virtual_ip_address):
            module.fail_json(msg="Virtual IP provided is invalid.")
    if module.params['virtual_ip6_address']:
        virtual_ip6_address = virtual_ip_params['virtual_ip6_address']
        if not check_if_valid_ip(virtual_ip6_address):
            module.fail_json(msg="Virtual IP provided is invalid.")

    if module.check_mode:
        module.exit_json(changed=False, debug_out="Cluster virtual IP would have been updated to %s" % virtual_ip_params, id='12345')
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, virtual_ip_params)
    if not updated:
        if module.params['virtual_ip_address'] and module.params['virtual_ip6_address']:
            module.exit_json(changed=False, message="Virtual IPs %s and %s are already set." % (virtual_ip_address, virtual_ip6_address))
        elif module.params['virtual_ip_address']:
            module.exit_json(changed=False, message="Virtual IP %s already set." % virtual_ip_address)
        elif module.params['virtual_ip6_address']:
            module.exit_json(changed=False, message="Virtual IP %s already set." % virtual_ip6_address)
    else:
        try:
            if module.params['virtual_ip_address'] and module.params['virtual_ip6_address']:
                (rc, resp) = request(manager_url + '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=%s&ip6_address=%s' % (virtual_ip_address, virtual_ip6_address), data='', headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            elif module.params['virtual_ip_address']:
                (rc, resp) = request(manager_url + '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=%s' %virtual_ip_address, data='', headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            elif module.params['virtual_ip6_address']:
                (rc, resp) = request(manager_url + '/cluster/api-virtual-ip?action=set_virtual_ip&ip6_address=%s' % virtual_ip6_address, data='', headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)

        except Exception as err:
            module.fail_json(msg="Failed to add virtual IP address. Error[%s]." % to_native(err))

        time.sleep(5)
        if module.params['virtual_ip_address'] and module.params['virtual_ip6_address']:
            module.exit_json(changed=True, result=resp, message="Virtual IP address is set with ip addresses: %s and "
                                                                "%s " % (virtual_ip_address, virtual_ip6_address))
        elif module.params['virtual_ip_address']:
            module.exit_json(changed=True, result=resp, message="Virtual IP address is set with IPv4 address: %s " % virtual_ip_address)
        elif module.params['virtual_ip6_address']:
            module.exit_json(changed=True, result=resp, message="Virtual IP address is set with IPv6 address: %s " % virtual_ip6_address)



  elif state == 'absent':
    # delete virtual IP address
    if action =="clear_virtual_ip":
        is_virtual_ip_set = True
        virtual_ip_address = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username, mgr_password, validate_certs, 'ip_address')
        if virtual_ip_address is None or virtual_ip_address == '0.0.0.0':
            virtual_ip_address = "Virtual IP address is not set"
            is_virtual_ip_set = False
        if module.check_mode:
            if not is_virtual_ip_set:
                module.exit_json(changed=True, debug_out='Virtual IPv4 address is not set', id=virtual_ip_address)
            else:
                module.exit_json(changed=True, debug_out='Virtual IPv4 address is set to %s. Will be removed.'% virtual_ip_address, id=virtual_ip_address)

        time.sleep(5)
        if not is_virtual_ip_set:
            module.exit_json(changed=False, object_name="Virtual IPv4 was not set before.", message="Cleared cluster virtual IPv4 address.")
        try:
            (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=clear_virtual_ip', data='', headers=headers, method='POST',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            module.fail_json(msg="Failed to clear virtual IPv4 address. Error[%s]." % to_native(err))
        module.exit_json(changed=True, object_name=virtual_ip_address, message="Cleared cluster virtual IPv4 address.")

    if action =="clear_virtual_ip6":
        is_virtual_ip6_set = True
        virtual_ip6_address = get_attribute_from_endpoint(module, manager_url, '/cluster/api-virtual-ip', mgr_username,
                                                         mgr_password, validate_certs, 'ip6_address')
        if virtual_ip6_address is None or virtual_ip6_address == '::':
            virtual_ip6_address = "Virtual IPv6 address is not set"
            is_virtual_ip6_set = False
        if module.check_mode:
            if not is_virtual_ip6_set:
                module.exit_json(changed=True, debug_out='Virtual IPv6 address is not set', id=virtual_ip6_address)
            else:
                module.exit_json(changed=True,
                                 debug_out='Virtual IPv6 address is set to %s. Will be removed.' % virtual_ip6_address,
                                 id=virtual_ip6_address)

        time.sleep(5)
        if not is_virtual_ip6_set:
            module.exit_json(changed=False, object_name="Virtual IPv6 was not set before.",
                             message="Cleared cluster virtual IPv6 address.")
        try:
            (rc, resp) = request(manager_url + '/cluster/api-virtual-ip?action=clear_virtual_ip6', data='',
                                 headers=headers, method='POST',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                                 ignore_errors=True)
        except Exception as err:
            module.fail_json(msg="Failed to clear virtual IPv6 address. Error[%s]." % to_native(err))
        module.exit_json(changed=True, object_name=virtual_ip6_address, message="Cleared cluster virtual IPv6 address.")


if __name__ == '__main__':
    main()
