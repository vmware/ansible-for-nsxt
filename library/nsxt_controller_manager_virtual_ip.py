#!/usr/bin/env python
#
# Copyright 2019 Vodafone Group Services GmbH
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
module: nsxt_controller_manager_virtual_ip
short_description: 'Set cluster virtual IP address'
description: "Sets the cluster virtual IP address. Note, all nodes in the management 
              cluster must be in the same subnet."
version_added: '2.7'
author: 'Ruediger Pluem'
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
    ip_address:
        description: 'The virtual IP address'
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
  - name: Set cluster virtual IP address
    nsxt_manager_controllers:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      ip_address: "10.192.167.138"
      state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_node_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_virtual_ip(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing controller-manager node. Error [%s]' % (to_native(err)))
    return resp

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(ip_address=dict(required=True, type='str'),
                    state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  node_params = get_node_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  ip_address = module.params['ip_address']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  request_data = json.dumps(node_params)
  results = get_virtual_ip(module, manager_url, mgr_username, mgr_password, validate_certs)
  if state == 'present':
    # Check if IP is already set
    if results['ip_address'] == ip_address:
      module.exit_json(changed=False, message="Virtual IP already set to %s. %s"% (ip_address, results))
    if module.check_mode:
      module.exit_json(changed=True, debug_out=str(request_data))
    try:
      (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address='+ ip_address, headers=headers, method='POST',
                           url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to set virtual IP %s. Error[%s]." % (ip_address, to_native(err)))

    module.exit_json(changed=True, body= str(resp), message="Virtual IP set.")

  elif state == 'absent':
      if module.check_mode:
        module.exit_json(changed=True, debug_out=str(request_data))
      try:
        (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip/?action=clear_virtual_ip', headers=headers, method='POST',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(msg="Failed to clear virtual IP. Error[%s]." % to_native(err))

      module.exit_json(changed=True, body= str(resp), message="Virtual IP cleared.")

if __name__ == '__main__':
    main()
