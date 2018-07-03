#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
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

DOCUMENTATION = '''TODO
author: Rahul Raghuvanshi
'''

EXAMPLES = '''
- name: Add license
  nsxt_licenses:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      license_key: "11111-22222-33333-44444-55555"
      state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_license_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def check_license_exist(module, manager_url, mgr_username, mgr_password, validate_certs):
    id = module.params['license_key']
    try:
      (rc, resp) = request(manager_url+ '/licenses/%s' % id, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      return False
    return True

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(license_key=dict(required=True, type='str', no_log=True),
                    state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  license_params = get_license_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'
  request_data = json.dumps(license_params)

  if state == 'present':
    # add the license
    if check_license_exist(module, manager_url, mgr_username, mgr_password, validate_certs):
        module.exit_json(changed=False, message="license with license key %s already exist."% module.params['license_key'])
   if module.check_mode:
       module.exit_json(changed=True, debug_out=str(request_data), id=module.params['license_key'])
    try:
        (rc, resp) = request(manager_url+ '/licenses', data=request_data, headers=headers, method='POST',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg="Failed to add license. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, result=resp, message="license with license key %s created." % module.params['license_key'])

  elif state == 'absent':
    # delete the license key
    id = module.params['license_key']
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(request_data), id=id)
    try:
       (rc, resp) = request(manager_url+ '/licenses?action=delete', data=request_data, headers=headers, method='POST',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to delete license with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=license_key, message="license with license key %s deleted." % id)


if __name__ == '__main__':
    main()
