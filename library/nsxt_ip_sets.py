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
DOCUMENTATION = '''
---
module: nsxt_ip_sets
short_description: 'Create an IP set'
description: "Creates a new IPv4 or IPv6 address set. Required parameters are
              allocation_ranges and cidr. Optional parameters are display_name,
              description, dns_nameservers, dns_suffix, and gateway_ip."
version_added: '2.7'
author: 'Matt Proud'
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
    display_name:
        description: 'Display name'
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
    ip_addresses:
        description: "ip_addresses can be IPv4 or IPv6 and they should not overlap. The maximum
                      number will not exceed 4000."
        required: false
        type: 'list'
    tags:
        description: 'Opaque identifiers meaningful to the API user'
        required: false
        type: str
   
'''

EXAMPLES = '''
- name: Create ip set
  nsxt_ip_sets:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: IPset-IPV4-1
    ip_addresses:
    - "10.112.201.28"
    - "10.112.201.64/26"
    state: "present"
'''

RETURN = '''# '''


import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_ip_set_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_ip_sets(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/ip-sets', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing ip sets. Error [%s]' % (to_native(err)))
    return resp

def get_ip_set_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    ip_sets = get_ip_sets(module, manager_url, mgr_username, mgr_password, validate_certs)
    return_ip_set = None
    for ip_set in ip_sets['results']:
        if ip_set.__contains__('display_name') and ip_set['display_name'] == display_name:
            if not return_ip_set: # Handle there being 2 sections created with the same display name
                return_ip_set = ip_set
            else:
                module.fail_json(msg='Section with display name %s exists more than once.' % (display_name))
    return return_ip_set

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, ip_set_params):
    existing_ip_set = get_ip_set_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, ip_set_params['display_name'])
    if existing_ip_set is None:
        return False
    if  existing_ip_set.__contains__('ip_addresses') and ip_set_params.__contains__('ip_addresses') and existing_ip_set['ip_addresses'] != ip_set_params['ip_addresses']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                        description=dict(required=False, type='str'),
                        ip_addresses=dict(required=False, type='list'),
                        tags=dict(required=False, type='str'),
                        state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  ip_set_params = get_ip_set_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  set_dict = get_ip_set_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  set_id, revision = None, None
  if set_dict:
    set_id = set_dict['id']
    revision = set_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, ip_set_params)

    if not updated:
      # add the set
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(ip_set_params)), id='12345')
      request_data = json.dumps(ip_set_params)
      try:
          if set_id:
              module.exit_json(changed=False, id=set_id, message="IP set with display_name %s already exist."% module.params['display_name'])
          (rc, resp) = request(manager_url+ '/ip-sets', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to add ip set. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="IP set with display name %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(ip_set_params)), id=set_id)
      ip_set_params['_revision']=revision # update current revision
      request_data = json.dumps(ip_set_params)
      id = set_id
      try:
          (rc, resp) = request(manager_url+ '/ip-sets/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update ip set with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="ip set with set id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = set_id
    if id is None:
        module.exit_json(changed=False, msg='No ip set exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(ip_set_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/ip-sets/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete ip set with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="ip set with set id %s deleted." % id)


if __name__ == '__main__':
    main()
