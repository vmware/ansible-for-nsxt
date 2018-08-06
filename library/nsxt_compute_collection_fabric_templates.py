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
- nsxt_compute_collection_templates:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    #compute_collection_templates_id: "25d314b6-97f2-48e2-87b5-f9ce04caf5f8"
    display_name: "vCenter"
    server: "10.161.244.213"
    origin_type: vCenter
    credential:
    credential_type: UsernamePasswordLoginCredential
    username: "administrator@vsphere.local"
    password: "Admin!23"
    thumbprint: "36:43:34:D9:C2:06:27:4B:EE:C3:4A:AE:23:BF:76:A0:0C:4D:D6:8A:D3:16:55:97:62:07:C2:84:0C:D8:BA:66"
    state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native
import ssl
import socket
import hashlib

def get_compute_collection_templates_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_compute_collection_templates(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/fabric/compute-collection-fabric-templates', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing fabric compute collection fabric template. Error [%s]' % (to_native(err)))
    return resp

def get_compute_collection_templates_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    compute_collection_templates = get_compute_collection_templates(module, manager_url, mgr_username, mgr_password, validate_certs)
    for compute_collection_templates in compute_collection_templates['results']:
        if compute_collection_templates.__contains__('display_name') and compute_collection_templates['display_name'] == display_name:
            return compute_collection_templates
    return None

def wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/fabric/compute-collection-fabric-templates/%s'% id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          time.sleep(10)
    except Exception as err:
      time.sleep(5)
      return

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, compute_collection_templates_with_ids):
    existing_compute_collection_templates = get_compute_collection_templates_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, compute_collection_templates_with_ids['display_name'])
    if existing_compute_collection_templates is None:
        return False
    if existing_compute_collection_templates['compute_collection_id'] != compute_collection_templates_with_ids['compute_collection_id']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                    compute_collection_id=dict(required=True, type='str'),
                    auto_install_nsx=dict(required=True, type='bool'),
                    state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  compute_collection_templates_params = get_compute_collection_templates_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  compute_collection_templates_dict = get_compute_collection_templates_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  compute_collection_templates_id, revision = None, None
  if compute_collection_templates_dict:
    compute_collection_templates_id = compute_collection_templates_dict['id']
    revision = compute_collection_templates_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, compute_collection_templates_params)
    if not updated:
      # add the compute_collection_templates
      request_data = json.dumps(compute_collection_templates_params)
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(request_data), id='12345')
      try:
          if compute_collection_templates_id:
              module.exit_json(changed=False, id=compute_collection_templates_id, message="Compute collection fabric template with display_name %s already exist."% module.params['display_name'])
          (rc, resp) = request(manager_url+ '/fabric/compute-collection-fabric-templates', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
                module.fail_json(msg="Failed to add compute_collection_templates. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Compute collection fabric template for id %s created." % module.params['compute_collection_id'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(compute_collection_templates_params)), id=compute_collection_templates_id)
      compute_collection_templates_params['_revision'] = revision # update current revision
      request_data = json.dumps(compute_collection_templates_params)
      id = compute_collection_templates_id
      try:
          (rc, resp) = request(manager_url+ '/fabric/compute-collection-fabric-templates/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update compute_collection_templates with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="fabric compute collection fabric template with Compute collection fabric template id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = compute_collection_templates_id
    if id is None:
        module.exit_json(changed=False, msg='No Compute collection fabric template exist with display_name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(compute_collection_templates_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/fabric/compute-collection-fabric-templates/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete fabric compute collection fabric template with id %s. Error[%s]." % (id, to_native(err)))

    wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs)

    module.exit_json(changed=True, id=id, message="Compute collection fabric template id %s deleted." % id)


if __name__ == '__main__':
    main()
