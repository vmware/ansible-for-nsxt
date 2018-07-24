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

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''TODO
author: Rahul Raghuvanshi
'''

EXAMPLES = '''
- nsxt_logical_ports:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      logical_switch_name: LS1
      attachment:
        attachment_type: VIF
        id: vif1
      admin_state: UP
'''

RETURN = '''# '''

def get_logical_port_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_logical_ports(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/logical-ports', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing logical ports. Error [%s]' % (to_native(err)))
    return resp

def get_logical_port_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    logical_ports = get_logical_ports(module, manager_url, mgr_username, mgr_password, validate_certs)
    if logical_ports and len(logical_ports['results'])>0:
        for logical_port in logical_ports['results']:
            if logical_port.__contains__('display_name') and logical_port['display_name'] == display_name:
                return logical_port
    return None

def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name):
    try:
      (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == display_name:
            return result['id']
    module.fail_json(msg='No id existe with display name %s' % display_name)

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, logical_port_params ):
    logical_port_params['logical_switch_id'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                                            '/logical-switches', logical_port_params.pop('logical_switch_name', None))
    host_switch_profile_ids = []
    host_switch_profiles = logical_port_params.pop('switching_profiles', None)
    if host_switch_profiles:
        for host_switch_profile in host_switch_profiles:
            profile_obj = {}
            profile_obj['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                                                    "/host-switch-profiles", host_switch_profile['name'])
            profile_obj['key'] = host_switch_profile['type']
            host_switch_profile_ids.append(profile_obj)
    logical_port_params['switching_profile_ids'] = host_switch_profile_ids
    return logical_port_params

# def ordered(obj):
#     if isinstance(obj, dict):
#         return sorted((k, ordered(v)) for k, v in obj.items())
#     if isinstance(obj, list):
#         return sorted(ordered(x) for x in obj)
#     else:
#         return obj

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, logical_port_with_ids):
    existing_logical_port = get_logical_port_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, logical_port_with_ids['display_name'])
    if existing_logical_port is None:
        return False
    if existing_logical_port.__contains__('attachment') and existing_logical_port['attachment'].__contains__('attachment_type') and \
        logical_port_with_ids.__contains__('attachment') and logical_port_with_ids['attachment'].__contains__('attachment_type') and \
        (existing_logical_port['attachment']['attachment_type'] != logical_port_with_ids['attachment']['attachment_type'] or \
        existing_logical_port['attachment']['id'] != logical_port_with_ids['attachment']['id']):
        return True
    if existing_logical_port.__contains__('switching_profile_ids') and logical_port_with_ids.__contains__('switching_profile_ids') and \
        existing_logical_port['switching_profile_ids'] != logical_port_with_ids['switching_profile_ids']:
        return True
    if existing_logical_port['admin_state'] != logical_port_with_ids['admin_state']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                        logical_switch_name=dict(required=True, type='str'),
                        init_state=dict(required=False, type='str'),
                        switching_profiles=dict(required=False, type='list'),
                        attachment=dict(required=False, type='dict',
                        attachment_type=dict(required=False, type='str'),
                        context=dict(required=False, type='dict',
                        tunnel_id=dict(required=True, type='int'),
                        vif_type=dict(required=True, type='str'),
                        parent_vif_id=dict(required=False, type='str'),
                        traffic_tag=dict(required=False, type='int'),
                        app_id=dict(required=False, type='str'),
                        allocate_addresses=dict(required=False, type='str'),
                        resource_type=dict(required=True, type='str')),
                        id=dict(required=True, type='str')),
                        admin_state=dict(required=True, type='str'),
                        extra_configs=dict(required=False, type='list'),
                        address_bindings=dict(required=False, type='list'),
                        state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_port_params = get_logical_port_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  lport_dict = get_logical_port_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  lport_id, revision = None, None
  if lport_dict:
    lport_id = lport_dict['id']
    revision = lport_dict['_revision']

  if state == 'present':
    body = update_params_with_id(module, manager_url, mgr_username, mgr_password, validate_certs, logical_port_params)
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if not updated:
      # add the logical_port
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id='12345')
      request_data = json.dumps(body)
      try:
          if lport_id:
              module.exit_json(changed=False, id=lport_id, message="Logical port with display_name %s already exist"% module.params['display_name'])

          (rc, resp) = request(manager_url+ '/logical-ports', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to add logical port. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Logical port with displayname %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id=lport_id)
      body['_revision'] = revision # update current revision
      request_data = json.dumps(body)
      id = lport_id
      try:
          (rc, resp) = request(manager_url+ '/logical-ports/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update logical port with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="logical port with id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = lport_id
    if id is None:
        module.exit_json(changed=False, msg='No logical port exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(logical_port_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/logical-ports/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete logical port with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Logical port with id %s deleted." % id)


if __name__ == '__main__':
    main()
