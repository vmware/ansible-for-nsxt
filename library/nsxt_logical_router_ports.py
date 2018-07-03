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
- nsxt_logical_routers_ports:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      resource_type: LogicalRouterDownLinkPort
      logical_router_id: "723c1e3e-c82c-4243-bba0-2e1ef4815143"
      linked_logical_switch_port_id:
        target_type: LogicalPort
        target_id: "18691381-b08f-4d90-8c0c-98d0e449b141"
      subnets:
      - ip_addresses:
        - "172.16.40.1"
        prefix_length: 24
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_logical_router_port_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_logical_router_ports(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/logical-router-ports', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing logical router ports. Error [%s]' % (to_native(err)))
    return resp

def get_lr_port_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    logical_router_ports = get_logical_router_ports(module, manager_url, mgr_username, mgr_password, validate_certs)
    for logical_router_port in logical_router_ports['results']:
        if logical_router_port.__contains__('display_name') and logical_router_port['display_name'] == display_name:
            return logical_router_port
    return None

# def ordered(obj):
#     if isinstance(obj, dict):
#         return sorted((k, ordered(v)) for k, v in obj.items())
#     if isinstance(obj, list):
#         return sorted(ordered(x) for x in obj)
#     else:
#         return obj

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_port_params):
    existing_lr_port = get_lr_port_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_port_params['display_name'])
    if existing_lr_port is None:
        return False
    if existing_lr_port['resource_type'] != logical_router_port_params['resource_type']:
        return True
    if existing_lr_port['logical_router_id'] != logical_router_port_params['logical_router_id']:
        return True
    if existing_lr_port.__contains__('service_bindings') and logical_router_port_params.__contains__('service_bindings') and \
        existing_lr_port['service_bindings'] != logical_router_port_params['service_bindings']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                        subnets=dict(required=False, type='list'),
                        urpf_mode=dict(required=False, type='str'),
                        mac_address=dict(required=False, type='str'),
                        linked_logical_switch_port_id=dict(required=False, type='dict',
                        selected=dict(required=True, type='boolean'),
                        service=dict(required=False, type='dict',
                        ether_type=dict(required=True, type='int'),
                        destination_ports=dict(required=False, type='list'),
                        l4_protocol=dict(required=True, type='str'),
                        source_ports=dict(required=False, type='list'),
                        icmp_code=dict(required=False, type='int'),
                        icmp_type=dict(required=False, type='int'),
                        protocol=dict(required=True, type='str'),
                        protocol_number=dict(required=True, type='int'),
                        alg=dict(required=True, type='str'),
                        resource_type=dict(required=True, type='str')),
                        target_display_name=dict(required=False, type='str'),
                        is_valid=dict(required=False, type='boolean'),
                        target_id=dict(required=False, type='str'),
                        target_type=dict(required=False, type='str')),
                        admin_state=dict(required=False, type='str'),
                        vpn_session_id=dict(required=False, type='str'),
                        enable_netx=dict(required=False, type='boolean'),
                        edge_cluster_member_index=dict(required=False, type='list'),
                        mtu=dict(required=False, type='int'),
                        linked_logical_router_port_id=dict(required=False, type='dict',
                        selected=dict(required=True, type='boolean'),
                        service=dict(required=False, type='dict',
                        ether_type=dict(required=True, type='int'),
                        destination_ports=dict(required=False, type='list'),
                        l4_protocol=dict(required=True, type='str'),
                        source_ports=dict(required=False, type='list'),
                        icmp_code=dict(required=False, type='int'),
                        icmp_type=dict(required=False, type='int'),
                        protocol=dict(required=True, type='str'),
                        protocol_number=dict(required=True, type='int'),
                        alg=dict(required=True, type='str'),
                        resource_type=dict(required=True, type='str')),
                        target_display_name=dict(required=False, type='str'),
                        is_valid=dict(required=False, type='boolean'),
                        target_id=dict(required=False, type='str'),
                        target_type=dict(required=False, type='str')),
                        logical_router_id=dict(required=True, type='str'),
                        service_bindings=dict(required=False, type='list'),
                        resource_type=dict(required=True, type='str'),
                        state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_router_port_params = get_logical_router_port_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  logical_router_port_dict = get_lr_port_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  logical_router_port_id, revision = None, None
  if logical_router_port_dict:
    logical_router_port_id = logical_router_port_dict['id']
    revision = logical_router_port_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_port_params)

    if not updated:
      # add the logical_router_port
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_port_params)), id='12345')
      request_data = json.dumps(logical_router_port_params)
      try:
          if logical_router_port_id:
              module.exit_json(changed=False, id=logical_router_port_id, message="Logical router port with display_name %s already exist."% module.params['display_name'])

          (rc, resp) = request(manager_url+ '/logical-router-ports', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to add logical router port. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Logical router port with displayname %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_port_params)), id=logical_router_port_id)
      logical_router_port_params['_revision'] = revision # update current revision
      request_data = json.dumps(logical_router_port_params)
      id = logical_router_port_id
      try:
          (rc, resp) = request(manager_url+ '/logical-router-ports/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update logical router port with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="logical router port with id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = logical_router_port_id
    if id is None:
        module.exit_json(changed=False, msg='No logical router port exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_port_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/logical-router-ports/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete logical router port with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Logical router port with id %s deleted." % id)


if __name__ == '__main__':
    main()
