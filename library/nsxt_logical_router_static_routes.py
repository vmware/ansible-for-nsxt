#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
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
module: nsxt_logical_router_static_routes
short_description: Add Static Routes on a Logical Router
description: Add Static Routes on a Logical Router
version_added: "2.7"
author: Rahul Raghuvanshi
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
    id:
        description: unique id
        required: false
        type: str
    logical_router_name:
        description: Name of the logical router
        required: false
        type: str
    network:
        description: destination in cidr
        required: true
        type: str
    next_hops:
        description: Next Hops
        required: true
        type: array of StaticRouteNextHop
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
    - name: Add Static Routes on a Logical Router
      nsxt_logical_router_static_routes:
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: False
        logical_router_name: "tier-0"
        next_hops:
        - administrative_distance: '2'
          ip_address: 192.168.200.253
        network: 192.168.200.0/24
        state: "present"


'''

RETURN = '''# '''






import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_body_object(body):
  if body.__contains__('id'):
    del body['id']
  if body.__contains__('logical_router_id'):
    del body['logical_router_id']
  return body


def get_logical_router_static_route_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name, exit_if_not_found=True):
    try:
      (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == display_name:
            return result['id']
    if exit_if_not_found:
        module.fail_json(msg='No id exist with display name %s' % display_name)

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_static_route_params ):
    logical_router_static_route_params['logical_router_id'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                '/logical-routers', logical_router_static_route_params.pop('logical_router_name', None))
    return logical_router_static_route_params

def get_logical_router_static_routes(module, manager_url, mgr_username, mgr_password, validate_certs,logical_router_id):
    try:
      (rc, resp) = request(manager_url+ '/logical-routers/%s/routing/static-routes' % logical_router_id , headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing logical router ports. Error [%s]' % (to_native(err)))
    return resp

def get_lr_static_route_from_network(module, manager_url, mgr_username, mgr_password, validate_certs, network, logical_router_id):
    logical_router_st_routes = get_logical_router_static_routes(module, manager_url, mgr_username, mgr_password, validate_certs,logical_router_id)
    for logical_router_st_route in logical_router_st_routes['results']:
        if logical_router_st_route.__contains__('network') and logical_router_st_route['network'] == network:
            return logical_router_st_route
    return None


def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(next_hops=dict(required=True, type='list'),
                logical_router_name=dict(required=False, type='str'),
                network=dict(required=True, type='str'),
                id=dict(required=False, type= 'str'),
                state=dict(required=True, choices=['present', 'absent']))


  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_router_static_route_params = get_logical_router_static_route_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  network = module.params['network']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)
  update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_static_route_params)
  logical_router_id = logical_router_static_route_params["logical_router_id"]
  logical_router_static_route_id = module.params["id"]


  if logical_router_static_route_id is None:
  	logical_router_static_route_dict = get_lr_static_route_from_network (module, manager_url, mgr_username, mgr_password, validate_certs, network,logical_router_id)
  	logical_router_static_route_id = None
  	if logical_router_static_route_dict:
    		logical_router_static_route_id = logical_router_static_route_dict['id']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    #updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_static_route_params)
    updated = 0

    if not updated:
      # add the logical_router_static_route
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_static_route_params)), id='12345')
      request_data = json.dumps(logical_router_static_route_params)
      try:
          if logical_router_static_route_id:
              module.exit_json(changed=False, id=logical_router_static_route_id, message="Logical router static route with network %s already exist."% module.params['network'])

          (rc, resp) = request(manager_url+ '/logical-routers/%s/routing/static-routes' % logical_router_id, data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to add logical router port. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Logical router static route  with network %s created." % module.params['network'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_static_route_params)), id=logical_router_port_id)
      logical_router_static_route_params['_revision'] = revision # update current revision
      request_data = json.dumps(logical_router_static_route_params)
      id = logical_router_port_id
      try:
          (rc, resp) = request(manager_url+ '/logical-routers/%s/routing/static-routes/%s' % (logical_router_id,id), data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update logical router static route with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="logical router static route  with id %s updated." % id)

  elif state == 'absent':
    if logical_router_static_route_id is None:
        module.exit_json(changed=False, msg='No logical router static route exist with network %s' % network)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_static_route_params)), id=logical_router_static_route_id)
    try:
        (rc, resp) = request(manager_url + "/logical-routers/%s/routing/static-routes/%s" % (logical_router_id,logical_router_static_route_id), method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete logical static route with id %s. Error[%s]." % (logical_router_static_route_id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=logical_router_static_route_id, message="Logical router static route with id %s deleted." % logical_router_static_route_id)




if __name__ == '__main__':
	main()
