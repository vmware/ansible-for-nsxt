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
- nsxt_logical_routers:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      resource_type: LogicalRouter
      description: "Router West"
      display_name: "tier-0"
      edge_cluster_name: edge-cluster-1
      router_type: TIER0
      high_availability_mode: ACTIVE_ACTIVE
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_logical_router_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_logical_routers(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/logical-routers', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing logical routers. Error [%s]' % (to_native(err)))
    return resp

def get_lr_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    logical_routers = get_logical_routers(module, manager_url, mgr_username, mgr_password, validate_certs)
    for logical_router in logical_routers['results']:
        if logical_router.__contains__('display_name') and logical_router['display_name'] == display_name:
            return logical_router
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

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_params ):

    if logical_router_params.__contains__('edge_cluster_name'):
        edge_cluster_name = logical_router_params.pop('edge_cluster_name', None)
        logical_router_params['edge_cluster_id'] = get_id_from_display_name (module, manager_url,
                                                                                mgr_username, mgr_password, validate_certs,
                                                                                "/edge-clusters", edge_cluster_name)
    if logical_router_params.__contains__('advanced_config') and logical_router_params['advanced_config'].__contains__('transport_zone_name'):
        transport_zone_name= logical_router_params['advanced_config'].pop('transport_zone_name', None)
        logical_router_params['advanced_config']['transport_zone_id'] = get_id_from_display_name (module, manager_url,
                                                                                mgr_username, mgr_password, validate_certs,
                                                                                "/transport-zones", transport_zone_name)
    return logical_router_params

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_with_ids):
    existing_logical_router = get_lr_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_with_ids['display_name'])
    if existing_logical_router is None:
        return False
    if existing_logical_router.__contains__('edge_cluster_id') and logical_router_with_ids.__contains__('edge_cluster_id') and \
        existing_logical_router['edge_cluster_id'] != logical_router_with_ids['edge_cluster_id']:
        return True
    if existing_logical_router.__contains__('advanced_config') and logical_router_with_ids.__contains__('advanced_config'):
        if existing_logical_router['advanced_config'].__contains__('internal_transit_network') and logical_router_with_ids['advanced_config'].__contains__('internal_transit_network') and \
            existing_logical_router['advanced_config']['internal_transit_network'] != logical_router_with_ids['advanced_config']['internal_transit_network']:
            return True
        if existing_logical_router['advanced_config'].__contains__('external_transit_networks') and logical_router_with_ids['advanced_config'].__contains__('external_transit_networks') and \
            existing_logical_router['advanced_config']['external_transit_networks'] != logical_router_with_ids['advanced_config']['external_transit_networks']:
            return True
        if existing_logical_router['advanced_config'].__contains__('ha_vip_configs') is False and \
            logical_router_with_ids['advanced_config'].__contains__('ha_vip_configs') is True:
            return True
    return False


def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                        description=dict(required=False, type='str'),
                        failover_mode=dict(required=False, type='str'),
                        advanced_config=dict(required=False, type='dict',
                            internal_transit_network=dict(required=False, type='str'),
                            transport_zone_name=dict(required=False, type='str'),
                            ha_vip_configs=dict(required=False, type='list'),
                            external_transit_networks=dict(required=False, type='list')),
                        router_type=dict(required=True, type='str'),
                        preferred_edge_cluster_member_index=dict(required=False, type='int'),
                        high_availability_mode=dict(required=False, type='str'),
                        edge_cluster_name=dict(required=False, type='str'),
                        resource_type=dict(required=False, type='str', choices=['LogicalRouter']),
                        state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_router_params = get_logical_router_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  logical_router_dict = get_lr_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  logical_router_id, revision = None, None
  if logical_router_dict:
    logical_router_id = logical_router_dict['id']
    revision = logical_router_dict['_revision']

  if state == 'present':
    body = update_params_with_id(module, manager_url, mgr_username, mgr_password, validate_certs, logical_router_params)
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if not updated:
      # add the router
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id='12345')
      request_data = json.dumps(body)
      try:
          if logical_router_id:
              module.exit_json(changed=False, id=logical_router_id, message="Logical router with display_name %s already exist."% module.params['display_name'])

          (rc, resp) = request(manager_url+ '/logical-routers', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to add logical router. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Logical router with display_name %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id=logical_router_id)

      body['_revision'] = revision # update current revision
      request_data = json.dumps(body)
      id = logical_router_id
      try:
          (rc, resp) = request(manager_url+ '/logical-routers/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update logical router with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="logical router with id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = logical_router_id
    if id is None:
        module.exit_json(changed=False, msg='No logical router exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(logical_router_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/logical-routers/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete logical router with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="logical router with id %s deleted." % id)


if __name__ == '__main__':
    main()
