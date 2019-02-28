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
author: Ramesh Chandra
'''

EXAMPLES = '''
- name: Create transport node
  nsxt_transport_nodes:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    resource_type: "TransportNode"
    display_name: "NSX Configured TN"
    description: "NSX configured Test Transport Node"
    host_switch_spec:
      resource_type: "StandardHostSwitchSpec"
      host_switches:
      - host_switch_profiles:
        - name: "uplinkProfile1"
          type: "UplinkHostSwitchProfile"
        host_switch_name: "hostswitch1"
        pnics:
        - device_name: "vmnic1"
          uplink_name: "uplink-1"
        ip_assignment_spec:
          resource_type: "StaticIpPoolSpec"
          ip_pool_name: "IPPool-IPV4-1"
    transport_zone_endpoints:
    - transport_zone_name: "TZ1"
    node_deployment_info:
      resource_type: "HostNode"
      display_name: "Host_1"
      ip_addresses: ["10.149.55.21"]
      os_type: "ESXI"
      os_version: "6.5.0"
      host_credential:
        username: "root"
        password: "ca$hc0w"
        thumbprint: "e7fd7dd84267da10f991812ca62b2bedea3a4a62965396a04728da1e7f8e1cb9"
    # Edge node_deployment_info
    # node_deployment_info:
    #   resource_type: "EdgeNode"
    #   display_name: "EdegeNode1"
    #   ip_addresses:
    #   deployment_type: "VIRTUAL_MACHINE"
    #   deployment_config:
    #     form_factor: "SMALL"
    #     node_user_settings:
    #       cli_password: "Admin!23Admin"
    #       root_password: "Admin!23Admin"
    #     vm_deployment_config:
    #       placement_type: VsphereDeploymentConfig
    #       vc_name: "VC2"
    #       data_network_ids:
    #       - network-16
    #       - network-16
    #       - network-16
    #       management_network_id: "network-16"
    #       hostname: "edge1.com"
    #       compute_id: "domain-c7"
    #       storage_id: "datastore-15"
    #       host_id: "host-14"
    #       default_gateway_addresses:
    #       management_port_subnets:
    node_id: null
    state: "present"

'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
import socket
import hashlib
import ssl

FAILED_STATES = ["failed"]
IN_PROGRESS_STATES = ["pending", "in_progress"]
SUCCESS_STATES = ["partial_success", "success"]


def get_transport_node_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args


def get_transport_nodes(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url + '/transport-nodes', headers=dict(Accept='application/json'),
                           url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing transport nodes. Error [%s]' % (to_native(err)))
    return resp


def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name, exit_if_not_found=True):
    try:
      (rc, resp) = request(manager_url + endpoint, headers=dict(Accept='application/json'),
                           url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == display_name:
            return result['id']
    if exit_if_not_found:
        module.fail_json(msg='No id exist with display name %s' % display_name)


def get_tn_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    transport_nodes = get_transport_nodes(module, manager_url, mgr_username, mgr_password, validate_certs)
    for transport_node in transport_nodes['results']:
        if transport_node.__contains__('display_name') and transport_node['display_name'] == display_name:
            return transport_node
    return None


def wait_till_create(node_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      count = 0
      while True:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s/state'% node_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          if any(resp['state'] in progress_status for progress_status in IN_PROGRESS_STATES):
              time.sleep(10)
              count = count + 1
              if count == 90:
                    #Wait for max 15 minutes for host to realize
                    module.fail_json(msg= 'Error creating transport node: %s'%(str(resp['state'])))
          elif any(resp['state'] in progress_status for progress_status in SUCCESS_STATES):
                time.sleep(5)
                return
          else:
                module.fail_json(msg='Error creating transport node: %s'%(str(resp['state'])))
    except Exception as err:
      module.fail_json(msg='Error accessing transport node. Error [%s]' % (to_native(err)))

def wait_till_delete(vm_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s/state'% vm_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          time.sleep(10)
    except Exception as err:
      time.sleep(5)
      return

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_params ):
    if transport_node_params.__contains__('host_switch_spec'):
        for host_switch in transport_node_params['host_switch_spec']['host_switches']:
            host_switch_profiles = host_switch.pop('host_switch_profiles', None)

            host_switch_profile_ids = []
            for host_switch_profile in host_switch_profiles:
                profile_obj = {}
                profile_obj['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                                                        "/host-switch-profiles", host_switch_profile['name'])
                profile_obj['key'] = host_switch_profile['type']
                host_switch_profile_ids.append(profile_obj)
            host_switch['host_switch_profile_ids'] = host_switch_profile_ids
            ip_pool_id = None
            if host_switch.__contains__('ip_assignment_spec') and host_switch['ip_assignment_spec']['resource_type'] == 'StaticIpPoolSpec':
                ip_pool_name = host_switch['ip_assignment_spec'].pop('ip_pool_name', None)
                host_switch['ip_assignment_spec']['ip_pool_id'] = get_id_from_display_name (module, manager_url,
                                                                                            mgr_username, mgr_password, validate_certs,
                                                                                            "/pools/ip-pools", ip_pool_name)
    if transport_node_params.__contains__('transport_zone_endpoints'):
        for transport_zone_endpoint in transport_node_params['transport_zone_endpoints']:
            transport_zone_name = transport_zone_endpoint.pop('transport_zone_name', None)
            transport_zone_endpoint['transport_zone_id'] = get_id_from_display_name (module, manager_url,
                                                                                    mgr_username, mgr_password, validate_certs,
                                                                                    "/transport-zones", transport_zone_name)
    if transport_node_params['node_deployment_info']['resource_type'] == 'EdgeNode':        
        vc_name = transport_node_params['node_deployment_info']['deployment_config']['vm_deployment_config'].pop('vc_name', None)
        transport_node_params['node_deployment_info']['deployment_config']['vm_deployment_config']['vc_id'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                    "/fabric/compute-managers", vc_name)

    transport_node_params['display_name'] = transport_node_params.pop('display_name', None)
    return transport_node_params
#
# def ordered(obj):
#     if isinstance(obj, dict):
#         return sorted((k, ordered(v)) for k, v in obj.items())
#     if isinstance(obj, list):
#         return sorted(ordered(x) for x in obj)
#     else:
#         return obj

def id_exist_in_list_dict_obj(key, list_obj1, list_obj2):
    all_id_presents = False
    if len(list_obj1) != len(list_obj2):
        return all_id_presents
    for dict_obj1 in list_obj1:
        if dict_obj1.__contains__(key):
            for dict_obj2 in list_obj2:
                if dict_obj2.__contains__(key) and dict_obj1[key] == dict_obj2[key]:
                    all_id_presents = True
                    continue
            if not all_id_presents:
                return False
    return True
def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_with_ids):
    existing_transport_node = get_tn_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_with_ids['display_name'])
    if existing_transport_node is None:
        return False
    if existing_transport_node.__contains__('transport_zone_endpoints') and transport_node_with_ids.__contains__('transport_zone_endpoints'):
        return not id_exist_in_list_dict_obj('transport_zone_id', existing_transport_node['transport_zone_endpoints'], transport_node_with_ids['transport_zone_endpoints'])
    if existing_transport_node.__contains__('host_switch_spec') and existing_transport_node['host_switch_spec'].__contains__('host_switches') and \
        transport_node_with_ids.__contains__('host_switch_spec') and transport_node_with_ids['host_switch_spec'].__contains__('host_switches') and \
        existing_transport_node['host_switch_spec']['host_switches'] != transport_node_with_ids['host_switch_spec']['host_switches']:
        return True
    return False


def get_api_cert_thumbprint(ip_address, module):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((ip_address, 443))
    except Exception as err:
        module.fail_json(msg='Failed to get node ID from ESXi host with IP {}. Error: {}'.format(ip_address, err))
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        return thumb_sha256
    finally:
        wrappedSocket.close()

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                       host_switch_spec=dict(required=False, type='dict',
                       host_switches=dict(required=True, type='list'),
                       resource_type=dict(required=True, type='str')),
                       node_deployment_info=dict(required=False, type='dict',
                       discovered_node_id=dict(required=False, type='str'),
                       deployment_config=dict(required=False, type='dict',
                       node_user_settings=dict(required=True, type='dict',
                       cli_username=dict(required=False, type='str'),
                       audit_username=dict(required=False, type='str'),
                       root_password=dict(required=False, type='str'),
                       cli_password=dict(required=False, type='str'),
                       audit_password=dict(required=False, type='str')),
                       vm_deployment_config=dict(required=True, type='dict',
                       data_network_ids=dict(required=True, type='list'),
                       dns_servers=dict(required=False, type='list'),
                       ntp_servers=dict(required=False, type='list'),
                       management_network_id=dict(required=True, type='str'),
                       enable_ssh=dict(required=False, type='boolean'),
                       allow_ssh_root_login=dict(required=False, type='boolean'),
                       placement_type=dict(required=True, type='str'),
                       compute_id=dict(required=True, type='str'),
                       search_domains=dict(required=False, type='list'),
                       vc_id=dict(required=True, type='str'),
                       storage_id=dict(required=True, type='str'),
                       default_gateway_addresses=dict(required=False, type='list'),
                       management_port_subnets=dict(required=False, type='list'),
                       host_id=dict(required=False, type='str'),
                       hostname=dict(required=True, type='str')),
                       form_factor=dict(required=False, type='str')),
                       discovered_ip_addresses=dict(required=False, type='list'),
                       ip_addresses=dict(required=False, type='list'),
                       fqdn=dict(required=False, type='str'),
                       os_version=dict(required=False, type='str'),
                       managed_by_server=dict(required=False, type='str'),
                       host_credential=dict(required=False, type='dict',
                       username=dict(required=False, type='str'),
                       password=dict(required=False, type='str'),
                       thumbprint=dict(required=False, type='str')),
                       allocation_list=dict(required=False, type='list'),
                       os_type=dict(required=True, type='str'),
                       external_id=dict(required=False, type='str'),
                       resource_type=dict(required=True, type='str'),
                       deployment_type=dict(required=False, type='str')),
                       maintenance_mode=dict(required=False, type='str'),
                       transport_zone_endpoints=dict(required=False, type='list'),
                       node_id=dict(required=False, type='str'),
                       state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  transport_node_params = get_transport_node_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  transport_node_dict = get_tn_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  transport_node_id, revision = None, None
  if transport_node_dict:
    transport_node_id = transport_node_dict['id']
    revision = transport_node_dict['_revision']

  if state == 'present':
    body = update_params_with_id(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_params)
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if not updated:
        # add the node
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_switch_params)), id='12345')
      thumbprint = body["node_deployment_info"]["host_credential"]["thumbprint"]
      esxi_ip_address = body["node_deployment_info"]["ip_addresses"][0]
      if not thumbprint:
          thumbprint = get_api_cert_thumbprint(esxi_ip_address, module)
          body["node_deployment_info"]["host_credential"]["thumbprint"] = thumbprint
      request_data = json.dumps(body)
      try:
          if not transport_node_id:
              transport_node_id = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, '/transport-nodes', display_name, exit_if_not_found=False)
          if transport_node_id:
              module.exit_json(changed=False, id=transport_node_id, message="Transport node with display_name %s already exist."% module.params['display_name'])

          (rc, resp) = request(manager_url+ '/transport-nodes', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
           module.fail_json(msg="Failed to add transport node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      wait_till_create(resp['node_id'], module, manager_url, mgr_username, mgr_password, validate_certs)
      time.sleep(5)
      module.exit_json(changed=True, id=resp["node_id"], body= str(resp), message="Transport node with display name %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id=transport_node_id)
      body['_revision'] = revision # update current revision
      thumbprint = body["node_deployment_info"]["host_credential"]["thumbprint"]
      esxi_ip_address = body["node_deployment_info"]["ip_addresses"][0]
      if not thumbprint:
          thumbprint = get_api_cert_thumbprint(esxi_ip_address, module)
          body["node_deployment_info"]["host_credential"]["thumbprint"] = thumbprint
      request_data = json.dumps(body)
      id = transport_node_id
      try:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update transport node with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["node_id"], body= str(resp), message="Transport node with node id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = transport_node_id
    if id is None:
        module.exit_json(changed=False, msg='No transport node exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(transport_node_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/transport-nodes/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete transport node with id %s. Error[%s]." % (id, to_native(err)))

    wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs)
    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Transport node with node id %s deleted." % id)



if __name__ == '__main__':
    main()
