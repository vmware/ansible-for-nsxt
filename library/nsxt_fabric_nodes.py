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


DOCUMENTATION = ''' TODO (Not complete)
module: nsxt_fabric_nodes
version_added: "2.2"
short_description: Add/update/remove fabric (host/edge) node to nsxt manager
description:
- Manage the fabric nodes
options:
  hostname:
    description:
    - Deployed NSX manager hostname.
    required: true
  username:
    description:
    - The username to authenticate with the NSX manager WebServices.
    required: true
  password:
    description:
    - The password to authenticate with the NSX manager WebServices.
    required: true
  validate_certs:
    description:
    - Should https certificates be validated?
    type: bool
    default: 'yes'
  state:
    description:
    - Desired state of module
    required: true
author: Rahul Raghuvanshi
'''

EXAMPLES = '''
- name: Add fabric node
  nsxt_fabric_nodes:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    resource_type: "HostNode"
    #node_id: "fefc3fed-84d9-4170-bf7c-5d7438ba91e9"
    display_name: "Host_10"
    ip_addresses: ["10.160.183.166"]
    os_type: "ESXI"
    os_version: "6.5.0"
    host_credential:
        username: "root"
        password: "ca$hc0w"
        thumbprint: "60:0A:68:4B:3F:B5:6C:FE:31:B0:2A:BC:CA:F8:61:CA:7B:B2:70:D5:D5:04:58:DB:59:E0:2A:22:64:35:35:C9"
    state: "present"

- name: Add Edge VM
  nsxt_fabric_nodes:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    resource_type: "EdgeNode"
    display_name: "EdegeNode1"
    #node_id: "eaaadf98-0f1a-4eb3-b8e7-2cc62ca8877b"
    ip_addresses:
      - 10.112.201.26
    deployment_config:
      form_factor: "SMALL"
      node_user_settings:
        cli_password: "Admin!23Admin"
        root_password: "Admin!23Admin"
      vm_deployment_config:
        placement_type: VsphereDeploymentConfig
        vc_id: "67dbce0d-973e-4b7d-813d-7ae5a91754c2"
        data_network_ids:
        - network-44
        - network-44
        - network-44
        management_network_id: "network-44"
        hostname: "EdgeVM1"
        compute_id: "domain-c49"
        storage_id: "datastore-43"
        default_gateway_addresses:
        - 10.112.203.253
        management_port_subnets:
        - ip_addresses:
          - 10.112.201.26
          prefix_length: "19"
    state: "present"

'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_fabric_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_fabric_nodes(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/fabric/nodes', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing fabric node. Error [%s]' % (to_native(err)))
    return resp

def get_fabric_node_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    fabric_nodes = get_fabric_nodes(module, manager_url, mgr_username, mgr_password, validate_certs)
    for fabric_node in fabric_nodes['results']:
        if fabric_node.__contains__('display_name') and fabric_node['display_name'] == display_name:
            return fabric_node
    return None

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, fabric_params):
    if fabric_params['resource_type'] != 'HostNode': # only host node update is allowed
        return False
    existing_fabric_node = get_fabric_node_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, fabric_params['display_name'])
    if existing_fabric_node is None:
        return False
    if existing_fabric_node.__contains__('ip_addresses') and fabric_params.__contains__('ip_addresses') and \
        existing_fabric_node['ip_addresses'] != fabric_params['ip_addresses']:
        return True
    return False

def wait_till_create(id, module, manager_url, mgr_username, mgr_password, validate_certs):
    DEPLOYMENT_PROGRESS = ['INSTALL_IN_PROGRESS', 'VM_DEPLOYMENT_IN_PROGRESS', 'VM_DEPLOYMENT_QUEUED', 'VM_POWER_ON_IN_PROGRESS', 'NODE_NOT_READY', 'REGISTRATION_PENDING']
    DEPLOYMENT_SUCCESS = ['NODE_READY', 'INSTALL_SUCCESSFUL']
    try:
      while True:
          (rc, resp) = request(manager_url+ '/fabric/nodes/%s/status'% id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          if resp['host_node_deployment_status'] in DEPLOYMENT_PROGRESS:
              time.sleep(10)
          elif resp['host_node_deployment_status'] in DEPLOYMENT_SUCCESS:
              time.sleep(5)
              return
          else:
              module.fail_json(msg= 'Error in fabric node status: %s'%(str(resp['host_node_deployment_status'])))
    except Exception as err:
      module.fail_json(msg='Error accessing fabric node status. Error [%s]' % (to_native(err)))

def wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/fabric/nodes/%s/status'% id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          time.sleep(10)
    except Exception as err:
      time.sleep(5)
      return

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                    action=dict(required=False, type= 'str'),
                    unprepare_host=dict(required=False, type= 'str'),
                    os_version=dict(required=False, type='str'),
                    os_type=dict(required=False, type='str'),
                    host_credential=dict(required=False, type='dict',
                        username=dict(required=False, type='str'),
                        password=dict(required=False, type='str', no_log=True),
                        thumbprint=dict(required=False, type='str', no_log=True)),
                    deployment_config=dict(required=False, type='dict',
                        node_user_settings=dict(required=True, type='dict',
                            cli_username=dict(required=False, type='str'),
                            audit_username=dict(required=False, type='str'),
                            root_password=dict(required=False, type='str', no_log=True),
                            cli_password=dict(required=False, type='str', no_log=True),
                            audit_password=dict(required=False, type='str')),
                        vm_deployment_config=dict(required=True, type='dict',
                            data_network_ids=dict(required=True, type='list'),
                            dns_servers=dict(required=False, type='list'),
                            ntp_servers=dict(required=False, type='list'),
                            management_network_id=dict(required=True, type='str'),
                            enable_ssh=dict(required=False, type='boolean'),
                            allow_ssh_root_login=dict(required=False, type='boolean'),
                            compute_id=dict(required=True, type='str'),
                            search_domains=dict(required=False, type='list'),
                            vc_id=dict(required=True, type='str'),
                            storage_id=dict(required=True, type='str'),
                            default_gateway_addresses=dict(required=False, type='list'),
                            management_port_subnets=dict(required=False, type='list'),
                            host_id=dict(required=False, type='str'),
                            hostname=dict(required=True, type='str'),
                            placement_type=dict(required=True, type='str')),
                        form_factor=dict(required=False, type='str')),
                    ip_addresses=dict(required=False, type='list'),
                    external_id=dict(required=False, type='str'),
                    resource_type=dict(required=True, type='str', choices=['HostNode', 'EdgeNode']),
                    state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                         required_if=[['resource_type', 'HostNode', ['os_type']],
                                      ['resource_type', 'EdgeNode', ['deployment_config']]])
  fabric_params = get_fabric_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  node_dict = get_fabric_node_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  node_id, revision = None, None
  if node_dict:
    node_id = node_dict['id']
    revision = node_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, fabric_params)

    if not updated:
      # add the node
      request_data = json.dumps(fabric_params)
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(request_data), id='12345')
      try:
          if node_id:
              module.exit_json(changed=False, id=node_id, message="Fabric node with display_name %s already exist."% module.params['display_name'])
          (rc, resp) = request(manager_url+ '/fabric/nodes', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
                module.fail_json(msg="Failed to add node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      wait_till_create(resp['id'], module, manager_url, mgr_username, mgr_password, validate_certs)

      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Fabric node with display name %s created succcessfully." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(fabric_params)), id=id)

      fabric_params['_revision'] = revision # update current revision
      request_data = json.dumps(fabric_params)
      id = node_id
      try:
          (rc, resp) = request(manager_url+ '/fabric/nodes/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update node wit id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Fabric node with node id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = node_id
    if id is None:
        module.exit_json(changed=False, msg='No fabric node exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(fabric_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/fabric/nodes/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete fabric node with id %s. Error[%s]." % (id, to_native(err)))

    wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs)

    module.exit_json(changed=True, id=id, message="Fabric node with node id %s deleted." % id)


if __name__ == '__main__':
    main()
