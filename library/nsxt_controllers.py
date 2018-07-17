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
- nsxt_controllers:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    deployment_requests:
    - roles:
    - CONTROLLER
      form_factor: "MEDIUM"
      user_settings:
        cli_password: "Admin!23Admin"
        root_password: "Admin!23Admin"
      deployment_config:
        placement_type: VsphereClusterNodeVMDeploymentConfig
        vc_id: "67dbce0d-973e-4b7d-813d-7ae5a91754c2"
        management_network_id: "network-44"
        hostname: "controller-1"
        compute_id: "domain-c49"
        storage_id: "datastore-43"
        default_gateway_addresses:
        - 10.112.203.253
        management_port_subnets:
        - ip_addresses:
          - 10.112.201.25
          prefix_length: "19"
    clustering_config:
    clustering_type: ControlClusteringConfig
    shared_secret: "123456"
    join_to_existing_cluster: false
    state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

FAILED_STATES = ["UNKNOWN_STATE", "VM_DEPLOYMENT_FAILED", "VM_POWER_ON_FAILED", "VM_ONLINE_FAILED", "VM_CLUSTERING_FAILED",
                      "VM_DECLUSTER_FAILED", "VM_POWER_OFF_FAILED", "VM_UNDEPLOY_FAILED"]
IN_PROGRESS_STATES = ["VM_DEPLOYMENT_QUEUED", "VM_DEPLOYMENT_IN_PROGRESS", "VM_POWER_ON_IN_PROGRESS",  "WAITING_TO_REGISTER_VM", "VM_WAITING_TO_CLUSTER",
                      "VM_WAITING_TO_COME_ONLINE", "VM_CLUSTERING_IN_PROGRESS", "WAITING_TO_UNDEPLOY_VM", "VM_DECLUSTER_IN_PROGRESS",
                      "VM_POWER_OFF_IN_PROGRESS", "VM_UNDEPLOY_IN_PROGRESS", "VM_UNDEPLOY_SUCCESSFUL"]
SUCCESS_STATES = ["VM_CLUSTERING_SUCCESSFUL", "VM_DECLUSTER_SUCCESSFUL"]
def get_controller_node_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs', 'node_id']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_controllers(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/cluster/nodes/deployments', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing controller. Error [%s]' % (to_native(err)))
    return resp

def check_controller_node_exist(existing_controllers_data, module):
    new_deployment_requests = module.params['deployment_requests']
    for result in existing_controllers_data['results']:
        for new_deployment_request in new_deployment_requests:
            if result['deployment_config']['hostname'] == new_deployment_request['deployment_config']['hostname']:
                return True, result['deployment_config']['hostname']
    return False, None

def wait_till_create(vm_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/cluster/nodes/deployments/%s/status'% vm_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          if any(resp['status'] in progress_status for progress_status in IN_PROGRESS_STATES):
              time.sleep(10)
          elif any(resp['status'] in progress_status for progress_status in SUCCESS_STATES):
              time.sleep(5)
              return
          else:
              module.fail_json(msg= 'Error in controller status: %s'%(str(resp['status'])))
    except Exception as err:
      module.fail_json(msg='Error accessing controller status. Error [%s]' % (to_native(err)))

def wait_till_delete(vm_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/cluster/nodes/deployments/%s/status'% vm_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          time.sleep(10)
    except Exception as err:
      time.sleep(5)
      return

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(deployment_requests=dict(required=True, type='list'),
                    clustering_config=dict(required=True, type='dict',
                    join_to_existing_cluster=dict(required=True, type='boolean'),
                    shared_secret=dict(required=False, type='str'),
                    clustering_type=dict(required=True, type='str')),
                    node_id=dict(required=False, type='str'),
                    state=dict(reauired=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                         required_if=[['state', 'absent', ['node_id']]])
  node_params = get_controller_node_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'
  request_data = json.dumps(node_params)
  if state == 'present':
    # add controller
    results = get_controllers(module, manager_url, mgr_username, mgr_password, validate_certs)
    is_controller_node_exist, hostname = check_controller_node_exist(results, module)
    if is_controller_node_exist:
      module.exit_json(changed=False, message="controller with hostname %s already exist."% hostname)

    if module.check_mode:
      module.exit_json(changed=True, debug_out=str(request_data))
    try:
      (rc, resp) = request(manager_url+ '/cluster/nodes/deployments', data=request_data, headers=headers, method='POST',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to add controller. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    for controller in resp['results']:
      wait_till_create(controller['vm_id'], module, manager_url, mgr_username, mgr_password, validate_certs)
    time.sleep(5)
    module.exit_json(changed=True, body= str(resp), message="Controllers deployed.")

  elif state == 'absent':
    # delete controller
    id = module.params['node_id']
    if module.check_mode:
      module.exit_json(changed=True, debug_out=str(request_data))
    try:

      (rc, resp) = request(manager_url+ '/cluster/nodes/deployments/%s?action=delete' % id, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to delete controller with id %s. Error[%s]." % (id, to_native(err)))

    wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs)
    time.sleep(5)
    module.exit_json(changed=changed, id=id, message="controller with node id %s deleted." % id)

if __name__ == '__main__':
    main()
