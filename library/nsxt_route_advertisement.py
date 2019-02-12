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
author: VJ49
'''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

import logging
logger = logging.getLogger('Route Advertisment')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}



def get_routing_advertisement_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs', 'router_name']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args


def get_routing_advertisement(module, manager_url, mgr_username, mgr_password, validate_certs,router_name):
    logical_router_id = get_logical_router_id_from_router_name(module,manager_url,mgr_username, mgr_password, validate_certs, router_name)
    try:
      (rc, resp) = request(manager_url +'/logical-routers/'+ logical_router_id + '/routing/advertisement', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing Router Advertisment. Error [%s]' % (to_native(err)))
    return resp
	





def get_logical_router_id_from_router_name(module, manager_url, mgr_username, mgr_password, validate_certs, router_name):
    try:
      (rc, resp) = request(manager_url+'/logical-routers', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
       module.fail_json(msg='Error No Logical Routers %s. Error: [%s]' %(router_name, to_native(err)))
    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == router_name:
            return result['id']
    module.fail_json(msg='No id exist with router name%s' % router_name)

	
def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(resource_type=dict(required=True, type='str'),
                        router_name=dict(required=True, type='str'),
                        advertise_nsx_connected_routes=dict(required=True, type='bool'),
                        advertise_static_routes=dict(required=True, type='bool'),
                        advertise_nat_routes=dict(required=True, type='bool'),
                        advertise_lb_vip=dict(required=True, type='bool'),
                        advertise_lb_snat_ip=dict(required=True, type='bool'),
                        enabled=dict(required=True, type='bool'))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  routing_advertisement_params = get_routing_advertisement_params(module.params.copy())
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  router_name = module.params['router_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)
  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'
  router_adv_dict = get_routing_advertisement(module, manager_url, mgr_username, mgr_password, validate_certs,router_name)
  router_adv_id, revision = None, None
  if module.check_mode:
    module.exit_json(changed=True, debug_out=str(json.dumps(routing_advertisement_params )))
  if router_adv_dict:
    router_adv_id = router_adv_dict['id']
    revision = router_adv_dict['_revision']
  routing_advertisement_params['_revision'] = revision  # update current revision
  request_data = json.dumps(routing_advertisement_params)  
  logger.info('request_data:{}'.format(request_data))
  logical_router_id = get_logical_router_id_from_router_name(module, manager_url, mgr_username, mgr_password, validate_certs, router_name)
  logger.info('routerid:{}'.format(logical_router_id))
  try:
     (rc, resp) = request(manager_url+'/logical-routers/'+ logical_router_id + '/routing/advertisement', data=request_data, headers=headers, method='PUT',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
  except Exception as err:
      logger.info(err.args)
      module.fail_json(msg="Failed to update Router Advertisment Error[%s]." % err)
  time.sleep(5)
  module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Router Advertisment is updated with id %s updated." % id)


if __name__ == '__main__':
    main()
