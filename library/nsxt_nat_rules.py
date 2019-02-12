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

EXAMPLES = '''
  nsxt_nat_rules:
     hostname: "192.168.110.31" 
     username: "admin"
     password: "VMware1!"
     validate_certs: False
     router_name: "Tier-1"
     action: "SNAT"
     match_source_network: "192.168.111.11"
     translated_network: "192.168.110.65"
     match_service: 
         resource_type: "L4PortSetNSService"
         source_ports: ["9000"]
         destination_ports: ["9000"]
         l4_protocol: "TCP"
     enabled: true
     state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

import logging
logger = logging.getLogger('NAT Rules')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

def get_logical_nat_rules_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs', 'router_name', 'nat_id']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_nat_rules(module, manager_url, mgr_username, mgr_password, validate_certs,router_name):
    router_id = get_router_id_from_router_name(module,manager_url,mgr_username,mgr_password,validate_certs,router_name)
    logger.info(router_id)
    try:
      (rc, resp) = request(manager_url+ '/logical-routers/'+router_id+'/nat/rules', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      logger.info(resp)

    except Exception as err:
      module.fail_json(msg='Error accessing while getting the data. Error [%s]' % (to_native(err)))
    return resp



def get_router_id_from_router_name(module, manager_url, mgr_username, mgr_password, validate_certs, router_name):
    try:
      (rc, resp) = request(manager_url+'/logical-routers', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
       module.fail_json(msg='Error No Logical Routers %ss. Error: [%s]' %(router_name, to_native(err)))
    for result in resp['results']:
        logger.info(result['display_name'])
        if result.__contains__('display_name') and result['display_name'] == router_name:
            return result['id']
    module.fail_json(msg='No id exist with router name%s' % router_name)



def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(action=dict(required=True, choices=['SNAT', 'DNAT', 'REFLEXIVE', 'NO_NAT', 'NO_SNAT', 'NO_DNAT'] ),
                       state=dict(required=True, choices=['present', 'absent']),
                       match_source_network=dict(required=False, type= 'str'),
                       match_destination_network=dict(required=False, type= 'str'),
                       translated_network=dict(required=False, type='str'),
                       match_service=dict(required=False, type='dict'),
                       router_name=dict(required=True, type='str'),
                       nat_id=dict(required=False, type='str'),
                       enabled=dict(required=True, choices=['true', 'false']))
               
  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_nat_rules_params = get_logical_nat_rules_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  router_name = module.params['router_name']
  nat_id = module.params['nat_id']
  action = module.params['action']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  nat_dict = get_nat_rules(module, manager_url, mgr_username, mgr_password, validate_certs, router_name)
  logical_router_id = get_router_id_from_router_name(module, manager_url, mgr_username, mgr_password, validate_certs, router_name)
  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    request_data = json.dumps(logical_nat_rules_params)
    try:
        
       (rc, resp) = request(manager_url+ '/logical-routers/'+logical_router_id+'/nat/rules', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
       module.exit_json(changed=True, id=resp["id"], body= str(resp), message="NAT rules with %s action created." %action)
    except Exception as err:
       module.fail_json(msg="Failed to create NAT rules. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      
  elif state == 'absent':
    # delete the array    
    try:
        (rc, resp) = request(manager_url +'/logical-routers/'+logical_router_id+'/nat/rules/'+nat_id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete NAT rule with id %s. Error[%s]." % (nat_id, to_native(err)))
    time.sleep(5)
    module.exit_json(changed=True, message="NAT Rule with %s Deleted" % nat_id)


if __name__ == '__main__':
    main()
