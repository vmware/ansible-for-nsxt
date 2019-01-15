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
- nsxt_edge_profile_id:
     hostname: "192.168.110.31" 
     username: "admin"
     password: "VMware1!"
     validate_certs: False
     edge_profile: "nsx-default-edge-high-availability-profile"
     state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

import logging
logger = logging.getLogger('Edge Profile Id')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

def get_logical_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs', 'edge_profile']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_edge_profile_id(module, manager_url, mgr_username, mgr_password, validate_certs, edge_profile):
    try:
      (rc, resp) = request(manager_url+ '/cluster-profiles', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      logger.info(resp)
    except Exception as err:
      module.fail_json(msg='Error accessing logical routers. Error [%s]' % (to_native(err)))
    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == edge_profile:
            return result['id']
    module.fail_json(msg="No name exist with that cluster profile name - %s" % edge_profile)


def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(edge_profile=dict(required=True, type= "str"),
                       state=dict(required=True, choices=['present', 'absent']),)
  logger.info("enter into main")            
  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  logical_params = get_logical_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)
  edge_profile = module.params['edge_profile']
  logger.info("going to get details")
  edge_profile_id = get_edge_profile_id(module, manager_url, mgr_username, mgr_password, validate_certs, edge_profile)
  module.exit_json(changed=True, id=edge_profile_id, message="The Profile Id of %s is %s" %(module.params['edge_profile'],edge_profile_id))


if __name__ == '__main__':
    main()
