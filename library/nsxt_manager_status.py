#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''TODO
author: Rahul Raghuvanshi
'''

EXAMPLES = '''
- nsxt_manager_status:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      wait_time: 50
'''

RETURN = '''# '''
import json, time
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(wait_time=dict(required=False, type='int'))
  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  changed = False
  wait_time = 10 # wait till 30 min
  while wait_time < (module.params['wait_time'] *60):
      try:
        current_time = datetime.now()
        (rc, resp) = request(manager_url+ '/cluster/nodes/deployments', headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        module.exit_json(changed=changed, msg= " NSX manager is UP")
      except Exception as err:
        time_diff = datetime.now() - current_time
        time.sleep(10)
        wait_time = time_diff.seconds + wait_time + 10
  module.fail_json(changed=changed, msg= " Error accessing nsx manager. Timeed out")

if __name__ == '__main__':
	main()
