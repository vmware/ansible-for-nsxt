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

DOCUMENTATION = '''
author: Aleksey Nishev
'''

EXAMPLES = '''
    - name: Remove Maximum Authentication Failures Limit 
      nsxt_remove_max_auth_failures_limit:
          hostname: "10.10.10.10"
          username: "admin"
          password: "VMware1!"
          validate_certs: True
          state: present
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(validate_certs=dict(required=True, type='bool'),
                         state=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    request_data_dict = dict()
    request_data_dict["api_max_auth_failures"] = 0
    request_data = json.dumps(request_data_dict)
    try:
        (rc, resp) = request(manager_url + '/node/aaa/auth-policy', data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200 or rc == 202:
            module.exit_json(changed=True, msg="Successfully removed max password auth failure limit")
        else:
            module.fail_json(msg="Failed to remove max password auth failure limit")
    except Exception as err:
        module.fail_json(msg="Failed to remove max password auth failure limit. Error: {}".format(to_native(err)))

if __name__ == '__main__':
    main()
