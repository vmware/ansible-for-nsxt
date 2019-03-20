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
author: Aleksey Nishev
'''

EXAMPLES = '''
- name: Upload MUB
  upload_mub:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      url: "https://file-server.com/file.mub"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def get_upload_mub_params(args=None):
    args_to_remove = ['username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value is None:
            args.pop(key, None)
    return args


def get_ip_address(test_string, module):
    node_ip_address = None
    result = test_string.split("The upgrade is allowed only from node ")
    result2 = test_string.split("Upgrade is already in progress on node ")
    if len(result) > 1:
        node_ip_address = result[1].split(", Please visit that node and continue upgrade from that node")[0]
    elif len(result2) > 1:
        node_ip_address = result2[1].split(". Please visit that node and continue upgrade from there.")[0]
    return node_ip_address


def attempt_upload(module, manager_url, mgr_username, mgr_password, validate_certs, request_data, headers, ip_address):
    try:
        (rc, resp) = request(manager_url + '/upgrade/bundles', data=request_data, headers=headers, method='POST',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            module.exit_json(changed=True, ip_address=ip_address, response=resp, message="The MUB file %s is being uploaded." % module.params['url'])
        else:
            module.fail_json(msg="Failed to run upload MUB REST call. response code: {} response: {}".format(rc, resp))
    except Exception as err:
        error_message = str(err[1]["error_message"])
        node_ip_address = get_ip_address(error_message, module)
        if node_ip_address:
            return node_ip_address
        else:
            module.fail_json(changed=True, msg="Error: {}".format(err))


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(url=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    upgrade_params = get_upload_mub_params(module.params.copy())

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    request_data = json.dumps(upgrade_params)
    node_ip_address = None
    node_ip_address = attempt_upload(module, manager_url, mgr_username, mgr_password, validate_certs, request_data, headers, mgr_hostname)
    update_node_url = 'https://{}/api/v1'.format(node_ip_address)
    attempt_upload(module, update_node_url, mgr_username, mgr_password, validate_certs, request_data, headers, node_ip_address)

if __name__ == '__main__':
    main()
