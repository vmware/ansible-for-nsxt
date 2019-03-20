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
- name: Set Upgrade Plan
    set_upgrade_plan:
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
'''

RETURN = '''# '''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(validate_certs=dict(required=True, type='bool'),
                         component_type=dict(required=True, type='str'),
                         display_name=dict(required=True, type='str'),
                         parallel=dict(required=True, type='str'),
                         upgrade_units=dict(required=True, type='list'),
                         esx_list=dict(required=True, type='list'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    component_type = module.params['component_type']
    upgrade_units = module.params['upgrade_units']
    display_name = module.params['display_name']
    parallel = module.params['parallel']

    combined_upgrade_units = list()
    for group in upgrade_units:
        combined_upgrade_units = combined_upgrade_units + group["upgrade_units"]

    esx_list = module.params['esx_list']
    esx_ids = list()
    for esx_node in esx_list:
        id = next((x["id"] for x in combined_upgrade_units if x["display_name"] == esx_node), None)
        esx_ids.append(dict(id=id))

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    request_data_dict = dict()
    request_data_dict["display_name"] = display_name
    request_data_dict["type"] = component_type
    request_data_dict["parallel"] = parallel
    request_data_dict["enabled"] = "true"
    request_data_dict["upgrade_units"] = esx_ids
    extended_configuration = dict()
    extended_configuration["key"] = "upgrade_mode"
    extended_configuration["value"] = "in_place"
    request_data_dict["extended_configuration"] = list()
    request_data_dict["extended_configuration"].append(extended_configuration)
    request_data = json.dumps(request_data_dict)

    try:
        (rc, resp) = request(manager_url + '/upgrade/upgrade-unit-groups', data=request_data, headers=headers, method='POST',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 201:
            module.exit_json(changed=True, msg="Successfully set the ugrade plan. Response: {}".format(resp))
        else:
            module.fail_json(msg="Failed to set the ugrade plan. Response code: {}, response content: {}".format(rc, resp))
    except Exception as err:
        module.fail_json(msg="Exception occured during REST call to set the ugrade plan. Error: {}".format(to_native(err)))

if __name__ == '__main__':
    main()
