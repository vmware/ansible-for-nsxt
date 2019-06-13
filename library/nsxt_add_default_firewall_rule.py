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
    - name: Add Default Firewall Rule
      nsxt_add_default_firewall_rule:
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


def get_section_id(default_section_name, manager_url, mgr_username, mgr_password, headers, validate_certs, module):
    try:
        (rc, resp) = request(manager_url + '/firewall/sections', headers=headers, method='GET',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            sections = resp["results"]
            for section in sections:
                if section["display_name"] == default_section_name:
                    return section["id"]
            return None
        else:
            return None
    except Exception as err:
        module.fail_json(msg="Failed to get section ID. Error[%s]." % (to_native(err)))


def get_rule_preoperties(section_id, rule_name, manager_url, mgr_username, mgr_password, headers, validate_certs, module):
    try:
        (rc, resp) = request(manager_url + '/firewall/sections/' + section_id + '/rules', headers=headers, method='GET',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            rules = resp["results"]
            for rule in rules:
                if rule["display_name"] == rule_name:
                    return (rule["id"], rule["_revision"])
            return None
        else:
            return None
    except Exception as err:
        module.fail_json(msg="Failed to get rule revision. Error[%s]." % (to_native(err)))


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
    default_section_name = "Default Layer3 Section"

    section_id = get_section_id(default_section_name, manager_url, mgr_username, mgr_password, headers, validate_certs, module)
    (rule_id, rule_revision) = get_rule_preoperties(section_id, "Default Layer3 Rule", manager_url, mgr_username, mgr_password, headers, validate_certs, module)
    request_data_dict = dict()

    if state == "present":
        # Change default section's rule action to DROP
        action = "DROP"
    elif state == "absent":
        # Change default section's rule action to ALLOW
        action = "ALLOW"

    request_data_dict["action"] = action
    request_data_dict["display_name"] = "Default Layer3 Rule"
    request_data_dict["_revision"] = rule_revision
    request_data = json.dumps(request_data_dict)
    try:
        (rc, resp) = request(manager_url + '/firewall/sections/' + section_id + '/rules/' + rule_id, data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            module.exit_json(changed=True, msg="Successfully changed the default section's rule to {}".format(action))
        else:
            module.fail_json(msg="Failed to change the default section's rule to {}. Response code: {}, response content: {}".format(action, rc, resp))
    except Exception as err:
        module.fail_json(msg="Failed to change the default section's rule to {} Error{}.".format(action, to_native(err)))

if __name__ == '__main__':
    main()
