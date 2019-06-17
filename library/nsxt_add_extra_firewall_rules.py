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
    - name: Add Default Extra Firewall Rules
      nsxt_add_extra_firewall_rules:
          hostname: "10.10.10.10"
          username: "admin"
          password: "VMware1!"
          validate_certs: True
          destination_ip: 169.254.169.254
          state: present
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def section_with_name_exists(section_name, manager_url, mgr_username, mgr_password, headers, validate_certs, module):
    try:
        (rc, resp) = request(manager_url + '/firewall/sections', headers=headers, method='GET',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            sections = resp["results"]
            for section in sections:
                if section["display_name"] == section_name:
                    return True
                else:
                    return False
        else:
            return False
    except Exception as err:
        module.fail_json(msg="Failed to get firewall sections. Error[%s]." % (to_native(err)))


def get_service_ids(service_names, manager_url, mgr_username, mgr_password, headers, validate_certs, module):
    try:
        (rc, resp) = request(manager_url + '/ns-services?default_service=true', headers=headers, method='GET',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 200:
            service_ids = dict()
            services = resp["results"]
            for service in services:
                for service_name in service_names:
                    if service["display_name"] == service_name:
                        service_ids[service_name] = service["id"]
            return service_ids
        else:
            return None
    except Exception as err:
        module.fail_json(msg="Failed to get service ID. Error[%s]." % (to_native(err)))


def create_payload(destination_ip, service_ids, section_name):
    destinations = []
    destination = dict()
    destination["target_display_name"] = destination_ip
    destination["is_valid"] = True
    destination["target_type"] = "IPv4Address"
    destination["target_id"] = destination_ip
    destinations.append(destination)

    services1 = []
    service1 = dict()
    service1["target_id"] = service_ids["HTTP"]
    service1["target_display_name"] = "HTTP"
    service1["target_type"] = "NSService"
    service1["is_valid"] = True
    services1.append(service1)

    rules = []
    rule1 = dict()
    rule1["display_name"] = "Allow HTTP"
    rule1["action"] = "ALLOW"
    rule1["direction"] = "IN_OUT"
    rule1["destinations"] = destinations
    rule1["services"] = services1

    services2 = []

    service2_1 = dict()
    service2_1["target_id"] = service_ids["DHCP-Client"]
    service2_1["target_display_name"] = "DHCP-Client"
    service2_1["target_type"] = "NSService"
    service2_1["is_valid"] = True
    services2.append(service2_1)

    service2_2 = dict()
    service2_2["target_id"] = service_ids["DHCP-Server"]
    service2_2["target_display_name"] = "DHCP-Server"
    service2_2["target_type"] = "NSService"
    service2_2["is_valid"] = True
    services2.append(service2_2)

    rule2 = dict()
    rule2["display_name"] = "Allow DHCP"
    rule2["action"] = "ALLOW"
    rule2["direction"] = "IN_OUT"
    rule2["destinations"] = destinations
    rule2["services"] = services2

    rules.append(rule1)
    rules.append(rule2)

    payload = dict()
    payload["section_type"] = "LAYER3"
    payload["display_name"] = section_name
    payload["stateful"] = True
    payload["rules"] = rules

    return payload


def main():
    argument_spec = vmware_argument_spec()

    argument_spec.update(validate_certs=dict(required=True, type='bool'),
                         state=dict(required=True, type='str'),
                         destination_ip=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    destination_ip = module.params['destination_ip']
    section_name = "Allow DHCP and Metadata"

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    default_section_name = "Default Layer3 Section"
    service_names = ["HTTP", "DHCP-Client", "DHCP-Server"]


    result = section_with_name_exists(section_name, manager_url, mgr_username, mgr_password, headers, validate_certs, module)
    if result == False:
        service_ids = get_service_ids(service_names, manager_url, mgr_username, mgr_password, headers, validate_certs, module)
        payload = create_payload(destination_ip, service_ids, section_name)
        request_data = json.dumps(payload)
        try:
            (rc, resp) = request(manager_url + '/firewall/sections?action=create_with_rules', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            if rc == 201:
                module.exit_json(changed=True, msg="Successfully added extra firewall rules")
            else:
                module.fail_json(changed=False, msg="Failed to add extra firewall rules. Response code: {}".format(rc))
        except Exception as err:
            module.fail_json(msg="Failed to add extra firewall rules. Error: {}".format(to_native(err)))
    else:
        module.exit_json(changed=False, msg="A firewall section named '{}' already exists".format(section_name))

if __name__ == '__main__':
    main()
