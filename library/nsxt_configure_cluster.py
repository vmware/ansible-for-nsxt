#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import json
import time
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''TODO
author: Aleksey Nishev
'''

EXAMPLES = '''
- nsxt_configure_cluster:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      floating_ip: "10.192.167.1"
      master_node: "10.0.0.1"
      state: absent
'''

RETURN = '''# '''


def check_floating_ip(module, manager_url, headers, mgr_username, mgr_password, validate_certs, floating_ip):
    # Retry interval in seconds
    retry_interval = 10
    counter = 0
    # Time (in seconds) to wait for the floating IP to become active
    floating_ip_boot_timeout = 600
    last_error = ""
    while counter < floating_ip_boot_timeout:
        time.sleep(retry_interval)
        counter += retry_interval
        try:
            # REST call to SNX-T server (mgr_hostname) to check is floating IP is set correctly
            (rc, resp) = request(manager_url + '/cluster/api-virtual-ip',
                                 headers=dict(Accept="application/json"),
                                 url_username=mgr_username,
                                 url_password=mgr_password,
                                 validate_certs=validate_certs,
                                 ignore_errors=True)
            if (rc == 200):
                return (resp["ip_address"] == floating_ip, "")
            else:
                last_error = "response code: {}, response {}".format(rc, resp)
                continue
        except Exception as err:
            last_error = err
            continue
    return (False, last_error)


def confugure_floating_ip(manager_url, mgr_username, mgr_password, validate_certs, headers, floating_ip, module, remove_ip=False):
    try:
        if remove_ip:
            url_sufix = "clear_virtual_ip"
            message_1 = "Floating IP {} cleared successfully".format(floating_ip)
            message_2 = "Failed to verify that floating IP {} was cleaned".format(floating_ip)
            message_3 = "Failed cleaning up floating IP {}".format(floating_ip)
            verify_ip = "0.0.0.0"
        else:
            url_sufix = "set_virtual_ip&ip_address=" + floating_ip
            message_1 = "Floating IP set successfully to {}".format(floating_ip)
            message_2 = "Error occured while setting floating IP to {}".format(floating_ip)
            message_3 = "Failed setting up floating IP {}".format(floating_ip)
            verify_ip = floating_ip

        (rc, resp) = request(manager_url + "/cluster/api-virtual-ip?action=" + url_sufix,
                             headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if (rc == 200):
            time.sleep(20)
            (floating_ip_ok, error) = check_floating_ip(module, manager_url, headers, mgr_username, mgr_password, validate_certs, verify_ip)
            if floating_ip_ok:
                module.exit_json(changed=True, msg=message_1)
            else:
                module.fail_json(changed=False, msg="{} Error: {}".format(message_2, error))
        else:
            module.fail_json(changed=False, msg="{} Error: {}".format(message_3, error))
    except Exception as err:
        module.fail_json(changed=False, msg=message_3 + "Error: {}".format(err))


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(floating_ip=dict(required=True, type='str'))
    argument_spec.update(state=dict(required=True, type='str'))
    argument_spec.update(use_floating_ip=dict(required=True, type='bool'))
    argument_spec.update(master_node=dict(required=True, type='bool'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    master_node = module.params['master_node']
    floating_ip = module.params['floating_ip']
    state = module.params['state']
    use_floating_ip = module.params['use_floating_ip']
    validate_certs = module.params['validate_certs']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if not master_node:
        module.exit_json(changed=False, msg="Skipping, not a master node")

    if state == "present":
        if use_floating_ip:
            confugure_floating_ip(manager_url, mgr_username, mgr_password, validate_certs, headers, floating_ip, module)
        else:
            # No floating IP is used by the cluster
            module.exit_json(changed=False, msg="The cluster does not use floating IP")
    elif state == "absent":
        confugure_floating_ip(manager_url, mgr_username, mgr_password, validate_certs, headers, floating_ip, module, remove_ip=True)

if __name__ == '__main__':
    main()
