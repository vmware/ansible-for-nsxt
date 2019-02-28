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
author: Ramesh Chandra
'''

EXAMPLES = '''
- nsxt_manager_status:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      service_boot_timeout: 50
'''

RETURN = '''# '''
import time
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def get_service_boot_timeout(service_boot_timeout, current_time, polling_interval):
    time_diff = datetime.now() - current_time
    time.sleep(polling_interval)
    return time_diff.seconds + service_boot_timeout + polling_interval


def is_nsxt_manager_alive(manager_url, mgr_username, mgr_password, validate_certs, headers, module):
    # Polling interval in seconds
    polling_interval = 60
    service_boot_timeout = 0
    while service_boot_timeout <= (module.params['service_boot_timeout'] * 60):
        try:
            current_time = datetime.now()
            (rc, resp) = request(manager_url + '/cluster/status', headers=dict(Accept='application/json'),
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
            if (rc == 200):
                cluster_id = resp.get("cluster_id")
                if cluster_id:
                    return True
                else:
                    service_boot_timeout = get_service_boot_timeout(service_boot_timeout, current_time, polling_interval)
        except Exception:
            service_boot_timeout = get_service_boot_timeout(service_boot_timeout, current_time, polling_interval)
    return False


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(service_boot_timeout=dict(required=True, type='int'), ip_address=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_ip_address = module.params['ip_address']
    mgr_hostname = module.params['hostname'] 
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    headers = dict(Accept='application/json')

    manager_url = 'https://{}/api/v1'.format(mgr_ip_address)

    if is_nsxt_manager_alive(manager_url, mgr_username, mgr_password, validate_certs, headers, module):
        module.exit_json(changed=False, msg="The NSX-T manager {} is up and running".format(mgr_hostname))
    else:
        module.fail_json(msg="Failed to verify that NSX-T manager {} is up and running".format(mgr_hostname))

if __name__ == '__main__':
    main()
