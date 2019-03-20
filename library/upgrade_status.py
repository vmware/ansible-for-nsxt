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
- name: Upgrade Status
    upgrade_status:
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        component_type: "MP"
'''

RETURN = '''# '''

import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(validate_certs=dict(required=True, type='bool'),
                         component_type=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    component_type = module.params['component_type']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    retry_interval = 10  # Time (in seconds)
    counter = 0
    uc_upgrade_timeout = 7200  # Time (in seconds) to wait for the upgrade to finish
    error_message = None
    while counter < uc_upgrade_timeout:
        time.sleep(retry_interval)
        counter += retry_interval
        try:
            (rc, resp) = request(manager_url + '/upgrade/status-summary?component_type=' + component_type, headers=dict(Accept="application/json"), method='GET',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            if rc == 200:
                if resp["component_status"][0]["status"] == "SUCCESS":
                    module.exit_json(changed=True, msg="Component {} upgraded successfully".format(component_type))
                elif resp["component_status"][0]["status"] == "PAUSED":
                    module.exit_json(changed=False, msg="The current update task has finished successfully and it is paused now. Please prepare to run the next task and start it again")
                elif resp["component_status"][0]["status"] == "FAILED":
                    module.fail_json(changed=False, msg="Failed to upgrade all components. Please check Upgrade Status for more details")
                elif resp["component_status"][0]["status"] == "NOT_STARTED":
                    module.fail_json(msg="Upgrade process for component {} has not started".format(component_type))
                else:
                    continue
            else:
                module.fail_json(msg="Failed to upgrade component {}. Response code: {}, response: {}".format(component_type, rc, resp))
        except Exception as err:
            error_message = err
            continue
    else:
        module.fail_json(msg="Exception occured during REST call to get component {} status. Error: {}".format(component_type, error_message))


if __name__ == '__main__':
    main()
