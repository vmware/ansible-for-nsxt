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
- name: UC Upgrade Status
    uc_upgrade_status:
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
'''

RETURN = '''# '''

import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(validate_certs=dict(required=True, type='bool'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    retry_interval = 10  # Time (in seconds)
    counter = 0
    uc_upgrade_timeout = 3600  # Time (in seconds) to wait for the UC upgrade to finish
    error = None
    while counter < uc_upgrade_timeout:
        time.sleep(retry_interval)
        counter += retry_interval
        try:
            (rc, resp) = request(manager_url + '/upgrade/uc-upgrade-status', headers=dict(Accept="application/json"), method='GET',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            if rc == 200:
                if resp["status"] == "Upgrade-coordinator has been upgraded":
                    module.exit_json(changed=True, msg="UC upgrade process finished successfully")
                elif resp["status"] == "FAILED": # TODO verify if this is the right string
                    module.fail_json(msg="Failed to upgrade UC")
                else:
                    continue
            else:
                module.fail_json(msg="Failed to get UC upgrade status. Response code: {}, response: {}".format(rc, resp))
        except Exception as err:
            error = err
            continue
    else:
        module.fail_json(msg="Exception occured during REST call to get UC upgrade status. {}".format(error))


if __name__ == '__main__':
    main()
