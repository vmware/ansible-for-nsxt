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
- name: Check Upload Status
    update_check_upload_status:
        hostname: "10.10.10.10"
        username: "admin"
        password: "VMware1!"
        validate_certs: True
        bundle_id: 2400012234332
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
                         bundle_id=dict(required=True, type='int'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    bundle_id = module.params['bundle_id']

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    retry_interval = 10  # Time (in seconds)
    counter = 0
    upload_timeout = 3600  # Time (in seconds) to wait for the upload to finish
    while counter < upload_timeout:
        time.sleep(retry_interval)
        counter += retry_interval
        try:
            (rc, resp) = request(manager_url + '/upgrade/bundles/' + str(bundle_id) + '/upload-status', headers=dict(Accept="application/json"), method='GET',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            if rc == 200:
                if resp["status"] == "SUCCESS":
                    module.exit_json(changed=True, msg="MUB file with bundle id {} uploaded successfully".format(str(bundle_id)))
                elif resp["status"] == "FAILED":
                    module.fail_json(msg="Failed to upload MUB file with id {}".format(str(bundle_id)))
                else:
                    continue
            else:
                module.fail_json(msg="Failed to upload MUB file with id {}".format(str(bundle_id)))
        except Exception as err:
            module.fail_json(msg="Failed to upload MUB file with id {}. Error: {}".format(str(bundle_id), str(err)))

if __name__ == '__main__':
    main()
