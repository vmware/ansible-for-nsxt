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
- name: Configure Restore Server
    nsxt_configure_restore_server:
        restore_server: 10.10.10.10
        restore_server_port: 22
        restore_protocol_name: "sftp"
        restore_ssh_fingerprint: "SHA256:w2NgXhG2Nm76q9PL/bXWKkLbDS31uMLYttUe9eajPa"
        restore_username: "restore_usr"
        restore_password: "VMware1!"
        restore_directory_path: "/nsxt-restores"
        restore_passphrase: "VMware1!VMware1!"
        hostname: "10.1.1.1"
        username: "admin"
        password: "VMware1!"
        validate_certs: True
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(restore_server=dict(required=True, type='str'),
                         restore_server_port=dict(required=True, type='int'),
                         restore_protocol_name=dict(required=True, type='str'),
                         restore_ssh_fingerprint=dict(required=True, type='str', no_log=True),
                         restore_username=dict(required=True, type='str'),
                         restore_password=dict(required=True, type='str', no_log=True),
                         restore_directory_path=dict(required=True, type='str'),
                         restore_passphrase=dict(required=True, type='str', no_log=True),
                         validate_certs=dict(required=True, type='bool'))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    authentication_scheme = dict()
    authentication_scheme["scheme_name"] = "PASSWORD"
    authentication_scheme["username"] = module.params['restore_username']
    authentication_scheme["password"] = module.params['restore_password']

    protocol = dict()
    protocol["protocol_name"] = module.params['restore_protocol_name']
    protocol["ssh_fingerprint"] = module.params['restore_ssh_fingerprint']
    protocol["authentication_scheme"] = authentication_scheme

    remote_file_server = dict()
    remote_file_server["server"] = module.params['restore_server']
    remote_file_server["port"] = module.params['restore_server_port']
    remote_file_server["protocol"] = protocol
    remote_file_server["directory_path"] = module.params['restore_directory_path']

    request_data_dict = dict()
    request_data_dict["passphrase"] = module.params['restore_passphrase']
    request_data_dict["remote_file_server"] = remote_file_server

    request_data = json.dumps(request_data_dict)

    try:
        (rc, resp) = request(manager_url + '/cluster/restore/config', data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg="Failed to add restore configuration. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, result=resp, message="Configuration for restore server %s created." % module.params['restore_server'])

if __name__ == '__main__':
    main()
