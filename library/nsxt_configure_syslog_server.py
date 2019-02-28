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


# Currently NSX-T 2.4 REST API does not support managlement of remote syslog server.
# This can be achieved by running the following command on NSX-T Manager:
# nsxcli -c "set logging-server <serverAddress>:<serverPort> proto <protocol> level <level>"

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author: Aleksey Nishev
'''

EXAMPLES = '''
- name: Configure Backup Server
    nsxt_configure_backup_server:
        backup_enabled: True
        seconds_between_backups: 10000
        backup_server: 10.10.10.10
        backup_server_port: 22
        backup_protocol_name: "sftp"
        backup_ssh_fingerprint: "SHA256:w2NgXhG2Nm76q9PL/bXWKkLbDS31uMLYttUe9eajPa"
        backup_username: "backup_usr"
        backup_password: "VMware1!"
        backup_directory_path: "/nsxt-backups"
        backup_passphrase: "VMware1!VMware1!"
        backup_inventory_summary_interval: 300
        hostname: "10.1.1.1"
        username: "admin"
        password: "VMware1!"
        validate_certs: True
        backup_state: present
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(syslog_server=dict(required=True, type='str'),
                         syslog_server_port=dict(required=True, type='int'),
                         syslog_protocol_name=dict(required=True, type='str'),
                         syslog_level=dict(required=True, type='str'),
                         hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str'),
                         password=dict(required=True, type='str'),
                         validate_certs=dict(required=True, type='bool'),
                         syslog_state=dict(required=True, type='str'))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    state = module.params['syslog_state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    syslog_server = module.params['syslog_server']
    syslog_server_port = module.params['syslog_server_port']
    syslog_protocol_name = module.params['syslog_protocol_name']
    syslog_level = module.params['syslog_level']

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    request_data_dict = dict()
    request_data = json.dumps(request_data_dict)

    if state == 'absent':
        # Disable syslog server config
        request_data_dict[""] = ""
    elif state == 'present':
        # Add syslog server configuration
        request_data_dict[""] = ""

    request_data = json.dumps(request_data_dict)

    try:
        (rc, resp) = request(manager_url + '/', data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg="Failed to add syslog configuration. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, result=resp, message="Configuration for syslog server %s created." % module.params['backup_server'])

if __name__ == '__main__':
    main()
