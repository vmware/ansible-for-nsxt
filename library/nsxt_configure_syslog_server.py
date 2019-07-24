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
    nsxt_configure_syslog_server:
        syslog_server: "{{syslog_server}}"
        syslog_server_port: "{{syslog_server_port}}"
        syslog_protocol: "{{syslog_protocol}}"
        syslog_level: "{{syslog_level}}"
        exporter_name: "{{exporter_name}}"
        facilities: "{{facilities}}"
        msgids: "{{msgids}}"
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        syslog_state: absent
    with_items:
    - "{{syslog_servers}}"
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
                         syslog_protocol=dict(required=True, type='str'),
                         syslog_level=dict(required=True, type='str'),
                         exporter_name=dict(required=True, type='str'),
                         facilities=dict(required=True, type='list'),
                         msgids=dict(required=True, type='list'),
                         hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str'),
                         password=dict(required=True, type='str', no_log=True),
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
    syslog_protocol = module.params['syslog_protocol']
    syslog_level = module.params['syslog_level']
    exporter_name = module.params['exporter_name']
    facilities = module.params['facilities']
    msgids = module.params['msgids']

    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if state == 'present':
        # Disable syslog server config
        request_data_dict = dict()
        request_data_dict["exporter_name"] = exporter_name
        request_data_dict["facilities"] = facilities
        request_data_dict["level"] = syslog_level
        request_data_dict["msgids"] = msgids
        request_data_dict["port"] = syslog_server_port
        request_data_dict["protocol"] = syslog_protocol
        request_data_dict["server"] = syslog_server
        request_data = json.dumps(request_data_dict)
        method = "POST"
        exporter_name_url = ""
    elif state == 'absent':
        # Add syslog server configuration
        method = "DELETE"
        exporter_name_url = "/" + exporter_name
        request_data = ""

    url = manager_url + '/node/services/syslog/exporters' + exporter_name_url
    try:
        (rc, resp) = request(url, data=request_data, headers=headers, method=method,
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 201:
            module.exit_json(changed=True, message="Successfully added syslog server configuration")
        elif rc == 200:
            module.exit_json(changed=True, message="Successfully removed syslog server configuration for exporter named: {}".format(exporter_name))
        else:
            module.fail_json(msg="Failed to add syslog server configuration. Response code {}".format(rc))
    except Exception as err:
        message = "Specified syslog exporter '" + module.params['exporter_name'] + "' already exists."
        if err[1]["error_message"] == message:
            module.exit_json(changed=False, message=message)
        else:
            module.fail_json(msg="Failed to add syslog configuration. Request body {}. Error: {}".format(request_data, err))

if __name__ == '__main__':
    main()
