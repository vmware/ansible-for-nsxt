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
- name: Configure vIDM Server
    nsxt_configure_vidm_server:
        vidm_enabled: True
        lb_enabled: True
        vidm_server: "vidm2.corp.local"
        vidm_thumbprint: "A8294342A2C70FC5E4267F8D994FEAAC4EE2BC731E9BB8B18D913D5486D3CC30"
        vidm_client_id: "place_vidm_client_id_here"
        vidm_client_secret: "place_vidm_client_secret_here"
        validate_certs: "{{validate_certs}}"
        state: present
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def get_api_cert_thumbprint(ip_address, module):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((ip_address, 443))
    except Exception as err:
        module.fail_json(msg='Failed to get node ID from ESXi host with IP {}. Error: {}'.format(ip_address, err))
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        return thumb_sha256
    finally:
        wrappedSocket.close()

def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(vidm_enabled=dict(required=True, type='bool'),
                         lb_enabled=dict(required=True, type='bool'),
                         vidm_server=dict(required=True, type='str'),
                         vidm_thumbprint=dict(required=True, type='str'),
                         vidm_client_id=dict(required=True, type='str'),
                         vidm_client_secret=dict(required=True, type='str', no_log=True),
                         validate_certs=dict(required=True, type='bool'),
                         state=dict(reauired=True, choices=['present', 'absent']))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    state = module.params['state']


    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    action = ""
    if state == 'present':
        action = "created"
        vidm_enabled = module.params['vidm_enabled']
        lb_enabled = module.params['lb_enabled']
        vidm_server = module.params['vidm_server']
        vidm_thumbprint = module.params['vidm_thumbprint']
        vidm_client_id = module.params['vidm_client_id']
        vidm_client_secret = module.params['vidm_client_secret']
        if not vidm_thumbprint:
            vidm_thumbprint = get_api_cert_thumbprint(vidm_server, module)
    elif state == 'absent':
        action = "removed"
        vidm_enabled = False
        lb_enabled = False
        vidm_server = ""
        vidm_thumbprint = ""
        vidm_client_id = ""
        vidm_client_secret = ""

    request_data_dict = dict()
    request_data_dict["lb_enable"] = lb_enabled
    request_data_dict["vidm_enable"] = vidm_enabled
    request_data_dict["host_name"] = vidm_server
    request_data_dict["thumbprint"] = vidm_thumbprint
    request_data_dict["client_id"] = vidm_client_id
    request_data_dict["client_secret"] = vidm_client_secret
    request_data_dict["node_host_name"] = mgr_hostname
    request_data = json.dumps(request_data_dict)

    try:
        (rc, resp) = request(manager_url + '/node/aaa/providers/vidm', data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if rc == 202 or rc == 200:
            module.exit_json(changed=True, result=resp, message="Configuration for vIDM server was successfully {}".format(action))
        else:
            module.fail_json(msg="Failed to add vIDM server configuration. Response code: {}. Response body {}".format(rc, resp))
    except Exception as err:
        module.fail_json(msg="Failed to add vIDM configuration. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

if __name__ == '__main__':
    main()
