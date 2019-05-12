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
---
module: nsxt_services
short_description: 'Create a Service'
description: "Creates a new Service. Required parameters are display_name,
              ports and state. Display_name is required to make module idempotent"
version_added: '2.7'
author: 'Matt Proud'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: str
    display_name:
        description: 'Display name'
        required: true
        type: str
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true
    nsservice_element:
        description: "####"
        required: false
        type: 'dict'
    tags:
        description: 'Opaque identifiers meaningful to the API user'
        required: false
        type: str

    
'''

EXAMPLES = '''
- name: Create ip set
  nsxt_services:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: IPset-IPV4-1
    ip_addresses:
    - "10.112.201.28"
    - "10.112.201.64/26"
    state: "present"
'''

RETURN = '''# '''


import json, time, copy
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_service_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_services(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
        (rc, resp) = request(manager_url+ '/ns-services', headers=dict(Accept='application/json'),
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing services. Error [%s]' % (to_native(err)))
    return resp

def get_service_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    services = get_services(module, manager_url, mgr_username, mgr_password, validate_certs)
    return_service = None
    for service in services['results']:
        if service.__contains__('display_name') and service['display_name'] == display_name:
            if not return_service: # Handle there being 2 sections created with the same display name
                return_service = service
            else:
                module.fail_json(msg='Section with display name %s exists twice.' % (display_name))
    return return_service

def flatten_child_list_to_string(nsservice_element):
    for list_type in ['sourse_ports', 'destination_ports']:
        if nsservice_element.__contains__(list_type):
            ports_string = ''
            for port in sorted(nsservice_element[list_type]):
                ports_string += str(port) + ','
            nsservice_element[list_type] = ports_string


def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, service_params):
    existing_service = get_service_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, service_params['display_name'])
    if existing_service is None:
        return False

    # service_params must be deep copied otherwise pop removes globally.
    copy_service_params = copy.deepcopy(service_params)
    copy_nsservice_element = copy_service_params.pop('nsservice_element', [])
    existing_nsservice_element = existing_service.pop('nsservice_element', None)

    # Flatten list of ports for ALGTypeNSService and L4PortSetNSService so that can be easily compared
    flatten_child_list_to_string(copy_nsservice_element)
    flatten_child_list_to_string(existing_nsservice_element)

    #TODO add support for tags
    # Check to ensure that all keys and values in the base of the params match the existing configuration.
    if not all(k in existing_service and copy_service_params[k] == existing_service[k] for k in copy_service_params):
        #module.fail_json(msg="Lazy old 1 [%s]  ########## New[%s]." % (existing_service, copy_service_params))
        return True
    
    # Check to ensure that all keys and values nsservice_element match the existing configration.
    if not all(k in existing_nsservice_element and copy_nsservice_element[k] == existing_nsservice_element[k] for k in copy_nsservice_element):
        return True
    
    return False

def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'),
                            description=dict(required=False, type='str'),
                            nsservice_element=dict(required=True, type='dict',
                                alg=dict(required=False, type='str', choices=['ORACLE_TNS', 'FTP', 'SUN_RPC_TCP', 
                                                                            'SUN_RPC_UDP', 'MS_RPC_TCP', 'MS_RPC_UDP', 
                                                                            'NBNS_BROADCAST', 'NBDG_BROADCAST', 'TFTP']),
                                destination_ports=dict(required=False, type='list'),
                                icmp_code=dict(required=False, type='int'),
                                icmp_type=dict(required=False, type='int'),
                                l4_protocol=dict(required=False, type='str'),
                                protocol=dict(required=False, type='str', choices=['ICMPv4', 'ICMPv6']),
                                protocol_number=dict(required=False, type='int'),
                                resource_type=dict(required=True, type='str', 
                                                    choices=['ALGTypeNSService', 'IPProtocolNSService', 
                                                            'L4PortSetNSService', 'ICMPTypeNSService', 'IGMPTypeNSService']),
                                source_ports=dict(required=False, type='list')),
                            resource_type=dict(required=False, type='str', default='NSService'),
                            state=dict(required=True, choices=['present', 'absent']),
                            tags=dict(required=False, type='str'))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    service_params = get_service_params(module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    service_dict = get_service_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
    service_id, revision = None, None
    if service_dict:
        service_id = service_dict['id']
        revision = service_dict['_revision']

    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, service_params)

        if not updated:
            # add the set
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(service_params)), id='12345')
            request_data = json.dumps(service_params)
            try:
                if service_id:
                    module.exit_json(changed=False, id=service_id, message="Service with display_name %s already exist."% module.params['display_name'])
                (rc, resp) = request(manager_url+ '/ns-services', data=request_data, headers=headers, method='POST',
                                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to add service. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

            time.sleep(0.5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Service with display name %s created." % module.params['display_name'])
        else:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(service_params)), id=service_id)
            service_params['_revision']=revision # update current revision
            request_data = json.dumps(service_params)
            id = service_id
            try:
                (rc, resp) = request(manager_url+ '/ns-services/%s' % id, data=request_data, headers=headers, method='PUT',
                                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to update service with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
            time.sleep(0.5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Service with id %s updated." % id)

    elif state == 'absent':
        # delete the array
        id = service_id
        if id is None:
            module.exit_json(changed=False, msg='No service exist with display name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(service_params)), id=id)
        try:
            (rc, resp) = request(manager_url + "/ns-services/%s" % id, method='DELETE',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete service with id %s. Error[%s]." % (id, to_native(err)))

        time.sleep(5)
        module.exit_json(changed=True, object_name=id, message="Service with id %s deleted." % id)


if __name__ == '__main__':
    main()
