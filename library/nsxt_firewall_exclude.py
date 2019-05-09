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


ANSIBLE_METADATA = {'metadata_version': 'xx',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: nsxt_firewall_exclude
short_description: Insert 
description:  Creates an NS Group with either static or dynamic membership.
              Reference the API guide for which params can be used with which operations.

version_added: "2.7"
author: Matt Proud
options:
    hostname:
        description: Deployed NSX manager hostname.
        required: true
        type: str
    username:
        description: The username to authenticate with the NSX manager.
        required: true
        type: str
    password:
        description: The password to authenticate with the NSX manager.
        required: true
        type: str
    display_name:
        description: Display name
        required: true
        type: str
    members:
        description: 'List of members. Must conform to NSGroupSimpleExpression schema.'
        required: False
        type: list
        op: 
            choices: ['EQUALS', 'CONTAINS', 'STARTSWITH', 'ENDSWITH', 'NOTEQUALS']
            description: "Operator used to check value against resource type"
            required: True
            type: str
        resource_type: 
            choices: ['NSGroupSimpleExpression']
            description: "Simple property which must be passed with all members"
            required: True
            type: str
        target_property: 
            description: "Object property used to identify. See API guide for details."
            required: True
            type: str
        target_type: 
            choices: ['NSGroup', 'IPSet', 'MACSet', 'LogicalSwitch', 'LogicalPort', 'VirtualMachine', 
                      'DirectoryGroup', 'VirtualNetworkInterface', 'TransportNode']
            description: "Type of target object which is supported"
            required: True
            type: str
        value: 
            description: "Value used to identify member. This can be the unique object ID, which is 'id'
                          for most objects. Virtual machine uses 'external_id'.
                          Module supports looking up object IDs by name, but target_property must still
                          be left as ID."
            required: True
            type: str
    membership_criteria:
        description: 'List of membership criteria. Members must conform to NSGroupTagExpression or 
                      NSGroupComplexExpression schema.'
        required: False
        type: list
        resource_type: 
            choices: ['NSGroupTagExpression', 'NSGroupComplexExpression']
            description: "Simple property which must be passed with all members"
            required: True
            type: str
        target_type: 
            description: "Object property used to identify. See API guide for details."
            required: False
            type: str
        scope:
            description: "Scope of objects to filter for"
            required: False
            type: str
        scope_op:
            description: "Operator to apply to the tag. Defaults to EQUALS. See API guide for options."
            required: False
            type: str
        tag:
            description: "Tag used to filter against"
            required: False
            type: str
        tag_op:
            description: "Operator to apply to the tag. Defaults to EQUALS. See API guide for options."
            required: False
            type: str
        expressions:
            description: "List of expressions. Minimum 2, maximum 5. Use when resource_type is NSGroupComplexExpression"
            required: False
            type: list
            resource_type: 
                choices: ['NSGroupTagExpression']
                description: "Simple property which must be passed with all members"
                required: True
                type: str
            target_type: 
                choices: ['LogicalSwitch', 'LogicalPort', 'VirtualMachine', ]
                description: "Object property used to identify. See API guide for details."
                required: True
                type: str
            scope:
                description: "Scope of objects to filter for"
                required: True
                type: str
            scope_op:
                description: "Operator to apply to the tag. Defaults to EQUALS. See API guide for options."
                required: False
                type: str
            tag:
                description: "Tag used to filter against"
                required: True
                type: str
            tag_op:
                description: "Operator to apply to the tag. Defaults to EQUALS. See API guide for options."
                required: False
                type: str
    resource_type:
        choices: ['NSGroup']
        description: Specifies NSGroup as object type
        required: False
        type: str
    state:
        choices:
        - present
        - absent
        description: "State can be either 'present' or 'absent'. 
                      'present' is used to create or update resource. 
                      'absent' is used to delete resource."
        required: true
'''

EXAMPLES = '''
- name: Add NS Group with membership criteria
  nsxt_firewall_exclude:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: "ns_with_criteria"
    resource_type: NSGroup
    membership_criteria:
      - resource_type: NSGroupTagExpression
        target_type: "LogicalSwitch"
        scope: "S1"
        tag: "T1"
      - resource_type: NSGroupComplexExpression
        expressions:
          - resource_type: NSGroupTagExpression
            target_type: "LogicalPort"
            scope: "S1"
            tag: "T1"
          - resource_type: NSGroupTagExpression
            target_type: "LogicalPort"
            scope: "S2"
            tag: "T2"
    state: "present"


- name: Add NS Group with static members
  nsxt_firewall_exclude:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: "ns_with_criteria"
    resource_type: NSGroup
  members:
    - resource_type: NSGroupSimpleExpression
      target_property: id
      op: EQUALS
      target_type: IPSet
      value: "ips_test1"
    - resource_type: NSGroupSimpleExpression
      target_property: id
      op: EQUALS
      target_type: IPSet
      value: "ips_test2"
    state: "present"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
from collections import Counter


def get_firewall_exclude_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_firewall_excludes(module, manager_url, mgr_username, mgr_password, validate_certs):
        try:
            (rc, resp) = request(manager_url+ '/firewall/excludelist', headers=dict(Accept='application/json'),
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            module.fail_json(msg='Error accessing NS Group. Error [%s]' % (to_native(err)))
        return resp

def get_firewall_exclude_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    firewall_excludes = get_firewall_excludes(module, manager_url, mgr_username, mgr_password, validate_certs)
    return_firewall_exclude = None
    for firewall_exclude in firewall_excludes['results']:
        if firewall_exclude.__contains__('display_name') and firewall_exclude['display_name'] == display_name:
            if not return_firewall_exclude: # Handle there being 2 sections created with the same display name
                return_firewall_exclude = firewall_exclude
            else:
                module.fail_json(msg='Section with display name %s exists more than once.' % (display_name))
    return return_firewall_exclude

def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name, exit_if_not_found=True, id_notation='id'):
        try:
            (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

        for result in resp['results']:
            if result.__contains__('display_name') and result['display_name'] == display_name:
                return result[id_notation]
        if exit_if_not_found:
            module.fail_json(msg='No id exist with display name %s' % display_name)

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, firewall_exclude_params ):
    endpoint_lookup = {'IPSet': '/ip-sets', 'LogicalSwitch': '/logical-switches', 'LogicalPort': '/logical-ports'}
    try:
        if firewall_exclude_params['target_type'] in endpoint_lookup.keys():
            firewall_exclude_params['id'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                        endpoint_lookup[firewall_exclude_params['target_type']], firewall_exclude_params['target_display_name'])
    except KeyError:
        module.fail_json(msg='Type  [%s]. Is not support by the fireall Exclude API' % (firewall_exclude_params['target_type']))
    return firewall_exclude_params


def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, firewall_exclude_params):
    existing_firewall_exclude = get_firewall_exclude_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, 
                                                       firewall_exclude_params['display_name'])
    return True #TODO figure out how to check with the API
    if not existing_firewall_exclude:
        return False
    # Compares the uniqie value for all static members, which is the object ID.
    if firewall_exclude_params['members']:
        if len(firewall_exclude_params['members']) != len(existing_firewall_exclude['members']):
            return True
        existing_members = [d['value'] for d in existing_firewall_exclude['members'] if 'value' in d]
        new_members = [d['value'] for d in firewall_exclude_params['members'] if 'value' in d]
        if not Counter(existing_members) == Counter(new_members):
            return True
    return False

def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(host_credential=dict(required=False, type='dict',
                            username=dict(required=False, type='str'),
                            password=dict(required=False, type='str', no_log=True),
                            thumbprint=dict(required=False, type='str', no_log=True)),
                        target_property=dict(required=True, type='str'),
                        target_type=dict(required=True, type='str', choices=['IPSet', 'LogicalSwitch', 'LogicalPort']),
                        state=dict(required=True, choices=['present', 'absent']))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    
    firewall_exclude_params = get_firewall_exclude_params(module.params.copy())
    
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    if firewall_exclude_params['members'] == ['']:
        firewall_exclude_params['members'] = []
    if firewall_exclude_params['membership_criteria'] == ['']:
        firewall_exclude_params['membership_criteria'] = []

    group_dict = get_firewall_exclude_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
    group_id, revision = None, None
    if group_dict:
        group_id = group_dict['id']
        revision = group_dict['_revision']

    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        body = update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, firewall_exclude_params)
        updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)

        if not updated:
            request_data = json.dumps(firewall_exclude_params)
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(request_data), id='12345')
            try:
                if group_id:
                    module.exit_json(changed=False, id=group_id, message="NS Group with display_name %s already exist."% module.params['display_name'])
                (rc, resp) = request(manager_url+ '/firewall/excludelist', data=request_data, headers=headers, method='POST',
                                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to add node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))
            time.sleep(5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="NS Group with display name %s created succcessfully." % module.params['display_name'])
        else:
            id = group_id
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(firewall_exclude_params)), id=id)

            firewall_exclude_params['_revision'] = revision # update current revision
            request_data = json.dumps(firewall_exclude_params)
            
            try:
                (rc, resp) = request(manager_url+ '/firewall/excludelist/%s' % id, data=request_data, headers=headers, method='POST',
                                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to update node wit id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
            time.sleep(5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="NS Group with node id %s updated." % id)

    elif state == 'absent':
        request_data = json.dumps([]) #TODO generate and insert ID of object to be removed
        # delete the array
        id = group_id
        if id is None:
            module.exit_json(changed=False, msg='No NS Group exist with display name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(firewall_exclude_params)), id=id)
        try:
            (rc, resp) = request(manager_url + "/firewall/excludelist?action=remove_member", data=request_data, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete NS Group with id %s. Error[%s]." % (id, to_native(err)))
        time.sleep(5)
        module.exit_json(changed=True, id=id, message="NG Group with node id %s deleted." % id)


if __name__ == '__main__':
    main()