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
module: nsxt_ns_groups
short_description: Create and update NS Groups
description:  Creates an NS Group with either static or dynamic memeber.
              
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

        ## NSGroupTagExpression required options
        resource_type: 
            choices: ['NSGroupTagExpression']
            description: "Simple property which must be passed with all members"
            required: True
            type: str
        target_type: 
            description: "Object property used to identify. See API guide for details."
            required: True
            type: str
        scope:
            description: "Scope of objects to filter for"
            required: True
            type: str
        tag:
            description: "Tag used to filter against"
            required: True
            type: str
        
        ## NSGroupComplexExpression required options
        resource_type: 
            choices: ['NSGroupComplexExpression']
            description: "Simple property which must be passed with all members"
            required: True
            type: str
        expressions:
            description: "Simple property which must be passed with all members"
            required: True
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
                
    display_name:
        description: Display name
        required: true
        type: str

    resource_type:
        choices:
        - NSGroup
        description: Specifies NSGroup as object type
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
'''

EXAMPLES = '''
- name: Add NS Group with membership criteria
  nsxt_ns_group:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: 'ns_with_criteria'
    resource_type: NSGroup
    membership_criteria:
      - resource_type: NSGroupTagExpression
        target_type: 'LogicalSwitch'
        scope: 'S1'
        tag: 'T1'
      - resource_type: NSGroupComplexExpression
        expressions:
          - resource_type: NSGroupTagExpression
            target_type: 'LogicalPort'
            scope: 'S1'
            tag: 'T1'
          - resource_type: NSGroupTagExpression
            target_type: 'LogicalPort'
            scope: 'S2'
            tag: 'T2'
    state: "present"


- name: Add NS Group with static members
  nsxt_ns_group:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: 'ns_with_criteria'
    resource_type: NSGroup
  members:
    - resource_type: NSGroupSimpleExpression
      target_property: id
      op: EQUALS
      target_type: IPSet
      value: 'ips_test1'
    - resource_type: NSGroupSimpleExpression
      target_property: id
      op: EQUALS
      target_type: IPSet
      value: 'ips_test2'
    state: "present"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
from collections import Counter

try:
    from __main__ import display
except ImportError:
    # pylint: disable=ungrouped-imports; this is the standard way how to import
    # the default display object in Ansible action plugins.
    from ansible.utils.display import Display
    display = Display()

def get_ns_group_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_ns_groups(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/ns-groups', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing NS Group. Error [%s]' % (to_native(err)))
    return resp

def get_ns_group_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    ns_groups = get_ns_groups(module, manager_url, mgr_username, mgr_password, validate_certs)
    for ns_group in ns_groups['results']:
        if ns_group.__contains__('display_name') and ns_group['display_name'] == display_name:
            return ns_group
    return None

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

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, ns_group_params ):
    endpoint_lookup = {'NSGroup': '/ns-groups', 'IPSet': '/ip-sets', 'MACSet': '/mac-sets', 'LogicalSwitch': '/logical-switches', 
                          'LogicalPort': '/logical-ports', 'VirtualMachine': '/fabric/virtual-machines', 'TransportNode': '/transport-nodes'}
    if ns_group_params['members']:
        for counter, member in enumerate(ns_group_params['members']):
          if member['target_type'] in endpoint_lookup.keys() and (member['target_property'] == 'id' or member['target_property'] == 'external_id'):
            value = ns_group_params['members'][counter].pop('value', None)
            if member['target_property'] == 'id':
              ns_group_params['members'][counter]['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                          endpoint_lookup[member['target_type']], value)
            elif member['target_property'] == 'external_id':
              ns_group_params['members'][counter]['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                          endpoint_lookup[member['target_type']], value, True, 'external_id')
    return ns_group_params

def add_equals_operator_if_missing(dict_to_check):
    addition_string = ''
    if not dict_to_check.__contains__('tag_op'):
        addition_string += 'EQUALS'
    if not dict_to_check.__contains__('scope_op'):
        addition_string += 'EQUALS'
    return addition_string if addition_string <> '' else ''

# All values are extracted for each membership_criteria and a sorted string is built. 
def extract_membership_criteria_list(membership_criteria_list):
    output_list = []
    for membership_criteria in membership_criteria_list:
        if membership_criteria['resource_type'] == 'NSGroupComplexExpression':
            for expression in membership_criteria['expressions']:
                item_string = add_equals_operator_if_missing(expression)
                for value in expression.values():
                    item_string += value
                output_list.append(''.join(sorted(item_string)))
        elif membership_criteria['resource_type'] == 'NSGroupTagExpression':
            item_string = add_equals_operator_if_missing(membership_criteria)
            for value in membership_criteria.values():
                item_string += value
            output_list.append(''.join(sorted(item_string)))
    return output_list

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, ns_group_params):
    existing_ns_group = get_ns_group_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, 
                                                       ns_group_params['display_name'])
    if existing_ns_group is None:
        return False
    # Compares the uniqie value for all static members, which is the object ID.
    if ns_group_params['members'] and len(ns_group_params['members']) == len(existing_ns_group['members']):
        existing_members = [d['value'] for d in existing_ns_group['members'] if 'value' in d]
        new_members = [d['value'] for d in ns_group_params['members'] if 'value' in d]
        if not Counter(existing_members) == Counter(new_members):
            return True
    # Membership criterial has no unique keys, so all values need to be compared. Lists are generated with sorted strings.
    if ns_group_params['membership_criteria'] and len(ns_group_params['membership_criteria']) == len(existing_ns_group['membership_criteria']):
        existings_membership_criteria_list = extract_membership_criteria_list(existing_ns_group['membership_criteria'])
        new_membership_criteria_list = extract_membership_criteria_list(ns_group_params['membership_criteria'])
        if not Counter(existings_membership_criteria_list) == Counter(new_membership_criteria_list):
            return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                    host_credential=dict(required=False, type='dict',
                        username=dict(required=False, type='str'),
                        password=dict(required=False, type='str', no_log=True),
                        thumbprint=dict(required=False, type='str', no_log=True)),
                    members=dict(required=False, type='list', 
                        op=dict(required=True, type='str', choices=['EQUALS', 'CONTAINS', 'STARTSWITH', 'ENDSWITH', 'NOTEQUALS']),
                        resource_type=dict(required=True, type='str', choices=['NSGroupSimpleExpression']),
                        target_property=dict(required=True, type='str'),
                        target_type=dict(required=True, type='str', choices=['NSGroup', 'IPSet', 'MACSet', 'LogicalSwitch', 'LogicalPort', 
                                                                              'VirtualMachine', 'DirectoryGroup', 'VirtualNetworkInterface', 'TransportNode']),
                        value=dict(required=True, type='str', choices=['NSGroupSimpleExpression'])
                            ),
                    membership_criteria=dict(required=False, type='list'),

                    resource_type=dict(required=True, type='str', choices=['NSGroup']),
                    state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  
  ns_group_params = get_ns_group_params(module.params.copy())
  
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  if ns_group_params['members'] == ['']:
    ns_group_params['members'] = []
  if ns_group_params['membership_criteria'] == ['']:
    ns_group_params['membership_criteria'] = []

  node_dict = get_ns_group_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  node_id, revision = None, None
  if node_dict:
    node_id = node_dict['id']
    revision = node_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    body = update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, ns_group_params)
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)

    if not updated:
      request_data = json.dumps(ns_group_params)
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(request_data), id='12345')
      try:
          if node_id:
              module.exit_json(changed=False, id=node_id, message="NS Group with display_name %s already exist."% module.params['display_name'])
          (rc, resp) = request(manager_url+ '/ns-groups', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
                module.fail_json(msg="Failed to add node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="NS Group with display name %s created succcessfully." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(ns_group_params)), id=id)

      ns_group_params['_revision'] = revision # update current revision
      request_data = json.dumps(ns_group_params)
      id = node_id
      try:
          (rc, resp) = request(manager_url+ '/ns-groups/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update node wit id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
      module.exit_json(changed=True, id=resp["id"], body= str(resp), message="NS Group with node id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = node_id
    if id is None:
        module.exit_json(changed=False, msg='No NS Group exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(ns_group_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/ns-groups/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete NS Group with id %s. Error[%s]." % (id, to_native(err)))

    module.exit_json(changed=True, id=id, message="NG Group with node id %s deleted." % id)


if __name__ == '__main__':
    main()
