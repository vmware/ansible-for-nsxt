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
module: nsxt_dfw_sections
short_description: 
description:  Creates an Distributed Firewall Section with along with rules.
              This is intended for use with GitOps workflows, where the configuration is stored in Git and the
              playbook run after a change has been made.
              This module is designed to be run with relatively small firewall sections. Large firewall sections
              can cause issues with API performance and the API guide states supported rule section size and 
              maximum levels of concurrency
              If section params or any rule params are changed, it will re-apply the configuration passed to Ansible
              in a single API call with all firewall rules.

              Exclusions:
                - Firewall rule name must be unique in each section, as the name is used to compare existing rules
                  against vars being passed in.
                - No checks are made to remove firewall rule params on update. For instance if the destination is 
                  removed from the answers file, it will not detect it as a change. This it to prevent future NSX API 
                  changes from breaking the checking algorithm, as the API treats a non-existant value as "ANY" for 
                  things like source and destination lists. To remediate, if you require a rule to have an empty 
                  default param set, simply change it description, which will force re-creation.

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
- name: Add Distributed Firewall Section with membership criteria
  nsxt_dfw_section:
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


- name: Add Distributed Firewall Section with static members
  nsxt_dfw_section:
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

ENDPOINT_LOOKUP = {'NSGroup': '/ns-groups', 'IPSet': '/ip-sets', 'FirewallSection': '/firewall/sections',
                    'LogicalSwitch': '/logical-switches', 'LogicalPort': '/logical-ports', 'NSProfile': '/ns-profiles',
                    'NSServiceGroup': '/ns-service-groups', 'NSService': '/ns-services'
                     }

# def check_all_sections_are_unique(sections):
#     existing_section_list = [d['display_name'] for d in l if 'display_name' in d]
#     for section 

def get_dfw_section_params(args=None):
  args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
  for key in args_to_remove:
    args.pop(key, None)
  for key, value in args.copy().items():
    if value == None:
      args.pop(key, None)
  return args

def get_dfw_section_rules(module, manager_url, mgr_username, mgr_password, validate_certs, section_id):
  try:
    (rc, resp) = request(manager_url+ '/firewall/sections/%s/rules' % section_id, headers=dict(Accept='application/json'),
                    url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    results = None
    if resp['results']:
      results = resp['results']
  except Exception as err:
    module.fail_json(msg='Error accessing Distributed Firewall Section Rules for section %s. \nError [%s]' % (section_id, to_native(err)))
  return results

def get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    try:
        (rc, resp) = request(manager_url+ '/firewall/sections', headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        dfw_sections = resp['results']
    except Exception as err:
        module.fail_json(msg='Error accessing Distributed Firewall Section. Error [%s]' % (to_native(err)))
    
    return_section = None
    for dfw_section in dfw_sections:
        if dfw_section.__contains__('display_name') and dfw_section['display_name'] == display_name:
            if not return_section: # Handle there being 2 sections created with the same display name
                return_section = dfw_section
            else:
                module.fail_json(msg='Section with display name %s exists twice.' % (display_name))
    return return_section

# def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name, exit_if_not_found=True, id_notation='id'):
#     try:
#         (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
#                         url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
#     except Exception as err:
#         module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

#     for result in resp['results']:
#         if result.__contains__('display_name') and result['display_name'] == display_name:
#             return result[id_notation]
#     if exit_if_not_found:
#         module.fail_json(msg='No id exist with display name %s' % display_name)

# def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params ):
#   if dfw_section_params['rules'] and False: #TODO
#     for idx, member in enumerate(dfw_section_params['rules']):
#       if member['target_type'] in ENDPOINT_LOOKUP.keys() and (member['target_property'] == 'id' or member['target_property'] == 'external_id'):
#         value = dfw_section_params['members'][idx].pop('value', None)
#         if member['target_property'] == 'id':
#           dfw_section_params['members'][idx]['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
#                       ENDPOINT_LOOKUP[member['target_type']], value)
#         elif member['target_property'] == 'external_id':
#           dfw_section_params['members'][idx]['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
#                       ENDPOINT_LOOKUP[member['target_type']], value, True, 'external_id')
#   return dfw_section_params

def update_param_list_with_ids(module, params, existing_config_lookup, duplicated_objects):
    for idx, param in enumerate(params):
        if param.__contains__('target_type') and param['target_display_name'] not in duplicated_objects[param['target_type']]:
            try:
                # Type IP address has the IP for display_name and target_id
                if param['target_type'] == 'IPAddress':
                    params[idx]['target_id'] = param['target_display_name']
                else:
                    params[idx]['target_id'] = existing_config_lookup[param['target_type']][param['target_display_name']]
            except Exception as err:
                module.fail_json(msg='Unable to find %s. Error [%s]' % (param['target_type'], to_native(err)))
        elif param.__contains__('target_display_name') and param['target_display_name'] in duplicated_objects[param['target_type']]:
            module.fail_json(msg='Object [%s] specified exists more than once with the same display name.' % (param['target_display_name']))

def update_rules_list_with_ids(module, rules, existing_config_lookup, list_section_names, duplicated_objects):
    for idx, rule in enumerate(rules):
        for section_name in list_section_names:
            if rule.__contains__(section_name) and rule[section_name]:
                # Passing in the original rules list, so that it can be updated in place.
                update_param_list_with_ids(module, rules[idx][section_name], existing_config_lookup, duplicated_objects)

def insert_missing_lists(source_dict, keys):
  for key in keys:
    if not source_dict.__contains__(key):
      source_dict[key] = []

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params):
    existing_dfw_section = get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, 
                                                            validate_certs, dfw_section_params['display_name'])
    if not existing_dfw_section:
        return False
    copy_dfw_section_params = dict(dfw_section_params)
    new_dfw_secton_rules = copy_dfw_section_params.pop('rules', [])
    new_dfw_secton_applied_tos = copy_dfw_section_params.pop('applied_tos', [])
    
    #display.banner("New :  %s" % new_dfw_secton_applied_tos + "\n\n\n Existing : %s" % existing_dfw_section)
    
    # Check to ensure that all keys and values in the new params match the existing configuration
    if not all(k in existing_dfw_section and copy_dfw_section_params[k] == existing_dfw_section[k] for k in copy_dfw_section_params):
        return True
    
    # Check that applied_tos sections match.
    insert_missing_lists(existing_dfw_section, ['applied_tos'])
    existing_applied_tos = [d['target_id'] for d in existing_dfw_section['applied_tos'] if 'target_id' in d]
    new_applied_tos = [d['target_id'] for d in dfw_section_params['applied_tos'] if 'target_id' in d]
    if not Counter(existing_applied_tos) == Counter(new_applied_tos):
        return True 

    # existing rules dict used to lookup against new rules by name.
    existing_rule_dict = {}
    existing_dfw_section_rules = get_dfw_section_rules(module, manager_url, mgr_username, mgr_password, validate_certs, existing_dfw_section['id'])
    if len(existing_dfw_section_rules) <> len(new_dfw_secton_rules):
        return True

    for rule in existing_dfw_section_rules:
        insert_missing_lists(rule, ['applied_tos', 'context_profiles', 'destinations', 'services', 'sources'])
            #TODO might not need
        existing_rule_dict[rule['display_name']] = rule
 
    

    # if not all(k in existing_dfw_section_rules and new_dfw_secton_rules[k] == existing_dfw_section_rules[k] for k in new_dfw_secton_rules):
    #     module.fail_json(msg="New:  %s" % new_dfw_secton_rules + "\n\n\n Existing: %s" % existing_dfw_section_rules)
    #     return True

    return True

def collect_all_existing_config(module, manager_url, mgr_username, mgr_password, validate_certs):
    # existing_config = {}
    existing_config_lookup = {}
    duplicated_objects = {'IPAddress': []}
    for endpoint_name, endpoint in ENDPOINT_LOOKUP.items():
        try:
            (rc, resp) = request(manager_url + endpoint, headers=dict(Accept='application/json'),
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            module.fail_json(msg='Error accessing %s. Error [%s]' % (endpoint_name, to_native(err)))
        if resp:
            duplicated_objects[endpoint_name] = []
            lookup_table = {}
            for item in resp['results']:
                if item.__contains__('display_name') and item.__contains__('id'):
                    if item['display_name'] not in duplicated_objects[endpoint_name]:
                        lookup_table[item['display_name']] = item['id']
                    else:
                        duplicated_objects[endpoint_name].append(item['display_name'])
            # existing_config[endpoint_name] = resp['results']
            existing_config_lookup[endpoint_name] = lookup_table
    #module.fail_json(msg="Lazy  %s.#### %s" % (duplicated_objects, ''))

    return existing_config_lookup, duplicated_objects

# Remove context profiles to allow support for 2.3 and below
def add_backwards_compatibilty(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params):
    try:
        (rc, resp) = request(manager_url+ '/upgrade/summary', headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing API verion details. Error [%s]' % (to_native(err)))
    if float(resp['system_version'][0:3]) < 2.4:
        for idx, rule in enumerate(dfw_section_params['rules']):
            dfw_section_params['rules'][idx].pop('context_profiles', None)

def check_rules_have_unique_names(module, dfw_section_params):
    rule_names = set()
    duplicateed_rule_names = set()
    for rule in dfw_section_params['rules']:
        if rule['display_name'] in rule_names:
            duplicateed_rule_names.add(rule['display_name'])
        else:
            rule_names.add(rule['display_name'])
    if duplicateed_rule_names:
        module.fail_json(msg='The following rules have duplicate display_names [%s]. \nEnsure all rules have unique names withiin each section' % (', '.join(duplicateed_rule_names)))

def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'),
                        section_placement=dict(required=False, type='dict',
                        operation=dict(required=True, type='str', choices=['insert_top', 'insert_bottom', 'insert_after', 
                                                                            'insert_before']),
                        id=dict(required=False, type='str'),
                        display_name=dict(required=False, type='str')
                        ),
                        host_credential=dict(required=False, type='dict',
                        username=dict(required=False, type='str'),
                        password=dict(required=False, type='str', no_log=True),
                        thumbprint=dict(required=False, type='str', no_log=True)),
                        applied_tos=dict(required=False, type='list', default=list([]),
                            target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                            target_type=dict(required=True, type='str')
                            ),
                        description=dict(required=False, type='str'),
                        rules=dict(required=True, type='list',
                            display_name=dict(required=True, type='str'), # API does not enforce, but added to all later management.
                            description=dict(required=False, type='str'),
                            action=dict(required=True, type='str', choices=['ALLOW', 'DROP', 'REJECT', 'REDIRECT', 
                                                                            'DO_NOT_REDIRECT']),
                            applied_tos=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str')
                                ),
                            context_profiles=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str')
                                ),
                            destinations=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str')
                                ),
                            direction=dict(required=False, type='str', choices=['IN', 'OUT', 'IN_OUT']),
                            disabled=dict(required=False, type='bool'),
                            ip_protocol=dict(required=False, type='str', choices=['IPV4', 'IPV6', 'IPV4_IPV6']),
                            logged=dict(required=False, type='bool'),
                            notes=dict(required=False, type='str'),
                            resource_type=dict(required=False, type='str', choices=['FirewallRule']),
                            rule_tag=dict(required=False, type='str'),
                            # section_name=dict(required=False, type='str'), # Will convert to ID and then pop to use in the URL.
                            services=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=False, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str'),
                                service=dict(required=False, type='list', default=[],
                                    alg=dict(required=False, type='str', choices=['ORACLE_TNS', 'FTP', 'SUN_RPC_TCP', 
                                                                                  'SUN_RPC_UDP', 'MS_RPC_TCP', 'MS_RPC_UDP', 
                                                                                  'NBNS_BROADCAST', 'NBDG_BROADCAST', 'TFTP']),
                                    destination_ports=dict(required=False, type='list'), # Will insert target_id a runtime
                                    icmp_code=dict(required=False, type='int'),
                                    icmp_type=dict(required=False, type='int'),
                                    l4_protocol=dict(required=False, type='str'),
                                    protocol=dict(required=False, type='str', choices=['ICMPv4']),
                                    protocol_number=dict(required=False, type='int'),
                                    resource_type=dict(required=True, type='str', 
                                                       choices=['ALGTypeNSService', 'IPProtocolNSService', 
                                                                'L4PortSetNSService', 'ICMPTypeNSService', 'IGMPTypeNSService']),
                                    source_ports=dict(required=False, type='list')
                                    ),
                                ),
                            sources=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str')
                                ),
                            ),
                        #resource_type=dict(required=True, choices=['FirewallSectionRuleList']),
                        section_type=dict(required=False, choices=['LAYER3'], default='LAYER3'),
                        state=dict(required=True, choices=['present', 'absent']),
                        stateful=dict(required=True, type='bool'))
                        
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    
    dfw_section_params = get_dfw_section_params(module.params.copy())
    #display.banner('B-Original Params = ' + str(dfw_section_params))
    #module.log(msg='L-Original Params = ' + str(dfw_section_params))  
    #module.fail_json(msg="Lazy  %s " % dfw_section_params)
    
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    section_placement = dfw_section_params.pop('section_placement', None)

    if not dfw_section_params['rules']:
        module.fail_json(msg="Failed to add section %s. You must include rules." % (display_name))

    check_rules_have_unique_names(module, dfw_section_params)
    
    # Convert empty default Ansible lists containing a single string to an empty list
    insert_missing_lists(dfw_section_params, ['applied_tos'])

    #module.fail_json(msg="Lazy  %s." % (dfw_section_params))

    node_dict = get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
    node_id, revision = None, None
    if node_dict:
        node_id = node_dict['id']
        revision = node_dict['_revision']
    
    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        add_backwards_compatibilty(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params)
        #body = update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params)
        
        existing_config_lookup, duplicated_objects = collect_all_existing_config(module, manager_url, mgr_username, 
                                                                                 mgr_password, validate_certs)
        update_param_list_with_ids(module, dfw_section_params['applied_tos'], existing_config_lookup, duplicated_objects)
        update_rules_list_with_ids(module, dfw_section_params['rules'], existing_config_lookup, 
                                   ['applied_tos', 'context_profiles', 'destinations', 'services', 'sources'],
                                   duplicated_objects)
        updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params)
        #module.fail_json(msg="Lazy  %s.#### %s" % (dfw_section_params, ''))
        if not updated:
            #TODO write method to extract ID and operator for section placement.
            section_placement_params = '' 
            request_data = json.dumps(dfw_section_params)
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(request_data), id='12345')
            try:
                if node_id:
                    module.exit_json(changed=False, id=node_id, message="Distributed Firewall Section with display_name %s already exist and has not changed."% module.params['display_name'])
                (rc, resp) = request(manager_url+ '/firewall/sections?action=create_with_rules' + section_placement_params, data=request_data, headers=headers, method='POST',
                                    url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to add node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Distributed Firewall Section with display name %s created succcessfully." % module.params['display_name'])
        else:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(dfw_section_params)), id=id)
            dfw_section_params['_revision'] = revision # update current revision   
            request_data = json.dumps(dfw_section_params)
            id = node_id
            try:
                (rc, resp) = request(manager_url+ '/firewall/sections/%s?action=update_with_rules' % id, data=request_data, headers=headers, method='POST',
                                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to update node with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))
            module.exit_json(changed=True, id=resp["id"], body= str(resp), message="Distributed Firewall Section with node id %s updated." % id)

    elif state == 'absent':
        # delete the array
        id = node_id
        if id is None:
            module.exit_json(changed=False, msg='No Distributed Firewall Section exist with display name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(dfw_section_params)), id=id)
        try:
            (rc, resp) = request(manager_url + "/firewall/sections/%s?cascade=true" % id, method='DELETE',
                                  url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete Distributed Firewall Section with id %s. Error[%s]." % (id, to_native(err)))

        module.exit_json(changed=True, id=id, message="NG Group with node id %s deleted." % id)


if __name__ == '__main__':
    main()
