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
module: nsxt_dfw_sections
short_description: Module to insert and modify firewall sections with or without rules.
description:  'Creates Firewall Sections, with the option to add rules.
              This is intended for use with GitOps workflows, where the configuration is stored in Git and the
              playbook run after a change has been made.
              Large firewall sections with many hundreds of rules can cause issues with API performance and the
              API guide states supported rule section size and maximum levels of concurrency.
              If section params or any rule params are changed, it will re-apply the configuration passed to Ansible
              in a single API call per section  with all firewall rules.

              Usage:
                - Firewall rule names must be unique in each section, as the name is used to compare existing rules
                  against vars being passed in.
                - Sections managed by Ansible must have unique display names.

              Reference the API guide for which params can be used with which operations.
              Maximums and descriptions below taken from the 2.4 API guide, consult for changes.'

version_added: "2.7"
author: Matt Proud
options:
    display_name:
        description: Display name
        required: true
        type: str
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
    applied_tos:
        description: 'List of obects section applies. Must conform to ResourceReference schema.
                      For distrubuted firewall rules target_type must be:
                        ['NSGroup', 'LogicalSwitch', 'LogicalPort']
                        Max 128 supported objects
                      For edge firewall rules target_type must be:
                        ['LogicalRouter']
                        Cannot mix distribted and edge types. Section can only apply to a single logical router'
        required: False
        type: list
        target_display_name:
            description: Display name of the NSX resource.
            required: True
            type: str
        target_type: 
            choices: ['NSGroup', 'LogicalSwitch', 'LogicalPort', 'LogicalRouter']
            description: Type of the NSX resource.
            required: True
            type: str
    description:
        description: Description of this resource.
        required: False
        type: str
    modify_placement:
        default: False
        description: When updating rules, flag will move section to desired placement.
        required: False
        type: bool
    rules:
        description: List of rules to be applied with the section. Rules follow FirewallRule schema.
        required: True
        type: list
        display_name:
            description: Display name
            required: true
            type: str
        description:
            description: Description of rule
            required: False
            type: str
        action:
            choices: ['ALLOW', 'DROP', 'REJECT', 'REDIRECT', 'DO_NOT_REDIRECT']
            description: 'Action enforced on the packets which matches the distributed service rule. Currently DS Layer
                          supports below actions. ALLOW - Forward any packet when a rule with this action gets a match
                          (Used by Firewall). DROP - Drop any packet when a rule with this action gets a match. Packets
                          won't go further(Used by Firewall). REJECT - Terminate TCP connection by sending TCP reset 
                          for a packet when a rule with this action gets a match (Used by Firewall). REDIRECT - 
                          Redirect any packet to a partner appliance when a rule with this action gets a match 
                          (Used by Service Insertion). DO_NOT_REDIRECT - Do not redirect any packet to a partner 
                          appliance when a rule with this action gets a match (Used by Service Insertion).'
            required: True
            type str
        applied_tos:
            description: List of obects rule applies. Must conform to ResourceReference schema.  Max 128.
            required: False
            type: list
            target_display_name:
                description: Display name of the NSX resource.
                required: True
                type: str
            target_type: 
                choices: ['NSGroup', 'LogicalSwitch', 'LogicalPort', 'LogicalRouterPort']
                description: 'Type of the NSX resource. LogicalRouterPort only supported on Logical Router sections'
                required: True
                type: str
        context_profiles:
            description: 'List of conext profile objects applied. Must conform to ResourceReference schema. 
                          Can only be usd for distrubted firewall sections on NSX-T 2.4. 
                          Not supported on the Edge firewall. Max 128.'
            required: False
            type: list
            target_display_name:
                description: Display name of the NSX resource.
                required: True
                type: str
            target_type: 
                choices: ['NSProfile']
                description: Type of the NSX resource.
                required: True
                type: str
        destinations:
            description: List of destination obects rule applies. Must conform to ResourceReference schema. Max 128.
            required: False
            type: list
            target_display_name:
                description: Display name of the NSX resource.
                required: True
                type: str
            target_type: 
                choices: ['IPSet', 'NSGroup', 'LogicalSwitch', 'LogicalPort']
                description: Type of the NSX resource.
                required: True
                type: str
        direction:
            description: 'Rule direction in case of stateless distributed service rules. This will only considered if
                          section level parameter is set to stateless. Default to IN_OUT if not specified.'
            required: False
            type: str
        disabled:
            description: Flag to disable rule. Disabled will only be persisted but never provisioned/realized.
            required: False
            type: bool
        ip_protocol:
            choices: ['IPV4', 'IPV6', 'IPV4_IPV6']
            description: Type of IP packet that should be matched while enforcing the rule.
            required: False
            type: str
        logged:
            description: Flag to enable packet logging. Default is disabled.
            required: False
            type: bool
        notes:
            description: User notes specific to the rule. Max 2048 chars.
            required: False
            type: str
        resouce_type:
            choices: ['FirewallRule']
            description: Type of NSX Resource.
            required: False
            type: str
        rule_tag:
            description: User level field which will be printed in CLI and packet logs. Max 32 chars.
            required: False
            type: str
        services:
            description: 'List of service obects rule applies. Must conform to ResourceReference schema.
                          Each service should either comprise target_display_name and target_type, or service.
                          Max 128.'
            required: False
            type: list
            service:
                description: 'List of custom services. Must conform to ResourceReference schema.
                              Should either comprise target_display_name and target_type, or service.
                              Custom services should conform to ALGTypeNSService, ICMPTypeNSService, 
                              IGMPTypeNSService, IPProtocolNSService or L4PortSetNSService schemas.'
                required: False
                type: list
                alg:
                    choices: ['ORACLE_TNS', 'FTP', 'SUN_RPC_TCP', 'SUN_RPC_UDP', 'MS_RPC_TCP', 'MS_RPC_UDP', 
                              'NBNS_BROADCAST', 'NBDG_BROADCAST', 'TFTP']
                    description: 'The Application Layer Gateway (ALG) protocol. Consult the documentation for edge
                                  rules as not all protocols are supported on edge firewalls.' 
                    required: False
                    type: str 
                destination_ports:
                    description: List of ports as integers. Max 15
                    required: False
                    type: list
                icmp_code:
                    description: ICMP message code
                    required: False
                    type: int
                icmp_type:
                    description: ICMP message type
                    required: False
                    type: int
                l4_protocol:
                protocol:
                    choices: ['ICMPv4', 'ICMPv6']
                    description: ICMP protocol type
                    required: False
                    type: list
                protocol_number:
                    description: The IP protocol number
                    required: False
                    type: int
                resource_type:
                    choices: ['ALGTypeNSService', 'IPProtocolNSService', 'L4PortSetNSService', 'ICMPTypeNSService',
                              'IGMPTypeNSService']
                    description: Type of service.
                    required: False
                    type: list
                source_ports:
                    description: List of ports as integers. Max 15
                    required: False
                    type: list
            target_display_name:
                description: Display name of the NSX resource.
                required: False
                type: str
            target_type: 
                choices: ['IPSet', 'NSGroup', 'LogicalSwitch', 'LogicalPort']
                description: Type of the NSX resource.
                required: False
                type: str
        sources:
            description: List of source obects rule applies. Must conform to ResourceReference schema. Max 128.
            required: False
            type: list
            target_display_name:
                description: Display name of the NSX resource.
                required: True
                type: str
            target_type: 
                choices: ['NSService', 'NSServiceGroup']
                description: 'Type of the NSX resource.'
                required: True
                type: str
    resource_type:
        choices: ['FirewallSectionRuleList']
        description: Type of the NSX resource.
        required: False
        type: str
    section_placement:
        description: Options on where to insert new secton. This must be a reference to a section in the
                     appropriate firewall.
        required: False
        type: dict
        id:
            description: Unique ID of the section to be paired with if insert_after or insert_before used.
            required: false
            type: str
        display_name:
            description: 'Display name of partner section if insert_after or insert_before used. Ignored if 
                          id is used.'
            required: false
            type: str
        operation:
            choices: ['insert_top', 'insert_bottom', 'insert_after', 'insert_before']
            description: 'Insert operation to place within the relevant firewall. In NSX-T 2.4.0, insert_bottom on 
                          Logical Routers will insert below the default ruleset so should be avoided. Instead use
                          insert_before and the ID of the default section of that router'
            required: True
            type: str
    section_type:
        choices: ['LAYER3']
        description: Insert operation command
        required: False
        type: str
    state:
        choices: ['present', 'absent']
        description: 'State can be either 'present' or 'absent'. 
                      'present' is used to create or update resource. 
                      'absent' is used to delete resource.'
        required: true
    stateful:
        description: 'Stateful nature of the distributed service rules in the section.
                     Stateful or Stateless nature of distributed service section is enforced 
                     on all rules inside the section.' 
        required: True
        type: bool
    tags:
        description: 'Opaque identifiers meaningful to the API user. Max 30 items'
        required: false
        type: list
        scope:
            description: 'Tag scope. Tag searches may optionally be restricted by scope. Max len 128 charactors.'
            required: true
            type: str
        tag:
            description: ' 	Tag value. Identifier meaningful to user. Max len 128 charactors.'
            required: true
            type: str

'''

EXAMPLES = '''
- name: Add Distributed Firewall Section with Rules
  nsxt_dfw_section:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: Test Section
    description: Testing DFW
    stateful: True
    state: present
    applied_tos:
    section_placement:
        operation: insert_top
    rules:
    - display_name: 'Test Rule'
        description: Testing
        action: ALLOW
        applied_tos:
        - target_display_name: 'ns_test'
          target_type: NSGroup
        context_profiles:
        - target_display_name: 'SSL'
          target_type: NSProfile
        destinations: 
        - target_display_name: 'ip_set_test'
          target_type: IPSet
        direction: IN_OUT
        ip_protocol: IPV4
        logged: True
        resource_type: FirewallRule
        rule_tag: Test-Log-Tag
        services: 
        - target_display_name: 'HTTPS'
          target_type: NSService
        sources: 
        - target_display_name: '10.1.1.1'
          target_type: IPAddress

- name: Add Edge Firewall Section with Rules
  nsxt_dfw_section:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: Test Section
    description: Testing Edge
    stateful: True
    state: present
    applied_tos:
    - target_display_name: 't0-router'
        target_type: LogicalRouter
    section_placement:
        operation: insert_top
    rules:
    - display_name: 'Test Rule'
        description: Testing
        action: ALLOW
        destinations: 
        - target_display_name: 'ip_set_test'
          target_type: IPSet
        resource_type: FirewallRule
        services: 
        - target_display_name: 'HTTPS'
          target_type: NSService
        sources: 
        - target_display_name: '10.1.1.1'
          target_type: IPAddress

- name: Add Distributed Firewall Section
  nsxt_dfw_section:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: Test Section
    description: Testing edge
    stateful: True
    state: present
'''

RETURN = '''# '''

import json, time, copy
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native
from collections import Counter


ENDPOINT_LOOKUP = {'NSGroup': '/ns-groups', 'IPSet': '/ip-sets', 'FirewallSection': '/firewall/sections',
                    'LogicalSwitch': '/logical-switches', 'LogicalPort': '/logical-ports', 'LogicalRouter': '/logical-routers', 
                    'LogicalRouterPort': '/logical-router-ports', 'NSProfile': '/ns-profiles', 
                    'NSServiceGroup': '/ns-service-groups', 'NSService': '/ns-services'}


def get_all_request(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint):
    '''Handle the API service respondign with a cursor and make subsequent request.'''
    try:
        output_list = []
        cursor = ''
        while True:
            (rc, resp) = request(manager_url + endpoint + cursor, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            if resp['results']:
                output_list += resp['results']
            if resp.__contains__('cursor'):
                cursor = '?cursor=' + resp['cursor']
            else:
                break
        return output_list
    except Exception as err:
        module.fail_json(msg='Error accessing endpoint %s. \nError [%s]' % (endpoint, to_native(err)))

def get_dfw_section_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    '''Return dict of firewall section by section name, if name is unique'''
    dfw_sections = get_all_request(module, manager_url, mgr_username, mgr_password, validate_certs, '/firewall/sections')
    return_section = None
    for dfw_section in dfw_sections:
        if dfw_section.__contains__('display_name') and dfw_section['display_name'] == display_name:
            if not return_section: # Handle there being 2 sections created with the same display name
                return_section = dfw_section
            else:
                module.fail_json(msg='Section with display name %s exists more than once.' % (display_name))
    return return_section

# Generate IDs for each sub-section
def update_param_list_with_ids(module, params, existing_config_lookup, duplicated_objects, rule_display_name, section_name):
    '''Update sections with ID of objects based on display_name'''
    for idx, param in enumerate(params):
        try:
            if param.__contains__('target_type') and param['target_display_name'] not in duplicated_objects[param['target_type']]:
                if param['target_type'] == 'IPAddress':
                    params[idx]['target_id'] = param['target_display_name']
                else:
                    params[idx]['target_id'] = existing_config_lookup[param['target_type']][param['target_display_name']]
            elif param.__contains__('target_display_name') and param['target_display_name'] in duplicated_objects[param['target_type']]:
                module.fail_json(msg='Object [%s] specified exists more than once with the same display name.' % (param['target_display_name']))
        except KeyError as err:
                module.fail_json(msg='Unable to find mandatory param [%s] within [%s] sub-section [%s]' % (to_native(err), rule_display_name, section_name))

def update_rules_list_with_ids(module, rules, existing_config_lookup, list_section_names, duplicated_objects):
    '''Loop through each rule and insert IDs into each section where display_name is supplied'''
    for idx, rule in enumerate(rules):
        for section_name in list_section_names:
            if rule.__contains__(section_name) and rule[section_name]:
                # Passing in the original rules list, so that it can be updated in place.
                update_param_list_with_ids(module, rules[idx][section_name], existing_config_lookup, duplicated_objects,
                                         'Rule ' + rule['display_name'], section_name)

def insert_lists_if_missing(source_dict, keys):
  '''Insert empty list as value in a dict if the dict does not contain the key'''
  for key in keys:
    if not source_dict.__contains__(key):
      source_dict[key] = []

def extract_services_list_of_strings(services):
    '''Extract services and represent them as a list of sorted strings to allow comparison'''
    output_list = []
    for service in services:
        item_string = ''
        for key, value in service.items():
            if isinstance(value, list):
                for item in value:
                    item_string += key + str(item)
            else:
                item_string += key + str(value)
        
        # String is sorted to allow for dictionary order to change.
        output_list.append(''.join(sorted(item_string)))
    return output_list

def compare_custom_services(module, existing_services, new_services):
    '''Compare custom services by extracting parameters as strings'''
    if existing_services and new_services:
        # Lists must be deep copied otherwise pop removes globally.
        existing_services_copy = copy.deepcopy(existing_services)
        new_services_copy = copy.deepcopy(new_services)
        existing_custom_services = [d.pop('service') for d in existing_services_copy if 'service' in d]
        new_custom_services = [d.pop('service') for d in new_services_copy if 'service' in d]
        
        if len(existing_custom_services) != len(new_custom_services):
            return True
        
        elif existing_custom_services or new_custom_services:
            # Extract list containing a strings of custom services. Lists of strings are hashable and faster to compare.
            existing_custom_service_list = extract_services_list_of_strings(existing_custom_services)
            new_custom_service_list = extract_services_list_of_strings(new_custom_services)
            if not Counter(existing_custom_service_list) == Counter(new_custom_service_list):
                return True

    return False

def convert_tag_dict_to_string(tag_list):
    '''Convert list of tag dicts to a list of strings'''
    existing_tag_strings = []
    for tag in tag_list:
        tag_string = ''
        for key in ['tag', 'scope']:
            if tag.__contains__(key) and tag[key] != '':
                tag_string += key + tag[key]
        existing_tag_strings.append(tag_string)
    return existing_tag_strings

def compare_tags(module, existing_tags, new_tags):
    '''Compare tags as lists of strings to check for differences'''
    if len(existing_tags) != len(new_tags):
        return True
    
    # Convert tag dictionaries to strings to allow list compare and account of empty values in either element.
    existing_tag_strings = convert_tag_dict_to_string(existing_tags)
    new_tag_string = convert_tag_dict_to_string(new_tags)
    if existing_tag_strings != new_tag_string:
        return True
        
    return False

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params):
    '''Check if any element of a section has changed'''
    existing_dfw_section = get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, 
                                                            validate_certs, dfw_section_params['display_name'])
    if not existing_dfw_section:
        return False
    
    # Lists must be deep copied otherwise pop removes globally.
    copy_dfw_section_params = copy.deepcopy(dfw_section_params)
    new_dfw_secton_rules = copy_dfw_section_params.pop('rules', [])
    new_dfw_secton_applied_tos = copy_dfw_section_params.pop('applied_tos', [])
    copy_dfw_section_params.pop('resource_type', None)
    copy_tags = copy_dfw_section_params.pop('tags', [])
    existing_tags = existing_dfw_section.pop('tags', [])
    
    # Check to ensure that all keys and values in the new params match the existing configuration.
    if not all(k in existing_dfw_section and copy_dfw_section_params[k] == existing_dfw_section[k] for k in copy_dfw_section_params):
        return True
    
    # Compare list of tags as strings
    if compare_tags(module, existing_tags, copy_tags):
        return True

    # Check that applied_tos sections match.
    insert_lists_if_missing(existing_dfw_section, ['applied_tos'])
    existing_applied_tos = [d['target_type'] + d['target_id'] for d in existing_dfw_section['applied_tos'] if 'target_id' in d]
    new_applied_tos = [d['target_type'] + d['target_id'] for d in dfw_section_params['applied_tos'] if 'target_id' in d]
    if not Counter(existing_applied_tos) == Counter(new_applied_tos):
        return True 
    
    # Create lookup table of existing rules by display name. Ignore duplicate names as would trigger a change anyway.
    existing_rule_dict = {}
    existing_dfw_section_rules = get_all_request(module, manager_url, mgr_username, mgr_password, validate_certs,
                                                 '/firewall/sections/%s/rules' % existing_dfw_section['id'])
    if len(existing_dfw_section_rules) != len(new_dfw_secton_rules):
        return True
    for rule in existing_dfw_section_rules:
        try:
            existing_rule_dict[rule['display_name']] = rule
        except KeyError:
            pass

    # Iterate through each rule and compare each subsection list and finally the keys and values.
    for new_rule in new_dfw_secton_rules:
        existing_rule = existing_rule_dict[new_rule['display_name']]
        section_labels = ['applied_tos', 'context_profiles', 'destinations', 'services', 'sources']
        insert_lists_if_missing(new_rule, section_labels)
        insert_lists_if_missing(existing_rule, section_labels)
        for section in section_labels:
            # Custom services don't have the target_id key, so need to be treated separately
            if section == 'services':
                if compare_custom_services(module, existing_rule[section], new_rule[section]):
                    return True
            existing_section_ids = [d['target_type'] + d['target_id'] for d in existing_rule[section] if 'target_id' in d]
            new_section_ids = [d['target_type'] + d['target_id'] for d in new_rule[section] if 'target_id' in d]
            if not Counter(existing_section_ids) == Counter(new_section_ids):
                return True

        # Remove lists for rules, so that the keys and values can be compared.
        [new_rule.pop(key, None) for key in section_labels]
        [existing_rule.pop(key, None) for key in section_labels]

        if not all(k in existing_rule and new_rule[k] == existing_rule[k] for k in new_rule):
            return True
    return False

def collect_all_existing_config(module, manager_url, mgr_username, mgr_password, validate_certs):
    '''Collect all existing configuration and return as dict mapping display_name to IDs and list of duplicates'''
    existing_config_lookup = {}
    duplicated_objects = {'IPAddress': []} # Manually isert IP Addresses as the cannot be duplicated.
    for endpoint_name, endpoint in ENDPOINT_LOOKUP.items():
        resp = get_all_request(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint)
        if resp:
            duplicated_objects[endpoint_name] = []
            lookup_table = {}
            for item in resp:
                if item.__contains__('display_name') and item.__contains__('id'):
                    if item['display_name'] not in duplicated_objects[endpoint_name]:
                        lookup_table[item['display_name']] = item['id']
                    else:
                        duplicated_objects[endpoint_name].append(item['display_name'])
            existing_config_lookup[endpoint_name] = lookup_table
    return existing_config_lookup, duplicated_objects

def add_backwards_compatibilty(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params):
    '''Remove context profiles to allow support for 2.3 and below'''
    try:
        (rc, resp) = request(manager_url+ '/upgrade/summary', headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        if float(resp['system_version'][0:3]) < 2.4:
            for idx, rule in enumerate(dfw_section_params['rules']):
                dfw_section_params['rules'][idx].pop('context_profiles', None)
                ENDPOINT_LOOKUP.pop('NSProfile', None)
    except Exception as err:
        module.fail_json(msg='Error accessing API verion details. Error [%s]' % (to_native(err)))

def check_if_section_moved(module, manager_url, mgr_username, mgr_password, validate_certs, section_placement, 
                           existing_config_lookup, dfw_section_params, modify_placement):
    '''Check if FW section placement does not match definition'''
    if not modify_placement:
        return False
    existing_section_list = get_all_request(module, manager_url, mgr_username, mgr_password, validate_certs, '/firewall/sections')                                                
    for idx, section in enumerate(existing_section_list):
        if section['display_name'] == dfw_section_params['display_name']:
            try:
                if section_placement['operation'] == 'insert_top' and idx != 0:
                    if section['enforced_on'] == 'VIF':
                        if existing_section_list[idx - 1]['enforced_on'] == section['enforced_on']:
                            return True
                    elif section['enforced_on'] == 'LOGICALROUTER':
                        if existing_section_list[idx - 1]['applied_tos'] == section['applied_tos']:
                            return True
                elif section_placement['operation'] == 'insert_bottom':
                    if section['enforced_on'] == 'VIF':
                        if existing_section_list[idx + 1]['display_name'] != 'Default Layer3 Section':
                            return True
                    elif section['enforced_on'] == 'LOGICALROUTER':
                        if existing_section_list[idx + 1]['display_name'] != 'Default LR Layer3 Section':
                            return True
                elif section_placement['operation'] == 'insert_after':
                    if idx == 0:
                        return True
                    elif section_placement.__contains__('id') and section_placement['id'] != existing_section_list[idx - 1]['id']:
                        return True
                    elif section_placement.__contains__('display_name') and \
                        existing_config_lookup['FirewallSection'][str(section_placement['display_name'])] != existing_section_list[idx - 1]['id']:
                        return True
                elif section_placement['operation'] == 'insert_before':
                    if section_placement.__contains__('id') and section_placement['id'] != existing_section_list[idx + 1]['id']:
                        return True
                    elif section_placement.__contains__('display_name') and \
                        existing_config_lookup['FirewallSection'][str(section_placement['display_name'])] != existing_section_list[idx + 1]['id']:
                        return True
            except KeyError:
                module.fail_json(msg="Failed when looking up section placement for section [%s] with params [%s]."  % 
                                 (dfw_section_params['display_name'], section_placement))
            break
    return False

def generate_section_placement(module, manager_url, mgr_username, mgr_password, validate_certs, section_placement, 
                               existing_config_lookup, duplicated_objects, section_name, place_updated):
    '''Generate option string to post on create or update'''
    if not section_placement:
        return ''
    try:
        if section_placement['operation'] == 'insert_top' or section_placement['operation'] == 'insert_bottom':
            return 'operation=' + section_placement['operation']
        elif section_placement['operation'] == 'insert_after' or section_placement['operation'] == 'insert_before':
            if section_placement.__contains__('id'):
                return 'operation=' + section_placement['operation'] + '&id=' + section_placement['id']
            elif section_placement.__contains__('display_name') and existing_config_lookup['FirewallSection'].__contains__(str(section_placement['display_name'])):
                if section_placement[str('display_name')] in duplicated_objects['FirewallSection']:
                    module.fail_json(msg='Firewall section %s exists more than once when trying to assign placement for section %s.' % 
                                     (section_placement['display_name'], section_name))
                return 'operation=' + section_placement['operation'] + '&id=' + existing_config_lookup['FirewallSection'][str(section_placement['display_name'])]
        else:
            module.fail_json(msg='[%s] is not a valid section plecement operator for section [%s].' % (section_placement['operation'], section_name))
        module.fail_json(msg='Unable to find section [%s]. when generating placement ID for section [%s].' % 
                         (section_placement['display_name'], section_name))
    except KeyError as err:
        module.fail_json(msg='Unable to find section [%s] when generating section placement. Error [%s]' % 
                         (section_placement['display_name'], to_native(err)))

def generate_query_params(module, dfw_section_params, manager_url, mgr_username, mgr_password, validate_certs, 
                          section_placement, updated, existing_config_lookup, duplicated_objects, modify_placement, 
                          place_updated):
    '''Allow for different query action depending on what has changed and whether play has modify flag'''
    section_place_params  = generate_section_placement(module, manager_url, mgr_username, mgr_password,
                                                       validate_certs, section_placement, existing_config_lookup,
                                                       duplicated_objects, dfw_section_params['display_name'], place_updated)
    if place_updated and modify_placement and not updated:
        dfw_section_params['rules'] = [] # action=revise doesn't support rules, so emptying rules if no changes
        return '?action=revise&' + section_place_params
    elif updated:
        if dfw_section_params['rules'] and place_updated and modify_placement:
            return '?action=revise_with_rules&' + section_place_params
        else:
            return '?action=update_with_rules'
    else:
        if dfw_section_params['rules']:
            return '?action=create_with_rules&' + section_place_params
        else:
            if section_place_params != '':
                return '?' + section_place_params
            else:
                return ''

def check_rules_have_unique_names(module, dfw_section_params):
    '''Check whether all supplied FW rules have unique display names to allow module to be idempotent'''
    rule_names = set()
    duplicateed_rule_names = set()
    for rule in dfw_section_params['rules']:
        try:
            if rule['display_name'] in rule_names:
                duplicateed_rule_names.add(rule['display_name'])
            else:
                rule_names.add(rule['display_name'])
        except KeyError:
            module.fail_json(msg='Rule does not have a display_name param set [%s].' +
                                 '\nEnsure all rules have unique names withiin each section' % (rule))
    if duplicateed_rule_names:
        module.fail_json(msg='The following rules have duplicate display_names [%s]. ' +
                             '\nEnsure all rules have unique names withiin each section' % (', '.join(duplicateed_rule_names)))

def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'),
                        host_credential=dict(required=False, type='dict',
                            username=dict(required=False, type='str'),
                            password=dict(required=False, type='str', no_log=True),
                            thumbprint=dict(required=False, type='str', no_log=True)),
                        applied_tos=dict(required=False, type='list', default=list([]),
                            target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                            target_type=dict(required=True, type='str', choices=['LogicalPort', 'LogicalSwitch', 
                                                                                'NSGroup', 'LogicalRouter'])),
                        description=dict(required=False, type='str'),
                        rules=dict(required=True, type='list',
                            display_name=dict(required=True, type='str'), # API does not enforce, but added to all later management.
                            description=dict(required=False, type='str'),
                            action=dict(required=True, type='str', choices=['ALLOW', 'DROP', 'REJECT', 'REDIRECT', 
                                                                            'DO_NOT_REDIRECT']),
                            applied_tos=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str', choices=['LogicalPort', 'LogicalSwitch', 
                                                                                    'NSGroup'])),
                            context_profiles=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str', choices=['NSProfile'])),
                            destinations=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str', choices=['IPSet', 'LogicalPort', 
                                                                                    'LogicalSwitch', 'NSGroup'])),
                            direction=dict(required=False, type='str', choices=['IN', 'OUT', 'IN_OUT']),
                            disabled=dict(required=False, type='bool'),
                            ip_protocol=dict(required=False, type='str', choices=['IPV4', 'IPV6', 'IPV4_IPV6']),
                            logged=dict(required=False, type='bool'),
                            notes=dict(required=False, type='str'),
                            resource_type=dict(required=False, type='str', choices=['FirewallRule']),
                            rule_tag=dict(required=False, type='str'),
                            services=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=False, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=False, type='str', choices=['NSService', 'NSServiceGroup']),
                                service=dict(required=False, type='list', default=[],
                                    alg=dict(required=False, type='str', choices=['ORACLE_TNS', 'FTP', 'SUN_RPC_TCP', 
                                                                                  'SUN_RPC_UDP', 'MS_RPC_TCP', 
                                                                                  'MS_RPC_UDP', 'NBNS_BROADCAST', 
                                                                                  'NBDG_BROADCAST', 'TFTP']),
                                    destination_ports=dict(required=False, type='list'),
                                    icmp_code=dict(required=False, type='int'),
                                    icmp_type=dict(required=False, type='int'),
                                    l4_protocol=dict(required=False, type='str'),
                                    protocol=dict(required=False, type='str', choices=['ICMPv4', 'ICMPv6']),
                                    protocol_number=dict(required=False, type='int'),
                                    resource_type=dict(required=True, type='str', 
                                                       choices=['ALGTypeNSService', 'IPProtocolNSService', 
                                                                'L4PortSetNSService', 'ICMPTypeNSService', 
                                                                'IGMPTypeNSService']),
                                    source_ports=dict(required=False, type='list')),),
                            sources=dict(required=False, type='list', default=[],
                                target_display_name=dict(required=True, type='str'), # Will insert target_id a runtime
                                target_type=dict(required=True, type='str', choices=['IPSet', 'LogicalPort', 
                                                                                     'LogicalSwitch', 'NSGroup'])),),
                        resource_type=dict(required=False, choices=['FirewallSectionRuleList'], 
                                           default='FirewallSectionRuleList'),
                        section_placement=dict(required=False, type='dict',
                            operation=dict(required=True, type='str', choices=['insert_top', 'insert_bottom', 
                                                                               'insert_after', 'insert_before']),
                            display_name=dict(required=True, type='str')),
                        section_type=dict(required=False, choices=['LAYER3'], default='LAYER2, LAYER3'),
                        state=dict(required=True, choices=['present', 'absent']),
                        stateful=dict(required=True, type='bool'),
                        tags=dict(required=False, type='list',
                                tag=dict(required=False, type='str'),
                                scope=dict(required=False, type='str')),
                        modify_placement=dict(required=False, type='bool', default=False))
                        
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    dfw_section_params = get_dfw_section_params(module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    section_placement = dfw_section_params.pop('section_placement', None)
    modify_placement = dfw_section_params.pop('modify_placement', None)

    check_rules_have_unique_names(module, dfw_section_params)
    insert_lists_if_missing(dfw_section_params, ['applied_tos', 'tags'])

    section_dict = get_dfw_section_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, 
                                                     display_name)
    section_id, revision = None, None
    if section_dict:
        section_id = section_dict['id']
        revision = section_dict['_revision']
    
    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        add_backwards_compatibilty(module, manager_url, mgr_username, mgr_password, validate_certs, dfw_section_params)
        existing_config_lookup, duplicated_objects = collect_all_existing_config(module, manager_url, mgr_username, 
                                                                                 mgr_password, validate_certs)
        update_param_list_with_ids(module, dfw_section_params['applied_tos'], existing_config_lookup, duplicated_objects,
                                 'DFW section ' + dfw_section_params['display_name'], 'applied_tos')
        update_rules_list_with_ids(module, dfw_section_params['rules'], existing_config_lookup, 
                                   ['applied_tos', 'context_profiles', 'destinations', 'services', 'sources'],
                                   duplicated_objects)
        updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, 
                                   dfw_section_params)
        place_updated = check_if_section_moved(module, manager_url, mgr_username, mgr_password, validate_certs, 
                                               section_placement, existing_config_lookup, dfw_section_params,
                                               modify_placement)   
        query_params = generate_query_params(module, dfw_section_params, manager_url, mgr_username, mgr_password, 
                                            validate_certs, section_placement, updated, existing_config_lookup, 
                                            duplicated_objects, modify_placement, place_updated)
        updated = updated or place_updated
        if not dfw_section_params['rules']:
            dfw_section_params.pop('rules', None)
        if not updated:            
            request_data = json.dumps(dfw_section_params)
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(request_data), id='12345')
            try:
                if section_id:
                    module.exit_json(changed=False, id=section_id, 
                                     message="Firewall Section with display_name [%s] already exist and has not changed." % 
                                     module.params['display_name'])
                (rc, resp) = request(manager_url+ '/firewall/sections%s' % query_params, data=request_data, 
                                     headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, 
                                     validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to add node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))
            #TODO consult VMWare NSBU on invokation rates and build dynamic delay between calls.
            time.sleep(5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), 
                             message="Firewall Section with display_name %s created succcessfully." % 
                             module.params['display_name'])
        else:
            id = section_id
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(dfw_section_params)), id=id)
            dfw_section_params['_revision'] = revision # update current revision   
            request_data = json.dumps(dfw_section_params)
            try:
                (rc, resp) = request(manager_url+ '/firewall/sections/%s%s' % (id, query_params), data=request_data, 
                                     headers=headers, method='POST', url_username=mgr_username, url_password=mgr_password, 
                                     validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg="Failed to update Section with display_name %s. Request body [%s]. Error[%s]." % 
                                 (module.params['display_name'], request_data, to_native(err)))
            time.sleep(5)
            module.exit_json(changed=True, id=resp["id"], body= str(resp), 
                             message="Firewall Section with display_name [%s] updated with params [%s]." % 
                             (module.params['display_name'], query_params))

    elif state == 'absent':
        id = section_id
        if id is None:
            module.exit_json(changed=False, msg='No Firewall Section exist with display name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(dfw_section_params)), id=id)
        try:
            (rc, resp) = request(manager_url + "/firewall/sections/%s?cascade=true" % id, method='DELETE',
                                  url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete Firewall Section with id %s. Error[%s]." % (id, to_native(err)))
        time.sleep(5)
        module.exit_json(changed=True, id=id, message="NG Group with node id %s deleted." % id)


if __name__ == '__main__':
    main()
