#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: nsxt_policy_group_member_types
short_description: List Policy Group Member Types for a specific Policy Grooup ID
description: Returns member types data for a policy group.

version_added: "X.Y"
author: Ed McGuigan <ed.mcguigan@palmbeachschools.org>
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
    ca_path:
        description: Path to the CA bundle to be used to verify host's SSL
                     certificate
        type: str
    nsx_cert_path:
        description: Path to the certificate created for the Principal
                     Identity using which the CRUD operations should be
                     performed
        type: str
    nsx_key_path:
        description:
            - Path to the certificate key created for the Principal Identity
              using which the CRUD operations should be performed
            - Must be specified if nsx_cert_path is specified
        type: str        
        
    global_infra:
        description: Flag set to True when targeting a Global NSX Manager (Federation)
        required: false
        type: bool
        
    domain_id:
        description: The domain string value to be used in the query, usually "default"
        required: false
        type: string
        default: default
    group_id:
        description: All of these URLs are specific to a single group and an ID is needed
       
'''
EXAMPLES = '''
- name: List Group Members - VMs
  nsxt_policy_group_members:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    domain_id: "default"
    group_id: <group_id>   
'''

RETURN = '''# '''
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.policy_communicator import PolicyCommunicator
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import build_url_query_dict, build_url_query_string, do_objects_get
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import GLOBAL_POLICY_URL, LOCAL_POLICY_URL
from ansible.module_utils._text import to_native

def main():
    # Fetch the specification of the absolute basic arguments needed to connect to the NSX Manager
    argument_spec = PolicyCommunicator.get_vmware_argument_spec()
    # The URL will need to be specified as being non-global or global and we will need a domain
    URL_path_spec = dict(
        global_infra=dict(type='bool', required=False, default=False),
        domain_id=dict(type='str', required=False, default='default'),
        group_id=dict(type='str', required=False, default='default')
        )
    # Combine the base URL and URL path spec
    argument_spec.update(URL_path_spec)
    # Some code to validate the arguments provided with the invocation of the module
    # in a playbook versus the defined argument spec and to get the require AnsibleModule object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    domain_id = module.params['domain_id']
    group_id = module.params['group_id'] 
    if module.params['global_infra']:
        url_path_root = GLOBAL_POLICY_URL
    else:
        url_path_root = LOCAL_POLICY_URL
    
    manager_url = 'https://{}{}/domains/{}/groups/{}/member-types'.format(mgr_hostname,url_path_root,domain_id,group_id)

    changed = False
    '''
    With member types we have no cursor or paging and all data should be retrieved with a single
    request
    '''
    try:
        (rc, resp) = request(manager_url, headers=dict(Accept='application/json'),
                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error retrieving groups. Error [%s]' % (to_native(err)))    

    module.exit_json(changed=changed, **resp)
    
if __name__ == '__main__':
    main()