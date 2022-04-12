#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: nsxt_policy_security_policy_rules_stats
short_description: List Policy Security Policy rule stats
description: Returns statistics for a security policy rule

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
        
    policy_id:
        description: ID for a specific security policy
        required: true
        type: string
        default: NONE
        
    rule_id:
        description: id for the rule
        required: true
        type: string
        default: NONE
        
    enforcement_point_path:
        description: enforcement point
        required: False
        type: string
        default: NONE

'''

EXAMPLES = '''
- name: List Policy Security Policies
  nsxt_policy_security_policy_facts:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
'''

RETURN = '''# '''
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.policy_communicator import PolicyCommunicator
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import build_url_query_dict, build_url_query_string, do_objects_get
from ansible.module_utils._text import to_native

def main():
    # Fetch the specification of the absolute basic arguments needed to connect to the NSX Manager
    argument_spec = PolicyCommunicator.get_vmware_argument_spec()
    # The URL will need to be specified as being non-global or global and we will need a domain
    URL_path_spec = dict(
        global_infra=dict(type='bool', required=False, default=False),
        domain_id=dict(type='str', required=False, default='default'),
        policy_id=dict(type='str', required=True),
        rule_id=dict(type='str', required=True)
        )
    '''
    Now add the arguments relating to query field in the URL for this GET method
    All the options from the API are offered, including paging. Not sure when a user
    might want to use paging but the option is provided.
    If no paging specification is provided, I need to make sure that 
    all data is retrieved, looking for a returned cursor in the response
    indicating that there is more data to fetch.
    
    NOTE: I suspect that the member_types filter parameter is not actually valid
    for a Policy Group where membership is described by a series of expressions
    and this may be an error when converting from MP ( Management Plane ) Groups
    to Policy Groups
    '''
    URL_query_spec = dict(
                            enforcement_point_path=dict(type='str', required=False)
                            )
    # Combine the base URL, URL path spec and URL query argument specs
    URL_path_spec.update(URL_query_spec)
    argument_spec.update(URL_path_spec)
    # Some code to validate the arguments provided with the invocation of the module
    # in a playbook versus the defined argument spec.
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    validate_certs = module.params['validate_certs']
    domain_id = module.params['domain_id']
    policy_id = module.params['policy_id']
    rule_id = module.params['rule_id']
    if module.params['global_infra']:
        infra_string = 'global-infra'
    else:
        infra_string = 'infra'
    
    # Need to build up a query string
    url_query_string = build_url_query_string( build_url_query_dict(module.params, URL_query_spec.keys() ) )
    manager_url = 'https://{}/policy/api/v1/{}/domains/{}/security-policies/{}/rules/{}/statistics{}'.format(mgr_hostname,infra_string,domain_id,policy_id,rule_id,url_query_string)
    print("**** Manager URL {}".format(manager_url))

    changed = False
    '''
    We potentially need to loop to fetch all data the code here will be the same for
    any object we are doing a GET on, not just Policy Groups, so I have put it into a function and put the function
    in the common_utils package.
    '''
    resp = do_objects_get(module,manager_url,module.params,
                        headers=dict(Accept='application/json'),validate_certs=validate_certs, ignore_errors=True)     

    module.exit_json(changed=changed, **resp)
if __name__ == '__main__':
    main()