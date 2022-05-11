#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: nsxt_policy_domain_info
short_description: List Policy Domains
description: Returns paginated list of policy domains
             Policy Domains are associated with policy groups and DFW Policies to determine the sites
             where those objects are used ( applied to ). On a local manager, there is only the default domain
               

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
        
        
    page_size:
        description: if there is a desire to fetch the data in chunks rather than all at
                     once, an integer specifying the maximum number of objects to fetch
        required: false
        type: integer
        
    cursor:
        description: when a page_size is specified, the returned data includes a "cursor" that
                     must be provided in a subsequent call in order to carry on where the prior call
                     left off. User would need to capture the cursor value from one call and provide it
                     in the next call
        required: false
        type: string
        
    include_mark_for_delete_objects:
        description: Show groups marked for deletion
        required: false
        type: bool
        default: False
        
    included_fields:
        description: Show groups marked for deletion
        required: Comma separated list of fields that should be included in query result
        type: string
        default: False
                
    sort_ascending:
        description: Used to reverse sort order by setting it to False
        required: false
        type: bool
        default: True
        
    sort_by:
        description: Field to sort on
        required: false
        type: string
        default: 

'''

EXAMPLES = '''
- name: List Policy Groups
  nsxt_policy_group_facts:
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
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import GLOBAL_POLICY_URL, LOCAL_POLICY_URL

def main():
    # Fetch the specification of the absolute basic arguments needed to connect to the NSX Manager
    argument_spec = PolicyCommunicator.get_vmware_argument_spec()
    # The URL will need to be specified as being non-global or global and we will need a domain
    URL_path_spec = dict(
        global_infra=dict(type='bool', required=False, default=False)
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
                            include_mark_for_delete_objects=dict(type='bool', required=False),
                            included_fields=dict(type='str', required=False),
                            sort_ascending=dict(type='bool', required=False, default=True),
                            sort_by=dict(type='str', required=False),
                            page_size=dict(type='int'   , required=False ),
                            cursor=dict(type='str', required=False )
                            )
    # Combine the base URL, URL path spec and URL query argument specs
    URL_path_spec.update(URL_query_spec)
    argument_spec.update(URL_path_spec)
    # Some code to validate the arguments provided with the invocation of the module
    # in a playbook versus the defined argument spec.
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    validate_certs = module.params['validate_certs']
    if module.params['global_infra']:
        url_path_root = GLOBAL_POLICY_URL
    else:
        url_path_root = LOCAL_POLICY_URL
    # Need to build up a query string
    url_query_string = build_url_query_string( build_url_query_dict(module.params, URL_query_spec.keys() ) )
    manager_url = 'https://{}{}/domains'.format(mgr_hostname,url_path_root,url_query_string)

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