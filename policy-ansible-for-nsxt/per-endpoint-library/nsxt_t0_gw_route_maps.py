#!/usr/bin/python
#
# Copyright (c) 2008-2020 Virtustream Corporation
# All Rights Reserved
#
# This software contains the intellectual property of Virtustream Corporation
# or is licensed to Virtustream Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of Virtustream.

from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.nsxt_utils import get_params, get_nsxt_object, create_nsxt_object, delete_nsxt_object
from ansible.module_utils.rest_functions import Rest
from ansible.module_utils.vmware_nsxt import vmware_argument_spec

__metaclass__ = type
__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_t0_route_map
short_description: 'Creates a T-0 Route-Map via the Policy API endpoint.'
description: "Deploys a T-0 Route-Map as specified by the deployment config using the Policy API endpoint."
version_added: ''
author: 'Juan Artiles <juan.artiles@virtustream.com>'
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
        type: 'tr
    display_name:
        description: 'Identifier to use when displaying entity in logs or GUI. '
        required: true
        type: str
    description:
        description: 'Description of this resource'
        required: false
        type: str
    _revision:
        description: 'The _revision property describes the current revision of the resource. To prevent clients from 
                      overwriting each other's changes, PUT operations must include the current _revision of the 
                      resource, which clients should obtain by issuing a GET operation. If the _revision provided in 
                      a PUT request is missing or stale, the operation will be rejected.'
        required: false
        type: int
    tier0:
        description: 'Name of the Tier-0 Router'
        required: true
        type: 'str'
    entries:
        description: 'Ordered list of route map entries.'
        required: false
        type: 'array of RouteMapEntry'
    tags:
        description: Opaque identifiers meaningful to the API user
        type: array of Tag
        required: false
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'. 'present' is used to create or update resource.
                     'absent' is used to delete resource."
        required: true
    
'''

EXAMPLES = '''
---
- ---
- name: Create T0 GW Route Maps
  nsxt_t0_gw_route_maps:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-TEST-ROUTE-MAP"
    description: "T0 route-map deployment test"
    entries: 
      - prefix_list_matches:
          - "PLIST-RFC-1918"
        action: PERMIT
    tier0: TEST-TO"
    state: present
'''

RETURN = '''# '''


def get_data(module, error_on_missing=False, **session):
    get_status, response = get_nsxt_object(**session)
    data = response.get("data")
    if not get_status and error_on_missing:
        if response["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=response["response"]
            )

    return data


def create_data(module, **session):
    get_status, response = create_nsxt_object(**session)
    if not get_status:

        if response["type"] == "error":
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                error=response["response"]
            )
    return response["data"]


def delete_data(module, **session):
    delete_status, response = delete_nsxt_object(**session)
    if not delete_status:
        if response["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=response["response"].status_code,
                text=response["response"].text,
                url=response["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=response["response"]
            )
    return response["data"]


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         tier0=dict(required=True, type='str'),
                         entries=dict(required=True, type='list'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy(), remove_args=['tier0'])
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    tier0 = module.params['tier0']
    display_name = module.params["display_name"]
    validate_certs = module.params["validate_certs"]
    api_version = '/policy/api/v1'
    endpoint = '/infra/tier-0s/{tier0}/route-maps'.format(tier0=tier0)
    resource_type = "Tier0RouteMap"
    entries = module.params['entries']

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   module=module,
                   client=client,
                   api_version=api_version
                   )

    # Check T0 exists
    tier0_endpoint = '/infra/tier-0s'
    get_data(endpoint=tier0_endpoint,
             name=tier0,
             error_on_missing=True,
             **session)

    # Check if each Entry exists
    for entry in entries:

        if entry.get("prefix_list_matches"):

            prefix_list_endpoint = '/infra/tier-0s/{tier0}/prefix-lists'.format(tier0=tier0)

            prefix_list_matches = []
            for prefix in entry.get("prefix_list_matches"):

                prefix_list_data = get_data(endpoint=prefix_list_endpoint,
                                            name=prefix,
                                            **session)
                if prefix_list_data:
                    prefix_list_matches.append("/infra/tier-0s/{}/prefix-lists/{}".format(tier0, prefix))

            node_params["entries"][entries.index(entry)]["prefix_list_matches"] = prefix_list_matches

        elif entry.get("community_list_matches"):

            community_list_api_version = '/policy/api/v1'
            community_list_endpoint = '/infra/tier-0s/{tier0}/community-lists'.format(tier0=tier0)

            community_list_matches = []
            for community in entry.get("community_list_matches"):

                community_list_status, community_list_data = get_nsxt_object(mgr_hostname, mgr_username, mgr_password,
                                                                             community_list_api_version,
                                                                             community_list_endpoint, community)

                if community_list_status:
                    community_list_matches.append("/infra/tier-0s/{}/community-lists/{}".format(tier0, community))
                elif community_list_data["type"] == "error":
                    module.fail_json(
                        msg="Failed to locate Community-List {}".format(tier0),
                        status_code=community_list_data["response"].status_code,
                        text=community_list_data["response"].text,
                        url=community_list_data["response"].url
                    )
                elif community_list_data["type"] == "exception":
                    module.fail_json(
                        msg="Failed to locate Community-List {}".format(tier0),
                        error=community_list_data["response"]
                    )

            node_params["entries"][entries.index(entry)]["community_list_matches"] = community_list_matches

    # check if the route map exists
    current_route_maps = get_data(endpoint=endpoint,
                                  name=display_name,
                                  **session)

    # Handle Object
    if state == "present":

        if current_route_maps:
            module.exit_json(changed=False,
                             message="{resource_type} {display_name} already exists".format(
                                 resource_type=resource_type,
                                 display_name=display_name)
                             )

        request = create_data(endpoint=endpoint,
                              resource_type=resource_type,
                              payload=node_params,
                              add_name=True,
                              update=True,
                              **session)
    elif state == "absent":

        if not current_route_maps:
            module.exit_json(changed=False, message="{} with name {} not found".format(resource_type,
                                                                                       display_name))
        request = delete_data(endpoint=endpoint,
                              name=display_name,
                              **session
                              )

    module.exit_json(changed=True,
                     msg="{resource_type} {display_name} is now {state}"
                     .format(resource_type=resource_type, display_name=display_name,
                             state=state),
                     response=request
                     )

if __name__ == "__main__":
    main()

