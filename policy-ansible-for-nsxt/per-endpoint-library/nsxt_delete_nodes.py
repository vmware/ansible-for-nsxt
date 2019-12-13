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
from ansible.module_utils.nsxt_utils import get_nsxt_object, delete_nsxt_object
from ansible.module_utils.rest_functions import Rest
from ansible.module_utils.vmware_nsxt import vmware_argument_spec

__metaclass__ = type
__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_delete_disconnected_nodes
short_description: 'Deletes nodes from NSXT'
description: "remove a list of ESXinodes from NSXT"
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
        type: 'str
    esx_hosts_to_remove:
        description: 'List of hosts to remove'
        required: true
        type: array of string
    unprepare_host:
        description: 'remove the NSXT configuration from the host'
        required: false
        type: bool
    force_delete:
        description: 'force the removal of the hosts'
        required: false
        type: bool
'''

EXAMPLES = '''
- name: Delete Transport nodes from NSXT
  nsxt_delete_nodes:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    esx_hosts_to_remove:
      - test123
'''

RETURN = '''# '''


def get_data(module, **session):
    get_status, nodes = get_nsxt_object(**session)

    if not get_status:
        if nodes["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=nodes["response"].status_code,
                text=nodes["response"].text,
                url=nodes["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=nodes["response"]
            )
    return nodes["data"]


def delete_data(module, **session):
    delete_status, nodes = delete_nsxt_object(**session)
    if not delete_status:
        if nodes["type"] == "error":
            module.fail_json(
                msg="Failed to delete {}".format(session['endpoint']),
                status_code=nodes["response"].status_code,
                text=nodes["response"].text,
                url=nodes["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=nodes["response"]
            )
    return nodes["data"]


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         esx_hosts_to_remove=dict(required=True, type='list'),
                         unprepare_hosts=dict(required=False, type='bool'),
                         force_delete=dict(required=False, type='bool'),
                         validate_certs=dict(required=False, type='bool', default=True)
                         )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    esx_hosts_to_remove = module.params['esx_hosts_to_remove']
    validate_certs = module.params["validate_certs"]
    unprepare_hosts = "unprepare_host=false"
    force_delete = "force=true"
    api_version = '/api/v1'
    endpoint = '/transport-nodes'
    nodes_to_delete = []
    params = ""
    nodes_removed = 0

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   api_version=api_version,
                   module=module,
                   client=client,
                   )

    if module.params['unprepare_hosts'] or module.params['force_delete']:
        params += "?"
    if not module.params['unprepare_hosts']:
        params += unprepare_hosts
    if module.params["force_delete"]:
        if params != "?":
            params += "&{}".format(force_delete)
        else:
            params += force_delete

    # Get Transport-Nodes state
    transport_nodes_state = get_data(endpoint=endpoint,
                                     **session
                                     )

    for node in transport_nodes_state["results"]:
        if node.get("node_deployment_info").get("display_name") in esx_hosts_to_remove or \
                node.get("node_deployment_info").get("fqdn") in esx_hosts_to_remove:
            nodes_to_delete.append(node["node_id"])

    # Delete Transport Nodes
    for node in nodes_to_delete:
        delete_data(endpoint=endpoint,
                    name=node + params,
                    **session
                    )
        nodes_removed += 1

    if nodes_removed:
        module.exit_json(changed=True,
                         debug_out="{} Nodes have been successfully deleted".format(nodes_removed),
                         url=api_version + endpoint + "<node_id>" + params
                         )
    else:
        module.exit_json(changed=False,
                         debug_out="{} Nodes have to be removed".format(nodes_removed),
                         url=api_version + endpoint + "<node_id>" + params
                         )


if __name__ == "__main__":
    main()
