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
module: nsxt_cluster_certificate
short_description: 'Imports a certificate and applies it to the VIP address'
description: "Deploys a T-0 Gateway as specified by the deployment config using the Policy API endpoint."
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
    dhcp_config_paths:
        description: 'DHCP configuration for Segments connected to Tier-1. DHCP service is enabled in relay mode.'
        required: false
        type: 'array of strings'
    disable_firewall: 
        description: 'Disable or enable gateway fiewall.'
        required: false
        type: 'boolean'
        default: False
    enable_standby_relocation: 
        description: 'Flag to enable standby service router relocation. Standby relocation is not enabled until edge 
                     cluster is configured for Tier1.'
        required: false
        type: 'boolean'
        default: False
    failover_mode:
        description: 'Determines the behavior when a Tier-1 instance in ACTIVE-STANDBY high-availability mode restarts 
                     after a failure. If set to PREEMPTIVE, the preferred node will take over, even if it causes 
                     another 
                     failure. If set to NON_PREEMPTIVE, then the instance that restarted will remain secondary. This 
                     property must not be populated unless the ha_mode property is set to ACTIVE_STANDBY'
        required: false
        choices:
            - PREEMPTIVE
            - NON_PREEMPTIVE
        default: NON_PREEMPTIVE 
    ipv6_profile_paths:
        description: 'IPv6 NDRA and DAD profiles configuration on Tier1. Either or both NDRA and/or DAD profiles can be 
                      configured.'
        required: false
        type: 'array of strings'
    route_advertisement_rules:
        description: 'Route advertisement rules and filtering'
        required: false
        type: array of RouteAdvertisementRule
    route_advertisement_types:
        description: 'Enable different types of route advertisements. When not specified, routes to IPSec VPN 
                     local-endpoint subnets (TIER1_IPSEC_LOCAL_ENDPOINT) are automatically advertised.'
        required: false
        type: array of Tier1RouteAdvertisentTypes
    tier0:
        description: 'Specify Tier-1 connectivity to Tier-0 instance.'
        required: false
        type: string
    type:
        description: 'Tier1 connectivity type for reference. Property value is not validated with Tier1 configuration.
                     ROUTED: Tier1 is connected to Tier0 gateway and routing is enabled. ISOLATED: Tier1 is not 
                     connected to any Tier0 gateway. NATTED: Tier1 is in ROUTED type with NAT configured locally.'
        required: false
        type: string
        choices:
            - ROUTED
            - ISOLATED
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
  ---
- name: Create T1 GW
  nsxt_cluster_certificate:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T1-TEST"
    description: "T1 deployment test"
    tier0: "T0-TEST"
    route_advertisement_types:
      - TIER1_STATIC_ROUTES
      - TIER1_CONNECTED
      - TIER1_NAT
      - TIER1_LB_VIP
      - TIER1_LB_SNAT
      - TIER1_DNS_FORWARDER_IP
      - TIER1_IPSEC_LOCAL_ENDPOINT
    state: present
'''

RETURN = '''# '''


def get_data(module, **session):
    get_status, certificates = get_nsxt_object(**session)
    if not get_status:
        if certificates["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=certificates["response"].status_code,
                text=certificates["response"].text,
                url=certificates["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=certificates["response"]
            )
    return certificates["data"]


def create_data(module, **session):
    get_status, certificates = create_nsxt_object(**session)
    if not get_status:

        if certificates["type"] == "error":
            if certificates["response"].status_code != 400 and certificates.get("data", {}).get("error_message") \
                    != "Certificate already exists.":
                module.fail_json(
                    msg="Failed to Create {}".format(session['endpoint']),
                    status_code=certificates["response"].status_code,
                    text=certificates["response"].text,
                    url=certificates["response"].url
                )
        else:
            module.fail_json(
                msg="Failed to Create {}".format(session['endpoint']),
                error=certificates["response"]
            )
    return certificates["data"]


def delete_data(module, **session):
    delete_status, certificates = delete_nsxt_object(**session)
    if not delete_status:
        if certificates["type"] == "error":
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                status_code=certificates["response"].status_code,
                text=certificates["response"].text,
                url=certificates["response"].url
            )
        else:
            module.fail_json(
                msg="Failed to get {}".format(session['endpoint']),
                error=certificates["response"]
            )
    return certificates["data"]


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname=dict(required=True, type='str'),
                         username=dict(required=True, type='str', no_log=True),
                         password=dict(required=True, type='str', no_log=True),
                         display_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         _revision=dict(required=False, type='int'),
                         key_algo=dict(required=False, type='str'),
                         passphrase=dict(required=False, type='str'),
                         pem_encoded=dict(required=True, type='str'),
                         private_key=dict(required=False, type='str'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         validate_certs=dict(required=False, type='bool', default=True),
                         )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    node_params = get_params(args=module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params["validate_certs"]
    api_version = '/api/v1'
    display_name = module.params['display_name']
    endpoint = '/trust-management/certificates'
    resource_type = "TrustObjectData"
    certificate_id = None
    response = None

    client = Rest(validate_certs=validate_certs)
    client.authenticate(username=mgr_username, password=mgr_password)

    session = dict(mgr_hostname=mgr_hostname,
                   api_version=api_version,
                   module=module,
                   client=client,
                   )

    # check if certificate exists
    current_certificates = get_data(endpoint=endpoint,
                                    **session)

    if state == "present":

        for certificate in current_certificates.get("results"):
            if certificate["pem_encoded"] == node_params["pem_encoded"]:
                certificate_id = certificate["id"]

        if not certificate_id:
            import_certificate = endpoint + "?action=import"
            create_certificate = create_data(endpoint=import_certificate,
                                             resource_type=resource_type,
                                             payload=node_params,
                                             add_name=False,
                                             **session)

            certificate_id = create_certificate["id"]

        apply_certificate_endpoint = "/cluster/api-certificate?action=set_cluster_certificate&certificate_id={}" \
            .format(certificate_id)
        response = create_data(endpoint=apply_certificate_endpoint,
                               resource_type=resource_type,
                               payload=None,
                               add_name=False,
                               **session)
    elif state == "absent":
        existing_certs = 0
        for certificate in current_certificates.get("results"):
            if certificate["display_name"] == node_params["display_name"] and not certificate["used_by"]:
                delete_data(endpoint=endpoint + "/{}".format(certificate["id"]),
                            **session)
                existing_certs += 1
        response = "Removed {} Certificates with Name {}".format(existing_certs, display_name)

    module.exit_json(changed=True,
                     msg="{resource_type} {display_name} is now {state}"
                     .format(resource_type=resource_type, display_name=display_name,
                             state=state),
                     response=response
                     )


if __name__ == "__main__":
    main()
