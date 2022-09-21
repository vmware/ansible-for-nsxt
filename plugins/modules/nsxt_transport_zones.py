#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2018 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
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
module: nsxt_transport_zones
short_description: Create a Transport Zone
description: Creates a new transport zone. The required parameters are display_name
and tz_type (OVERLAY_BACKED or VLAN_BACKED). The optional parameters are
description and resource_type. 

version_added: "2.7"
author: Rahul Raghuvanshi
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
    description:
        description: Description of this resource
        required: false
    display_name:
        description: Identifier to use when displaying entity in logs or GUI
        required: true
        type: str
    is_default:
        description: Only one transport zone can be the default one for a given transport
                     zone type. APIs that need transport zone can choose to use the default 
                     transport zone if a transport zone is not given by the user.
        required: false
        type: boolean
    nested_nsx:
        description: The flag only need to be set in nested NSX environment.
        required: false
        type: boolean
    resource_type:
        description: Should be set to the value PolicyTransportZone
        required: false
    state:
        choices:
        - present
        - absent
        description: "State can be either 'present' or 'absent'. 
                      'present' is used to create or update resource. 
                      'absent' is used to delete resource."
        required: true
    tz_type:
        description: Valid values are OVERLAY_BACKED , VLAN_BACKED
        required: true
        type: str
    tags:
        description: Opaque identifier meaningful to API user
        required: false
        type: Array of Tag
    transport_zone_profile_ids:
        description: Identifiers of the transport zone profiles associated with this 
                     TransportZone.
        required: false
        type: array of TransportZoneProfileTypeIdEntry
    uplink_teaming_policy_names:
        description: The names of switching uplink teaming policies that all transport nodes
                     in this transport zone must support. An exception will be thrown if a 
                     transport node within the transport zone does not support a named teaming
                     policy. The user will need to first ensure all trasnport nodes support the 
                     desired named teaming policy before assigning it to the transport zone. 
                     If the field is not specified, the host switch's default teaming policy will 
                     be used.
        required: false
        type: list

    enforcementpoint_id:
        description: The EnforcementPoint ID where the TZ is located.
                     Required if transport_zone_id is specified.
        default: default
        type: str
    site_id:
        description: The site ID where the EnforcementPoint is located.
                     Required if transport_zone_id is specified.
        default: default
        type: str

'''

EXAMPLES = '''
- name: Create transport zone
  nsxt_transport_zones:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    resource_type: "PolicyTransportZone"
    display_name: "TZ1"
    description: "NSX configured Test Transport Zone"
    tz_type: "VLAN_BACKED"
    state: "present"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import TRANSPORT_ZONE_URL
from ansible.module_utils._text import to_native


def get_transport_zone_params(args=None):
  args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
  for key in args_to_remove:
    args.pop(key, None)
  for key, value in args.copy().items():
    if value == None:
      args.pop(key, None)
  return args


def get_transport_zone_baseURL(transport_zone_params):
  if transport_zone_params.__contains__('display_name'):
    site_id = transport_zone_params.pop("site_id", 'default')
    enforcementpoint_id = transport_zone_params.pop("enforcementpoint_id", 'default')
    transport_zone_base_url = (TRANSPORT_ZONE_URL.format(site_id, enforcementpoint_id))
    return transport_zone_base_url


def get_transport_zones(module, manager_url, mgr_username, mgr_password, validate_certs, transport_zone_base_url):
  try:
    (rc, resp) = request(manager_url + transport_zone_base_url, method='GET',
                         headers=dict(Accept='application/json'),
                         url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                         ignore_errors=True)
  except Exception as err:
    module.fail_json(msg='Error accessing transport zones. Error [%s]' % (to_native(err)))
  return resp


def get_tz_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name,transport_zone_base_url):
  transport_zones = get_transport_zones(module, manager_url, mgr_username, mgr_password, validate_certs, transport_zone_base_url)
  for transport_zone in transport_zones['results']:
    if transport_zone.__contains__('display_name') and transport_zone['display_name'] == display_name:
      return transport_zone
  return None


def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, transport_zone_params, transport_zone_base_url):
  existing_transport_zone = get_tz_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs,
                                                     transport_zone_params['display_name'], transport_zone_base_url)
  if existing_transport_zone is None:
    return False
  if existing_transport_zone.__contains__('is_default') and transport_zone_params.__contains__('is_default') and \
          existing_transport_zone['is_default'] != transport_zone_params['is_default']:
    return True
  if not existing_transport_zone.__contains__('description') and transport_zone_params.__contains__('description'):
    return True
  if existing_transport_zone.__contains__('description') and not transport_zone_params.__contains__('description'):
    return True
  if existing_transport_zone.__contains__('description') and transport_zone_params.__contains__('description') and \
          existing_transport_zone['description'] != transport_zone_params['description']:
    return True
  if not existing_transport_zone.__contains__('uplink_teaming_policy_names') and transport_zone_params.__contains__(
          'uplink_teaming_policy_names'):
    return True
  if existing_transport_zone.__contains__('uplink_teaming_policy_names') and not transport_zone_params.__contains__(
          'uplink_teaming_policy_names'):
    return True
  if existing_transport_zone.__contains__('uplink_teaming_policy_names') and transport_zone_params.__contains__(
          'uplink_teaming_policy_names') and \
          existing_transport_zone['uplink_teaming_policy_names'] != transport_zone_params[
    'uplink_teaming_policy_names']:
    return True
  return False


def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                       tz_type=dict(required=True, choice=['VLAN_BACKED', 'OVERLAY_BACKED']),
                       nested_nsx=dict(required=False, type='bool'),
                       uplink_teaming_policy_names=dict(required=False, type='list'),
                       transport_zone_profile_paths=dict(required=False, type='list'),
                       is_default=dict(required=False, type='bool'),
                       resource_type=dict(required=False, type='str'),
                       description=dict(required=False, type='str'),
                       tags=dict(required=False, type='list'),
                       state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  transport_zone_params = get_transport_zone_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/policy/api/v1'.format(mgr_hostname)
  transport_zone_base_url = get_transport_zone_baseURL(transport_zone_params)
  zone_dict = get_tz_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name,
                                       transport_zone_base_url)
  zone_id, revision = None, None
  if zone_dict:
    zone_id = zone_dict['id']
    revision = zone_dict['_revision']

  if state == 'present':
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs,
                               transport_zone_params, transport_zone_base_url)

    if not updated:
      # add the node
      if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(transport_zone_params)), id='12345')
      request_data = json.dumps(transport_zone_params)
      try:
        if zone_id:
          module.exit_json(changed=False, id=zone_id,
                           message="Transport zone with display_name %s already exist." % module.params[
                             'display_name'])
        (rc, resp) = request(manager_url + transport_zone_base_url + '/%s' % module.params['display_name'],
                             data=request_data, headers=headers, method='PUT',
                             url_username=mgr_username, url_password=mgr_password,
                             validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(
          msg="Failed to add transport zone. Request body [%s]. Error[%s]." % (request_data, to_native(err)))
      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body=str(resp),
                       message="Transport zone with display name %s created. " % (module.params['display_name']))
    else:
      if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(transport_zone_params)), id=zone_id)

      transport_zone_params['_revision'] = revision  # update current revision
      request_data = json.dumps(transport_zone_params)
      id = zone_id
      try:
        (rc, resp) = request(manager_url + transport_zone_base_url + '/%s' % id, data=request_data,
                             headers=headers, method='PATCH',
                             url_username=mgr_username, url_password=mgr_password,
                             validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(msg="Failed to update transport zone with id %s. Request body [%s]. Error[%s]." % (
          id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["id"], body=str(resp),
                       message="Transport zone with zone id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = zone_id
    if id is None:
      module.exit_json(changed=False, msg='No transport zone exist with display name %s' % display_name)
    if module.check_mode:
      module.exit_json(changed=True, debug_out=str(json.dumps(transport_zone_params)), id=id)
    try:
      (rc, resp) = request(manager_url + transport_zone_base_url + "/%s" % id, method='DELETE',
                           url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
      module.fail_json(msg="Failed to delete transport zone with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Transport zone with zone id %s deleted." % id)


if __name__ == '__main__':
  main()