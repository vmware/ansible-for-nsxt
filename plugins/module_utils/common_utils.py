#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import time
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import request
from ansible.module_utils._text import to_native
import ipaddress

def check_if_valid_ip(address):
    '''
    params:
    - ip_address: IP Address in string format
    result:
    checks if the IP address is valid or not.
    '''
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv4Address):
            ip_octets = address.split('.')
            valid_ip_octets = [int(ip_octet) for ip_octet in ip_octets]
            valid_ip_octets = [ip_octet for ip_octet in valid_ip_octets if ip_octet >= 0 and ip_octet<=255]
            return len(ip_octets) == 4 and len(valid_ip_octets) == 4
        elif isinstance(ip, ipaddress.IPv6Address):
            return True
    except ValueError:
        return False

def traverse_and_retrieve_value(object , attribute_list):
    '''
    params:
    - object: Object where value is to be searched from attribute list
    - attribute_list: List to be used for searching attribute value
    '''
    if object is None:
        return None
    for attribute in attribute_list:
        if object.__contains__(attribute):
            object = object[attribute]
        else:
            raise Exception('AttributeError: Attribute value \"%s\" not found '
                            'while traversing.' % attribute)
    return object

def get_attribute_from_endpoint(module, manager_url, endpoint, mgr_username, 
                                mgr_password, validate_certs, attribute_name,
                                fail_on_error=True):
    '''
    params:
    - endpoint: API endpoint.
    - attribute_name: Name of attribute whose value is required
    result:
    attribute value of the attribute name provided.
    '''
    try:
        (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, 
                      validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        if fail_on_error:
            module.fail_json(msg='Error while retrieving'
                             ' %s. Error [%s]' % (attribute_name, to_native(err)))
        else:
            pass
    if resp.__contains__(attribute_name):
        return resp[attribute_name]
    return None

def get_id_from_display_name_results(module, manager_url, endpoint, mgr_username, 
                                     mgr_password, validate_certs, 
                                     search_attribute_list, return_attribute_list, 
                                     display_name, fail_module=True):
    '''
    params:
    - endpoint: API endpoint.
    - search_attribute_list: List of name attribute the depth to be searched in the result object
    - return_attribute_list: List of name attribute the depth to be returned in the result object
    - display_name: The name to be matched
    - id_attribute: id_attribute whose value is to be returned
    '''
    try:
        (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, 
                      validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error while converting the passed name to'
                             ' ID. Error [%s]' % to_native(err))
    try:
        for result in resp['results']:
            if traverse_and_retrieve_value(result, search_attribute_list) == display_name:
                return traverse_and_retrieve_value(result, return_attribute_list)
    except Exception as err:
        module.fail_json(msg='Error while getting id from display name. Error [%s]' % to_native(err))
    if fail_module:
        module.fail_json(msg='No id exist with display name %s' % display_name)
    else:
        return None

def wait_for_operation_to_execute(manager_url, endpoint, mgr_username, 
                                  mgr_password, validate_certs, attribute_list,
                                  desired_attribute_values, undesired_attribute_values,
                                  time_out=10800):
    '''
    params:
    - endpoint: API endpoint.
    - attribute_list: The attribute whose value should become the desired attribute value
    - desired_attribute_value: The desired attribute value
    
    Function will wait till the attribute value derived from going deep to attribute list
    becomes equal to desired_attribute_value.
    '''
    operation_time = 0
    while True:
        try:
            (rc, resp) = request(manager_url + endpoint, headers=dict(Accept='application/json'),
                                 url_username=mgr_username, url_password=mgr_password, 
                                 validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            pass
        try:
            retrieved_value = traverse_and_retrieve_value(resp, attribute_list)
            if retrieved_value in desired_attribute_values:
                return None
            if retrieved_value in undesired_attribute_values:
                raise Exception(resp)
        except Exception as err:
            pass
        time.sleep(10)
        operation_time = operation_time + 10
        if operation_time > time_out:
            raise Exception('Operation timed out.')

def clean_and_get_params(args=None, extra_args_to_remove=[]):
    '''
    params:
    - args: All the arguments to be removed
    '''
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    args_to_remove.extend(extra_args_to_remove)
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_upgrade_orchestrator_node(module, mgr_hostname, mgr_username, mgr_password,
                               headers, validate_certs):
    '''
    params:
    - mgr_hostname: Any one of the manager node in manager cluster

    Returns the upgrade orchestrator node  
    '''
    try:
        (rc, resp) = request('https://%s/api/v1/node/services/install-upgrade' % mgr_hostname,
               headers=headers, url_username=mgr_username, url_password=mgr_password, 
                             validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(changed=True, msg='Error getting ip address of the upgrade'
                        ' orchestrator node. Error: {}'.format(err))
    return resp['service_properties']['enabled_on'];

def deep_same(a, b):
    '''
    params:
    - a: A python literal, list, or dict
    - b: A python literal, list, or dict

    Compares a and b, including their subcomponents. Lists are compared
    ignoring order.

    Returns True if a and b are the same, False if they are not.
    '''
    if isinstance(a, dict) and isinstance(b, dict):
        for k, v in a.items():
            if k not in b:
                return False
            if not deep_same(v, b[k]):
                return False
        return True

    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        # Compare the two lists as sets. The standard set() type cannot be used
        # because lists and dicts are not hashable.
        for subitem_a in a:
            match_found = False
            for subitem_b in b:
                if deep_same(subitem_a, subitem_b):
                    match_found = True
                    break
            if not match_found:
                return False
        return True

    return a == b

def check_for_update(existing_params, resource_params):
    '''
    params:
    - existing_params: A dict representing the existing state
    - resource_params: A dict representing the expected future state

    Compares the existing_params with resource_params and returns
    True if an update is needed.

    Returns True if the params should trigger an update.
    '''
    # A resource exists in reality but not in ansible. No need to update.
    if not existing_params:
        return False

    # An update is needed if they are not the same.
    return not deep_same(existing_params, resource_params)

def format_for_ansible_diff(before, after):
    '''
    params:
    - before: An object representing the existing state
    - after: An object representing the expected future state

    If the before and after objects implement MutableMapping (e.g. dict), they
    will be automatically serialized to json by ansible. If not, they should be
    run through json.dumps() beforehand.

    Returns a dict formatted for ansible diff
    '''
    return {'before': before, 'after': after}

def diff_for_update(existing_params, resource_params, strict_keys=[], lazy_keys=[]):
    '''
    params:
    - existing_params: A dict representing the current resource state
    - resource_params: A dict representing the desired (unapplied) state
    - strict_keys: Always compare these top-level keys. If strict_keys is
                   empty, it will default to all keys in new_params.
    - lazy_keys: Compare these keys only if they are defined in both sets of
                 params. These may overlap with strict_keys.


    Returns a tuple of (is_updated, diff)
    '''
    # Generate representative "before" and "after" objects for diff output with
    # only the relevant keys.
    old_params = existing_params or {}
    new_params = resource_params or {}
    before = {}
    after = {}
    keys = strict_keys if strict_keys else list(new_params.keys())
    for key in set(keys + lazy_keys):
        if key in lazy_keys and \
           not (key in old_params and key in new_params):
            continue
        before[key] = old_params.get(key)
        after[key] = new_params.get(key)

    # Compute diff using before and after objects, rather than existing_params
    # and new_params, so that the diff output matches the is_updated state.
    # This allows support for lazy keys without showing them in the diff when
    # they only exist in one set of params.
    is_updated = check_for_update(before, after) if existing_params else False
    diff = format_for_ansible_diff(before, after)
    return (is_updated, diff)
