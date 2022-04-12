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

def check_if_valid_ip(ip_address):
    '''
    params:
    - ip_address: IP Address in string format
    result:
    checks if the IP address is valid or not.
    '''
    try:
        ip_octets = ip_address.split('.')
        valid_ip_octets = [int(ip_octet) for ip_octet in ip_octets]
        valid_ip_octets = [ip_octet for ip_octet in valid_ip_octets if ip_octet >= 0 and ip_octet<=255]
        return len(ip_octets) == 4 and len(valid_ip_octets) == 4
    except:
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

def build_url_query_string(parm_dict):
    '''
    This function just builds up a URL query string of the form:
    
    ?parm1=val1&bool1=True&bool2=False
    
    '''
    qstring = ""
    qlist = list()
    for dkey in parm_dict.keys():
        if parm_dict[dkey] is not None:
            if type(parm_dict[dkey]) is bool:
                qlist.append("{}={}".format(dkey,str(parm_dict[dkey])))
            else:
                qlist.append("{}={}".format(dkey,parm_dict[dkey]))
    if qlist:
        qstring = "?{}".format("&".join(qlist))
    return qstring

def build_url_query_dict(params,query_keys):
    '''
    The params dict in many of the modules contains a lot of keys. Some keys pertain
    to the URL path, some to things like credentials, certificates etc.
    We only want to process the ones relating to the query section of a URL. So the whole set of params is passed here
    along with a filter defined as the set of keys pertaining to the query section.
    The fields are filtered down
    '''
    query_params_dict = { k:v for (k,v) in params.items() if k in query_keys }
    return query_params_dict

def do_objects_get(module,manager_url,module_params,
                        headers=dict(Accept='application/json'), validate_certs=True, ignore_errors=False):
    
    mgr_username = module_params["username"]
    mgr_password = module_params["password"]
    nsx_cert_path = module_params["nsx_cert_path"]
    nsx_key_path = module_params["nsx_key_path"]
    # If a cursor was provided, or a page size then we are making a single call
    # If we test for a key that doesn't exist and trap
    mp_keys = module_params.keys()
    if ('cursor' in mp_keys and module_params['cursor'] is not None ) or ('page_size' in mp_keys  and module_params['page_size'] is not None):
        try:
            (rc, resp) = request(manager_url, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
        except Exception as err:
            module.fail_json(msg='Error retrieving groups. Error [%s]' % (to_native(err)))
    else:
        # No cursor parameter was provided so all data is being fetched
        # This might still require multiple calls if there are more objects than are allowed to be returned in a single call
        still_more_groups = True
        cursor = None
        all_group_data = dict()
    #        all_group_data["results"] = list()
        while still_more_groups:
            if cursor:
                # Add the cursor to the URL
                url_with_cursor = "{}&cursor={}".format(manager_url,cursor)
            else:
                url_with_cursor = manager_url
            try:
                (rc, resp) = request(url_with_cursor, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
            except Exception as err:
                module.fail_json(msg='Error retrieving groups. Error [%s]' % (to_native(err)))
            if not "cursor" in resp:
                still_more_groups = False
            else:
                cursor = resp["cursor"]
            # Add new results to existing results
            # If this is the first add, all the other data besides the "results" needs to be added
            if not "results" in all_group_data:
                all_group_data = resp
            else:
                # JUst add the additionally fetched results
                all_group_data["results"] += resp["results"]
        resp = all_group_data
    return resp
    