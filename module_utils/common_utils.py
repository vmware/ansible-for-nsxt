#!/usr/bin/env python

# Copyright 2018 VMware, Inc.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from ansible.module_utils.vmware_nsxt import request

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

def traverse_and_retrieve_value(module, object , attribute_list):
    '''
    params:
    - object: Object where value is to be searched from attribute list
    - attribute_list: List to be used for searching attribute value
    '''
    for attribute in attribute_list:
        if object.__contains__(attribute):
            object = object[attribute]
        else:
            module.fail_json(msg='Error while  traversing and retrieving value. Attribute named %s was not found.'% attribute)
    return object

def get_attribute_from_endpoint(module, manager_url, endpoint, mgr_username, mgr_password, validate_certs, attribute_name):
    '''
    params:
    - endpoint: API endpoint.
    - attribute_name: Name of attribute whose value is required
    result:
    attribute value of the attribute name provided.
    '''
    try:
        (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error while retrieving %s. Error [%s]' % (attribute_name, to_native(err)))
    if resp.__contains__(attribute_name):
        return resp[attribute_name]
    return None

def get_id_from_display_name_results(module, manager_url, endpoint, mgr_username, mgr_password, validate_certs, search_attribute_list, return_attribute_list, display_name):
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
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error while converting the passed name to ID. Error [%s]' % to_native(err))
    for result in resp['results']:
        if traverse_and_retrieve_value(module, result, search_attribute_list) == display_name:
            return traverse_and_retrieve_value(module, result, return_attribute_list)
    module.fail_json(msg='No id exist with display name %s' % display_name)