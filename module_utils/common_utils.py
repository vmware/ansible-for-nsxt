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
        module.fail_json(msg='Error while retrieving existing IP address. Error [%s]' % to_native(err))
    if resp.__contains__(attribute_name):
        return resp[attribute_name]
    return None