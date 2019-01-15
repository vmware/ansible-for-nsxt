#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016 VMware, Inc.  All rights reserved.

# Portions Copyright (c) 2015 VMware, Inc. All rights reserved.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import paramiko
import string
import pyVim.task


from pyVmomi import vim, vmodl
from pyVim import connect
from pyVim.connect import SmartConnect, SmartConnectNoSSL

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native

import logging
logger = logging.getLogger('nsxt_selfsigned_cert')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(funcName)s: %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

headers = dict(Accept="application/json")
headers['Content-Type'] = 'application/json'

create_cert = """openssl req -newkey rsa:2048 -x509 -nodes -keyout nsx.key -new -out nsx.crt -subj /CN=$NSX_MANAGER_COMMONNAME \
 -reqexts SAN -extensions SAN -config <(cat /opt/chaperone-ansible/roles/nsxt/defaults/nsx-cert.cnf \
 <(printf "[SAN]\nsubjectAltName=DNS:$NSX_MANAGER_COMMONNAME,IP:$NSX_MANAGER_IP_ADDRESS")) -sha256 -days 365"""


verify_cert = """openssl x509 -in nsx.crt -text -noout"""


search_pemcode = """awk '{printf "%s\\n", $0}' /home/vmware/nsx.crt"""

search_private_key= """awk '{printf "%s\\n", $0}' /home/vmware/nsx.key"""

register_cert = """curl --insecure -u admin:'admin_pw' -X POST 'https://NSX-Manager-IP-Address/api/v1/node/services/http?action=apply_certificate&certificate_id=CERTIFICATE-ID' """

def Self_Signed_Cert(pi,module,request_data,NSX_MANAGER_COMMONNAME,NSX_MANAGER_IP_ADDRESS,NSX_USER,NSX_PASSWORD,validate_certs,cert_name,manager_url):
    #create_cert1 = string.replace(create_cert, "$NSX_MANAGER_IP_ADDRESS",NSX_MANAGER_IP_ADDRESS)
    create_cert1 = string.replace(create_cert, "$NSX_MANAGER_IP_ADDRESS",NSX_MANAGER_IP_ADDRESS)
    create_cert2 = string.replace(create_cert1, "$NSX_MANAGER_COMMONNAME",NSX_MANAGER_COMMONNAME) 
    register_cert1 = string.replace(register_cert, "admin_pw" , NSX_PASSWORD)
    register_cert2 = string.replace(register_cert1, "NSX-Manager-IP-Address", NSX_MANAGER_IP_ADDRESS)
    
    try:
        (sshin1, sshout1, ssherr1) = pi.exec_command(create_cert2)          
        output = sshout1.read()
        logger.info(output)
		
        (sshin2, sshout2, ssherr2) = pi.exec_command(verify_cert)
        logger.info(sshout2.read())
        (sshin3, sshout3, ssherr3) = pi.exec_command(search_pemcode)
        (sshin4, sshout4, ssherr4) = pi.exec_command(search_private_key)

        request_data["pem_encoded"] = sshout3.read()
        request_data["private_key"] = sshout4.read()
        request_data["display_name"] = cert_name
		
        logger.info(cert_name)
        cert_id = get_certificate_id_with_name(module,manager_url, NSX_USER, NSX_PASSWORD, validate_certs,cert_name )
        import_cert = import_certificate(module,manager_url,NSX_USER,NSX_PASSWORD, validate_certs, request_data,cert_id)
        cert_id = get_certificate_id_with_name(module,manager_url, NSX_USER, NSX_PASSWORD, validate_certs,cert_name )
        logger.info(cert_id)
        register_cert3 = string.replace(register_cert2, "CERTIFICATE-ID", cert_id)
        (sshin5,sshout5,ssherr5)=  pi.exec_command(register_cert3)
        logger.info(sshout5.read())
        module.exit_json(changed= True, msg= "Successuflly Created the SelfSigned Certificate with %s" %(cert_id))
        

    except Exception as err:
        logger.info("Error Occured: {}".format(err))
        module.fail_json(changed = False, msg = "Error Occured:%s" %(err))
        
def import_certificate(module,manager_url, NSX_USER, NSX_PASSWORD, validate_certs,request_data,cert_id):
    request_obj = json.dumps(request_data)
    if cert_id is None:
            try:
                if cert_id:
                    print("Certificate Already Exists with that name %s" %(cert_id))                    
                (rc, resp) = request(manager_url+ '/trust-management/certificates?action=import', data=request_obj, headers=headers, method='POST',
                                url_username=NSX_USER, url_password=NSX_PASSWORD, validate_certs=validate_certs, ignore_errors=True)
                logger.info("Successfully Imported the Certificate")
            except Exception as err:
                module.fail_json(changed=False,msg="Failed to Import the Certificate.Error:%s." % (to_native(err)))




def get_certificate_id_with_name(module,manager_url, NSX_USER, NSX_PASSWORD, validate_certs,cert_name ):
    
    try:
      (rc, resp) = request(manager_url+'/trust-management/certificates', headers=dict(Accept='application/json'),
                      url_username=NSX_USER, url_password=NSX_PASSWORD, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
       print err
    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == cert_name:
            return result['id']
    
	

def main():
    logger.info("entered into main")
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname = dict(required=True, type= 'str'),
			 username = dict(required=True, type= 'str'),
			 password = dict(required=True, type= 'str'),
                       NSX_MANAGER_IP_ADDRESS =dict(required=True, type= 'str'),
                       NSX_MANAGER_COMMONNAME =dict(required=True, type= 'str'),
                       NSX_PASSWORD=dict(required=True, type='str'),
					   NSX_USER=dict(required=True, type='str'),
		       validate_certs= dict(required=True, type= 'bool'),
			    cert_name = dict(required=True, type= 'str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)  
    pi = None
    request_data ={}
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    NSX_MANAGER_COMMONNAME = module.params["NSX_MANAGER_COMMONNAME"]
    NSX_MANAGER_IP_ADDRESS = module.params["NSX_MANAGER_IP_ADDRESS"]
    NSX_USER = module.params["NSX_USER"]
    NSX_PASSWORD = module.params["NSX_PASSWORD"]
    cert_name = module.params["cert_name"]
    validate_certs = module.params["validate_certs"]   
    manager_url = 'https://{}/api/v1'.format(NSX_MANAGER_IP_ADDRESS)
    try:
       	
	pi = paramiko.client.SSHClient()
	pi.load_system_host_keys()
	pi.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
	pi.connect(module.params["hostname"], 22, module.params["username"],module.params["password"])
        logger.info('Esxi host connection succeed...........')
        Self_Signed_Cert(pi,module,request_data,NSX_MANAGER_COMMONNAME,NSX_MANAGER_IP_ADDRESS,NSX_USER,NSX_PASSWORD,validate_certs,cert_name,manager_url)        
    except Exception as err:
	logger.info("Error Occured1: {}".format(err))
        module.fail_json(changed=False, msg= "Error Occured : %s" %(err))
	
      
if __name__ == "__main__":
        main()