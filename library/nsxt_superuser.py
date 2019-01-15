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
logger = logging.getLogger('nsxt_superuser')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(funcName)s: %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

create_cert = 'openssl req -newkey rsa:2048 -x509 -nodes -keyout '"'$NSX_SUPERUSER_KEY_FILE'"' -new -out '"'$NSX_SUPERUSER_CERT_FILE'"' -subj /CN=pks-nsx-t-superuser -extensions client_server_ssl -config <(cat /etc/ssl/openssl.cnf <(printf "[client_server_ssl]\nextendedKeyUsage = clientAuth\n")) -sha256 -days 730'

search_pemcode = """awk '{printf "%s\\n", $0}' $NSX_SUPERUSER_CERT_FILE"""

cert_reg = """cat <<END
  {
    "display_name": "$PI_NAME",
    "pem_encoded": pemcode
  }
END"""   

register_cert_curl ="""curl -k -X POST 'https://${NSX_MANAGER}/api/v1/trust-management/certificates?action=import' -u '$NSX_USER:$NSX_PASSWORD' -H 'content-type: application/json' -d '$register_cert'"""
					   
pi_request="""cat <<END
  {
    "display_name": "$PI_NAME",
    "name": "$PI_NAME",
    "permission_group": "superusers",
    "certificate_id": "$CERTIFICATE_ID",
    "node_id": "$NODE_ID"
  }
END"""

pi_request_curl = """curl -k -X POST \
  "https://${NSX_MANAGER}/api/v1/trust-management/principal-identities" \
  -u "$NSX_USER:$NSX_PASSWORD" \
  -H 'content-type: application/json' \
  -d  '$pi_request' """


verify = """curl -k -X GET \
"https://${NSX_MANAGER}/api/v1/trust-management/principal-identities" \
--cert $(pwd)/"$NSX_SUPERUSER_CERT_FILE" \
--key $(pwd)/"$NSX_SUPERUSER_KEY_FILE" """


def SuperUser(module,pi,NSX_MANAGER,NSX_USER,NSX_PASSWORD,PI_NAME,validate_certs,NSX_SUPERUSER_CERT_FILE,NSX_SUPERUSER_KEY_FILE,NODE_ID,manager_url):
    create_cert1 = string.replace(create_cert, "$NSX_SUPERUSER_KEY_FILE",NSX_SUPERUSER_KEY_FILE)
    create_cert2 = string.replace(create_cert1, "$NSX_SUPERUSER_CERT_FILE",NSX_SUPERUSER_CERT_FILE)
    search_pemcode1 = string.replace(search_pemcode, "$NSX_SUPERUSER_CERT_FILE",NSX_SUPERUSER_CERT_FILE)
    logger.info(search_pemcode1)    
    register_cert_curl1 = string.replace(register_cert_curl, "${NSX_MANAGER}",NSX_MANAGER)
    register_cert_curl2 = string.replace(register_cert_curl1, "$NSX_USER",NSX_USER)
    register_cert_curl3 = string.replace(register_cert_curl2, "$NSX_PASSWORD",NSX_PASSWORD)  
    try:
        (sshin1, sshout1, ssherr1) = pi.exec_command(create_cert2)
        logger.info(create_cert2)
        logger.info(sshout1.read())
		
        (sshin,sshout,ssherr) = pi.exec_command(search_pemcode1)
        pem_code_out = repr(sshout.read())
        pem_code_out = pem_code_out.replace("'",'"')
        logger.info("Pemcode:{}".format(pem_code_out))
		
        register_cert1 = string.replace(cert_reg, "$PI_NAME", PI_NAME)
        register_cert1 = string.replace(register_cert1, "pemcode", pem_code_out)
		
        (sshin2, sshout2, ssherr2) = pi.exec_command(register_cert1)
        register_cert_out=sshout2.read()
        logger.info(register_cert_out)
        logger.info(ssherr2)
        register_cert_curl4 = string.replace(register_cert_curl3, "$register_cert",register_cert_out)
        logger.info(register_cert_curl4)
		
        (sshin3, sshout3, ssherr3) = pi.exec_command(register_cert_curl4)
        output = sshout3.read()
        logger.info(output)
        cert_id = get_certificate_id_with_name(manager_url, NSX_USER, NSX_PASSWORD, validate_certs,PI_NAME )
        logger.info(cert_id)
		
        pi_request1 = string.replace(pi_request,"$PI_NAME",PI_NAME)
        pi_request2 = string.replace(pi_request1,"$CERTIFICATE_ID", cert_id)
        pi_request3 = string.replace(pi_request2, "$NODE_ID",NODE_ID)
        (sshin4,sshout4,ssherr4) = pi.exec_command(pi_request3)
        pi_request_out = sshout4.read()
        logger.info(pi_request_out)
      
        pi_request_curl1 = string.replace(pi_request_curl, "$NSX_USER", NSX_USER)
        pi_request_curl2 = string.replace(pi_request_curl1, "${NSX_MANAGER}", NSX_MANAGER)
        pi_request_curl3 = string.replace(pi_request_curl2, "$NSX_PASSWORD", NSX_PASSWORD)
        pi_request_curl4 = string.replace(pi_request_curl3, "$pi_request", pi_request_out)
        logger.info(pi_request_curl4)
        (sshin5, sshout5,ssherr5) = pi.exec_command(pi_request_curl4)
        logger.info(sshout5.read())
        
        verify1 = string.replace(verify, "${NSX_MANAGER}", NSX_MANAGER)
        verify2 = string.replace(verify1, "$NSX_SUPERUSER_CERT_FILE", NSX_SUPERUSER_CERT_FILE)
        verify3 = string.replace(verify2,"$NSX_SUPERUSER_KEY_FILE" , NSX_SUPERUSER_KEY_FILE)

        (sshin6,sshout6,ssherr6) = pi.exec_command(verify3)
        logger.info(sshout6.read())
        module.exit_json(changed=True,msg ="Successfully Created Super User with name %s having id %s" %(PI_NAME,cert_id))

    except Exception as err:
        logger.info("Error occured at Super User Creation: {}".format(err))
        module.fail_json(chagned=False, msg = "Error at Super User Creation:{}".format(err))
        

def get_certificate_id_with_name(manager_url, NSX_USER, NSX_PASSWORD, validate_certs,PI_NAME ):
    try:
        (rc, resp) = request(manager_url+'/trust-management/certificates', headers=dict(Accept='application/json'),
                      url_username=NSX_USER, url_password=NSX_PASSWORD, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        logger.info(err)
	module.fail_json(msg= "Error at getting Certificate")
    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == PI_NAME:
            return result['id']
    
	

def main():
    logger.info("entered into main")
    argument_spec = vmware_argument_spec()
    argument_spec.update(hostname = dict(required=True, type= 'str'),
			 username = dict(required=True, type= 'str'),
			 password = dict(required=True, type= 'str'),
                       NSX_MANAGER =dict(required=True, type= 'str'),
                       NSX_USER =dict(required=True, type= 'str'),
                       NSX_PASSWORD=dict(required=True, type='str'),
		       validate_certs= dict(required=True, type= 'bool'),
			        PI_NAME = dict(required=True, type= 'str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)  
    logger.info("after module")       
    NSX_MANAGER = module.params["NSX_MANAGER"]
    NSX_USER = module.params["NSX_USER"]
    NSX_PASSWORD = module.params["NSX_PASSWORD"]
    PI_NAME = module.params["PI_NAME"]
    validate_certs = module.params["validate_certs"]
    NSX_SUPERUSER_CERT_FILE = "/home/vmware/pks-nsx-t-superuser.crt"
    NSX_SUPERUSER_KEY_FILE = "/home/vmware/pks-nsx-t-superuser.key"
    NODE_ID = "$(cat /proc/sys/kernel/random/uuid)"
    manager_url = 'https://{}/api/v1'.format(NSX_MANAGER)      

    pi = None
    try:
        logger.info("hii")	
	pi = paramiko.client.SSHClient()
	pi.load_system_host_keys()
	pi.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
	pi.connect(module.params["hostname"], 22,module.params["username"],module.params["password"])
	logger.info('Esxi host connection succeed...........')
    	SuperUser(module,pi,NSX_MANAGER,NSX_USER,NSX_PASSWORD,PI_NAME,validate_certs,NSX_SUPERUSER_CERT_FILE,NSX_SUPERUSER_KEY_FILE,NODE_ID,manager_url)
    except Exception as err:
        logger.info("Error occured: {}".format(err))
        module.fail_json(changed=False, msg = "Error occured:{}".format(err))
	
      
if __name__ == "__main__":
        main()