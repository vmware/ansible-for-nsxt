#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015 VMware, Inc. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

__author__ = 'VJ49'

from pyVmomi import vim, vmodl
from pyVim import connect
from pyVim.connect import SmartConnect, SmartConnectNoSSL

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

from ansible.module_utils.basic import *

import logging
logger = logging.getLogger('Vcenter Moids')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

""" 
    VIM_TYPES = {'datacenter': [vim.Datacenter],
             'dvs_name': [vim.dvs.VmwareDistributedVirtualSwitch],
             'datastore_name': [vim.Datastore],
             'resourcepool_name': [vim.ResourcePool],
             'portgroup_name': [vim.dvs.DistributedVirtualPortgroup, vim.Network]} """


def get_all_objs(module,content, vimtype):
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder,
                                                         vimtype, True)
    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name})
    return obj


def find_object_by_name(module,content, object_name):
    try:
    	if(object_name == module.params['datacenter']):
    	    vmware_objects = get_all_objs(module,content,[vim.Datacenter])
    	elif (object_name == module.params['cluster']):
    	    vmware_objects = get_all_objs(module,content,[vim.ComputeResource])
    	elif (object_name == module.params['datastore']):
            vmware_objects = get_all_objs(module,content,[vim.Datastore])
    	elif (object_name == module.params['portgroup1'] or module.params['portgroup2'] or module.params['portgroup3'] or module.params['portgroup4'] ):
            vmware_objects = get_all_objs(module,content,[vim.dvs.DistributedVirtualPortgroup, vim.Network])
 
    	for object in vmware_objects:
            if object.name == object_name:
            	logger.info('object: %s',object.name)
            	return object
    	return None
    except Exception as err:
       module.fail_json(changed=False, msg= "Error Occured while Finding the Object by name. Error is %s" %(to_native(err)))





def main():
  argument_spec = vmware_argument_spec()
 
  argument_spec.update(
        dict(hostname= dict(required=True, type='str'),
            username=dict(required=True, type='str'),
            password=dict(required=True, type='str'),
            datacenter=dict(required=True, type='str'),
            cluster=dict(required=True, type='str'),
            datastore=dict(required=True,type='str'),
            portgroup1= dict(required=True,type='str'),
            portgroup2= dict(required=True, type='str'),
            portgroup3=dict(required=True, type='str'),
            portgroup4=dict(required=True, type='str')))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  try:
	logger.info("Trying to connect to VCENTER SERVER . . .")
	si = SmartConnectNoSSL(host=module.params['hostname'],
						   user=module.params['username'],
						   pwd=module.params['password'],
						   port=443)
        logger.info("Connected to VCENTER SERVER !")
  except IOError, e:
	#pass
	#atexit.register(Disconnect, si)
	logger.info("Connection failed {0}")
        module.fail_json(chagned=False, msg="Failed to connect vCenter")
  content = si.RetrieveContent()

  datacenter= module.params['datacenter']
  cluster= module.params['cluster']
  datastore= module.params['datastore']
  portgroup1= module.params['portgroup1']
  portgroup2= module.params['portgroup2']
  portgroup3= module.params['portgroup3']
  portgroup4= module.params['portgroup4']

  try:
  	datacenter_mo = find_object_by_name(module,content, datacenter)
  	datacenter_moid =  datacenter_mo._moId
  	cluster_mo = find_object_by_name(module,content, cluster)
  	cluster_moid = cluster_mo._moId
  	datastore_mo = find_object_by_name(module,content, datastore)
  	datastore_moid = datastore_mo._moId
  	portgroup1_mo = find_object_by_name(module,content, portgroup1)
  	portgroup1_moid = portgroup1_mo._moId
  	portgroup2_mo = find_object_by_name(module,content, portgroup2)
  	portgroup2_moid = portgroup2_mo._moId
  	portgroup3_mo = find_object_by_name(module,content, portgroup3)
 	portgroup3_moid = portgroup3_mo._moId
  	portgroup4_mo = find_object_by_name(module,content, portgroup4)
  	portgroup4_moid = portgroup4_mo._moId
        #module.exit_json(changed=True, msg= "success")
  	module.exit_json(changed=True,datacenter_id=datacenter_moid,cluster_id=cluster_moid,datastore_id=datastore_moid, portgroup1_id=portgroup1_moid,portgroup2_id=portgroup2_moid,portgroup3_id=portgroup3_moid,portgroup4_id=portgroup4_moid,
                            msg= "datacenter:%s, cluster:%s, datastore:%s, portgroup1:%s, portgroup2:%s, portgroup3:%s, portgroup4:%s" %(datacenter_moid, cluster_moid, datastore_moid, portgroup1_moid, portgroup2_moid, portgroup3_moid, portgroup4_moid))
  except Exception as err:
	module.fail_json(changed=False, msg="Error Occured:%s" %err) 
    
if __name__ == '__main__':
    main()

