from __future__ import absolute_import, division, print_function
import time
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import get_attribute_from_endpoint, get_upgrade_orchestrator_node


UPGRADE_URL = '/upgrade/plan?action=upgrade'

def get_upgrade_status(module, manager_url, mgr_username, mgr_password, validate_certs):
  '''
  Get the current status of upgrade at the start.
  Doesn't upgrade if any component is in progress 
  or system is already upgraded.
  '''

  endpoint = "/upgrade/upgrade-unit-groups?sync=true"
  call_get_sync(manager_url, endpoint, mgr_username, mgr_password, validate_certs)
  upgrade_status = get_attribute_from_endpoint(module, manager_url, '/upgrade/status-summary',
                    mgr_username, mgr_password, validate_certs, 'overall_upgrade_status', 
                    False)
  
  return upgrade_status

def call_get_sync(managerUrl, endpoint, mgrUsername, mgrPassword, validateCerts):
    request(managerUrl + endpoint, method='GET', url_username=mgrUsername, url_password=mgrPassword,
            validate_certs=validateCerts, ignore_errors=True)

def execute_upgrade(module, manager_url, mgr_username, mgr_password, validate_certs):
   headers = dict(Accept="application/json")
   headers['Content-Type'] = 'application/json'

   while True:
      try:
        (rc, resp) = request(manager_url+ UPGRADE_URL,
                        data='', headers=headers, method='POST', 
                        url_username=mgr_username, url_password=mgr_password, 
                        validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(msg="Failed while upgrading component")
      time.sleep(10)

      upgrade_status = ''

      while True:       
         upgrade_status = get_upgrade_status(module, manager_url, mgr_username,
                                          mgr_password, validate_certs)
         if upgrade_status == 'SUCCESS' or upgrade_status == 'FAILED' or upgrade_status == 'PAUSED':
            break
         time.sleep(10)
         
      if upgrade_status == 'SUCCESS' or upgrade_status == 'FAILED':
         return upgrade_status
      

def trigger_upgrade_reverse_order(module, mgr_hostname, mgr_username, mgr_password, validate_certs):

    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    mgr_hostname = get_upgrade_orchestrator_node(module, mgr_hostname, mgr_username, 
                                            mgr_password, headers, validate_certs)
    
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    upgrade_status = get_upgrade_status(module, manager_url, mgr_username,
                                          mgr_password, validate_certs)


    if upgrade_status == 'IN_PROGRESS' or upgrade_status == 'PAUSING':
      module.fail_json(msg='Upgrade is in state: %s, can\'t continue' % upgrade_status)

    elif upgrade_status == 'SUCCESS':
      module.exit_json(changed=False, message='Upgrade state is SUCCESS. No need to'
                    ' continue.')
      
    elif upgrade_status == 'NOT_STARTED' or upgrade_status == 'PAUSED':
       upgrade_result = execute_upgrade(module, manager_url, mgr_username, mgr_password, validate_certs)

       if upgrade_result == 'FAILED':
           module.fail_json(msg='Failed to upgrade system')
          
    module.exit_json(changed=True, message='System has been upgraded successfully!!!')