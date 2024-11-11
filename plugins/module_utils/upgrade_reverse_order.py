from __future__ import absolute_import, division, print_function
import json, time
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import get_attribute_from_endpoint, get_upgrade_orchestrator_node
from ansible.module_utils._text import to_native
from collections import OrderedDict

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
    
def check_component_upgrade_completion(index, module, manager_url, mgr_username, mgr_password, validate_certs):
   no_of_checks = 0
   while True:
        try:
            component_status_list = get_attribute_from_endpoint(module, manager_url, 
                            '/upgrade/status-summary', mgr_username, mgr_password,
                            validate_certs, 'component_status', False)
        except Exception as err:
            no_of_checks += 1
            if(no_of_checks == 5):
                module.fail_json(msg="Failed to fetch /upgrade/status-summary. Error[%s]." % to_native(err))

        no_of_checks = 0

        current_component_status = component_status_list[index]

        if current_component_status['status'] == 'SUCCESS' or current_component_status['status'] == 'FAILED' or current_component_status['status'] == 'PAUSED':
            return current_component_status['status']

        time.sleep(10)



def execute_upgrade_in_sequence(upgrade_component_sequence_list, number_of_component_completed_upgrade, module, manager_url, mgr_username, mgr_password, validate_certs):
   headers = dict(Accept="application/json")
   headers['Content-Type'] = 'application/json'
   for index, (key, value) in enumerate(upgrade_component_sequence_list):
      component = key
      component_upgrade_url = value
      component_index_value = index + number_of_component_completed_upgrade


      if index != 0 :
         while True:
            upgrade_status = get_upgrade_status(module, manager_url, mgr_username,
                                          mgr_password, validate_certs)
            
            if upgrade_status == 'PAUSED' or upgrade_status == 'SUCCESS':
               break
            time.sleep(10)

      
      try:
        (rc, resp) = request(manager_url+ component_upgrade_url,
                        data='', headers=headers, method='POST', 
                        url_username=mgr_username, url_password=mgr_password, 
                        validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(msg="Failed while upgrading component:[%s]. Error[%s]."
                          % (component, to_native(err)))
      time.sleep(10)

      completion_status = check_component_upgrade_completion(component_index_value, module, manager_url, mgr_username, mgr_password, validate_certs)
      
      if completion_status == 'FAILED' or completion_status == 'PAUSED':
         module.fail_json(msg="Failed while upgrading component:[%s].Component status is[%s]."% (component, to_native(err)))

   module.exit_json(changed=True, message='System has been upgraded successfully!!!')


def check_upgrade_resume_component(module, manager_url, mgr_username, mgr_password, validate_certs):
   try:
    component_status_list = get_attribute_from_endpoint(module, manager_url, 
                    '/upgrade/status-summary', mgr_username, mgr_password,
                    validate_certs, 'component_status', False)
   except Exception as err:
      module.fail_json(msg="Failed to fetch /upgrade/status-summary. Error[%s]." % to_native(err))

   for index , component_status in enumerate(component_status_list):
      if component_status['status'] == 'SUCCESS':
         continue
      else:
         return index
   return -1;

def trigger_upgrade_reverse_order(module, mgr_hostname, mgr_username, mgr_password, validate_certs):

    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    mgr_hostname = get_upgrade_orchestrator_node(module, mgr_hostname, mgr_username, 
                                            mgr_password, headers, validate_certs)
    
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    upgrade_component_sequence = OrderedDict([
    ('MP' , '/upgrade/plan?action=upgrade&component_type=MP'),
    ('EDGE' , '/upgrade/plan?action=upgrade&component_type=EDGE'),
    ('HOST' , '/upgrade/plan?action=upgrade&component_type=HOST'),
    ('FINALIZE' , '/upgrade/plan?action=upgrade&component_type=FINALIZE_UPGRADE')
])

    upgrade_status = get_upgrade_status(module, manager_url, mgr_username,
                                          mgr_password, validate_certs)


    if upgrade_status == 'IN_PROGRESS' or upgrade_status == 'PAUSING':
      module.fail_json(msg='Upgrade is in state: %s, can\'t continue' % upgrade_status)

    elif upgrade_status == 'SUCCESS':
      module.exit_json(changed=False, message='Upgrade state is SUCCESS. No need to'
                    ' continue.')
      
    elif upgrade_status == 'NOT_STARTED':
       upgrade_component_sequence_list = list(upgrade_component_sequence.items())[0:]

       execute_upgrade_in_sequence(upgrade_component_sequence_list, 0, module, manager_url, mgr_username, mgr_password, validate_certs)
    
    elif upgrade_status == 'PAUSED':
       index_to_start_from = check_upgrade_resume_component(module, manager_url, mgr_username, mgr_password, validate_certs)
       upgrade_component_sequence_list = list(upgrade_component_sequence.items())[index_to_start_from:]

       execute_upgrade_in_sequence(upgrade_component_sequence_list, index_to_start_from, module, manager_url, mgr_username, mgr_password, validate_certs)
      
    module.exit_json(changed=True, message='Upgrade reverse order module completed!')