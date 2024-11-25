#!/usr/bin/python
# -*- coding: utf-8 -*-
#
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

from __future__ import absolute_import, division, print_function
import time
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import get_upgrade_orchestrator_node
from ansible.module_utils._text import to_native


UPGRADE_API = '/upgrade/plan?action=upgrade'
UPGRADE_STATUS_SUMMARY_API = '/upgrade/status-summary'
MP_UPGRADE_DONE = False

def check_upgrade_status_at_start(module, manager_url, mgr_username, mgr_password, validate_certs):
   global MP_UPGRADE_DONE

   endpoint = "/upgrade/upgrade-unit-groups?sync=true"
   call_get_sync(manager_url, endpoint, mgr_username, mgr_password, validate_certs)
   
   upgrade_status_summary = get_upgrade_status_summary(module, manager_url, mgr_username, mgr_password, validate_certs , False)

   overall_upgrade_status = upgrade_status_summary['overall_upgrade_status']

   if overall_upgrade_status == 'PAUSED' :
      if upgrade_status_summary['component_status'][0]['status'] == 'SUCCESS':
         MP_UPGRADE_DONE = True

   return overall_upgrade_status

def get_upgrade_status_summary(module, manager_url, mgr_username, mgr_password, validate_certs , ignore_errors):
  '''
  Get the upgrade status summary
  '''

  try:
        (rc, resp) = request(manager_url+ UPGRADE_STATUS_SUMMARY_API, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, 
                      validate_certs=validate_certs, ignore_errors=ignore_errors)
  except Exception as err:
          if ignore_errors:
             return None
          else:
            module.fail_json(msg='Error while triggering api:'
                            ' %s. Error [%s]' % (manager_url+ UPGRADE_STATUS_SUMMARY_API, to_native(err)))
  return resp

def call_get_sync(managerUrl, endpoint, mgrUsername, mgrPassword, validateCerts):
    request(managerUrl + endpoint, method='GET', url_username=mgrUsername, url_password=mgrPassword,
            validate_certs=validateCerts, ignore_errors=True)

def check_component_upgrade_completion_status(module, manager_url, mgr_username, mgr_password, validate_certs):
   global MP_UPGRADE_DONE
   count_upgrade_status_api_no_resp = 0
   component_upgrade_start_time = time.time()

   while True:
      upgrade_status_summary = get_upgrade_status_summary(module, manager_url, mgr_username, mgr_password, validate_certs , True)

      if upgrade_status_summary == None:
        count_upgrade_status_api_no_resp +=1

      elif upgrade_status_summary.__contains__('overall_upgrade_status'):
         overall_upgrade_status = upgrade_status_summary['overall_upgrade_status']

         if overall_upgrade_status == 'SUCCESS':
            module.exit_json(changed=True, message='System has been upgraded successfully!!!')
            
         elif overall_upgrade_status == 'PAUSED':
            check_component_statuses(module , upgrade_status_summary['component_status'])
            if not MP_UPGRADE_DONE:
                MP_UPGRADE_DONE = True
            return
        
      elapsed_time = time.time() - component_upgrade_start_time
      if MP_UPGRADE_DONE and count_upgrade_status_api_no_resp >= 5:
        module.fail_json(msg='Error while triggering api:'
                    ' %s. API failed 5 times' %UPGRADE_STATUS_SUMMARY_API)
      elif not MP_UPGRADE_DONE and elapsed_time > 3600 :
         module.fail_json(msg='MP component upgrade took longer than 1hr, System upgrade failed')

      time.sleep(30)
       

def check_component_statuses(module, component_status_list):
    for component_status in component_status_list:
        if component_status['status'] == 'FAILED':
            module.fail_json(msg='Failed to upgrade system as Component : %s'
                        'has Status : %s ' %(component_status['component_type'], component_status['status']))
      
   

def execute_upgrade(module, manager_url, mgr_username, mgr_password, validate_certs):
   global MP_UPGRADE_DONE
   headers = dict(Accept="application/json")
   headers['Content-Type'] = 'application/json'

   while True:
      try:
        (rc, resp) = request(manager_url+ UPGRADE_API,
                        data='', headers=headers, method='POST', 
                        url_username=mgr_username, url_password=mgr_password, 
                        validate_certs=validate_certs, ignore_errors=False)
      except Exception as err:
        module.fail_json(msg="Failed while upgrading component")

      time.sleep(30)

      check_component_upgrade_completion_status(module, manager_url, mgr_username, mgr_password, validate_certs)

      

def trigger_upgrade_reverse_order(module, mgr_hostname, mgr_username, mgr_password, validate_certs):

    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    mgr_hostname = get_upgrade_orchestrator_node(module, mgr_hostname, mgr_username, 
                                            mgr_password, headers, validate_certs)
    
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)

    upgrade_status = check_upgrade_status_at_start(module, manager_url, mgr_username,
                                          mgr_password, validate_certs)

    if upgrade_status == 'IN_PROGRESS' or upgrade_status == 'PAUSING':
      module.fail_json(msg='Upgrade is in state: %s, can\'t continue' % upgrade_status)

    elif upgrade_status == 'SUCCESS':
      module.exit_json(changed=False, message='Upgrade state is SUCCESS. No need to'
                    ' continue.')
      
    elif upgrade_status == 'NOT_STARTED' or upgrade_status == 'PAUSED':
      execute_upgrade(module, manager_url, mgr_username, mgr_password, validate_certs)