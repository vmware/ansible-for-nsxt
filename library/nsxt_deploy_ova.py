#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
import ssl
from datetime import datetime
import time
from pyVim.connect import SmartConnect
from pyVmomi import vim
from ansible.module_utils.vmware_nsxt import request
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''TODO
author: Aleksey Nishev
'''

EXAMPLES = '''
- name: Deploy NSX Manager OVA
  deploy_ova:
    ovftool_path: "{{ ovfToolPath }}"
    datacenter: "private_dc"
    datastore: "data store"
    portgroup: "VM Network"
    cluster: "nsxt_cluster"
    vmname: "nsxt-manager"
    hostname: "nsxt-manager-10"
    dns_server: "10.161.244.213"
    dns_domain: "eng.vmware.com"
    ntp_server: "123.108.200.124"
    gateway: "10.112.203.253"
    ip_address: "10.112.201.24"
    netmask: "255.255.224.0"
    admin_password: "Admin!23Admin"
    cli_password: "Admin!23Admin"
    path_to_ova: "http://build-squid.eng.vmware.com/build/mts/release/bora-8411846/publish/nsx-unified-appliance/exports/ovf"
    ova_file: "nsx-unified-appliance-2.2.0.0.0.8411854.ovf"
    vcenter: "10.161.244.213"
    vcenter_user: "administrator@vsphere.local"
    vcenter_passwd: "Admin!23"
    deployment_size: "{{appliance_size}}"
    role: "nsx-manager nsx-controller"
    validate_certs: "True"
    mgr_username: "admin"
    service_boot_timeout: "30"
    force_redeploy: False
'''

RETURN = '''# '''


def virtual_machine_exists(content, searched_vm_name):
    virtual_machines = get_all_objs(content, [vim.VirtualMachine])
    for vm in virtual_machines:
        if vm.name == searched_vm_name:
            return True
    return False


def get_all_objs(content, vimtype):
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name})
    return obj


def connect_to_api(vchost, vc_user, vc_pwd):
    try:
        service_instance = SmartConnect(host=vchost, user=vc_user, pwd=vc_pwd)
    except (requests.ConnectionError, ssl.SSLError):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_NONE
            service_instance = SmartConnect(host=vchost, user=vc_user, pwd=vc_pwd, sslContext=context)
        except Exception as e:
            raise Exception(e)
    return service_instance.RetrieveContent()


def get_service_boot_timeout(service_boot_timeout, current_time, polling_interval):
    time_diff = datetime.now() - current_time
    time.sleep(polling_interval)
    return time_diff.seconds + service_boot_timeout + polling_interval


def is_nsxt_manager_alive(manager_url, mgr_username, mgr_password, validate_certs, headers, module):
    # Polling interval in seconds
    polling_interval = 10
    service_boot_timeout = 0
    while service_boot_timeout <= (module.params['service_boot_timeout'] * 60):
        try:
            current_time = datetime.now()
            (rc, resp) = request(manager_url + '/cluster/status', headers=dict(Accept='application/json'),
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
            if (rc == 200):
                cluster_id = resp.get("cluster_id")
                if cluster_id:
                    return True
                else:
                    service_boot_timeout = get_service_boot_timeout(service_boot_timeout, current_time, polling_interval)
        except Exception:
            service_boot_timeout = get_service_boot_timeout(service_boot_timeout, current_time, polling_interval)
    return False


def install_nsx_manager(module):
    ovftool_exec = '{}/ovftool'.format(module.params['ovftool_path'])
    ovf_command = [ovftool_exec]

    ovf_base_options = ['--X:vimSessionTimeout=1', '--powerOffTarget', '--overwrite', '--acceptAllEulas', '--skipManifestCheck', '--X:injectOvfEnv', '--powerOn', '--noSSLVerify',
                        '--allowExtraConfig', '--diskMode={}'.format(module.params['disk_mode']),
                        '--datastore={}'.format(module.params['datastore']),
                        '--name={}'.format(module.params['vmname']),
                        '--deploymentOption={}'.format(module.params['deployment_size'])]
    if module.params['portgroup_ext']:
        ovf_base_options.extend(['--net:Network 0={}'.format(module.params['portgroup']),
                                 '--net:Network 1={}'.format(module.params['portgroup_ext']),
                                 '--net:Network 2={}'.format(module.params['portgroup_transport']),
                                 '--net:Network 3={}'.format(module.params['portgroup'])])
    else:
        ovf_base_options.extend(['--network={}'.format(module.params['portgroup'])])
    ovf_command.extend(ovf_base_options)

    ovf_ext_prop = ['--prop:nsx_hostname={}'.format(module.params['hostname']),
                    '--prop:nsx_dns1_0={}'.format(module.params['dns_server']),
                    '--prop:nsx_domain_0={}'.format(module.params['dns_domain']),
                    '--prop:nsx_ntp_0={}'.format(module.params['ntp_server']),
                    '--prop:nsx_gateway_0={}'.format(module.params['gateway']),
                    '--prop:nsx_ip_0={}'.format(module.params['ip_address']),
                    '--prop:nsx_netmask_0={}'.format(module.params['netmask']),
                    '--prop:nsx_passwd_0={}'.format(module.params['admin_password']),
                    '--prop:nsx_cli_passwd_0={}'.format(module.params['cli_password']),
                    '--prop:nsx_isSSHEnabled={}'.format(module.params['ssh_enabled']),
                    '--prop:nsx_allowSSHRootLogin={}'.format(module.params['allow_ssh_root_login']),
                    '--prop:nsx_role={}'.format(module.params['role'])]
    ovf_command.extend(ovf_ext_prop)

    if module.params['extra_para']:
        ovf_command.extend(['--prop:extraPara={}'.format(module.params['extra_para'])])

    ova_file = '{}/{}'.format(module.params['path_to_ova'], module.params['ova_file'])
    ovf_command.append(ova_file)

    vi_string = 'vi://{}:{}@{}/'.format(module.params['vcenter_user'],
                                        module.params['vcenter_passwd'], module.params['vcenter'])
    if module.params.__contains__('folder') and module.params['folder']:
        vi_string = vi_string + module.params['folder']

    vi_string = vi_string + '/{}/host/{}/'.format(module.params['datacenter'], module.params['cluster'])

    ovf_command.append(vi_string)

    if module.check_mode:
        module.exit_json(changed=True, debug_out=ovf_command)

    ova_tool_result = module.run_command(ovf_command)

    if ova_tool_result[0] != 0:
        module.fail_json(msg='Failed to deploy OVA, error message from ovftool is: {}, the comand was {}'.format(ova_tool_result[1], ovf_command))

    module.exit_json(changed=True, ova_tool_result=ova_tool_result)

argument_spec = dict(
    ovftool_path=dict(type='str'),
    folder=dict(required=False, type='str'),
    datacenter=dict(required=True, type='str'),
    datastore=dict(required=True, type='str'),
    portgroup=dict(required=True, type='str'),
    portgroup_ext=dict(type='str'),
    portgroup_transport=dict(type='str'),
    cluster=dict(required=True, type='str'),
    vmname=dict(required=True, type='str'),
    hostname=dict(required=True, type='str'),
    dns_server=dict(required=True, type='str'),
    ntp_server=dict(required=True, type='str'),
    dns_domain=dict(required=True, type='str'),
    gateway=dict(required=True, type='str'),
    ip_address=dict(required=True, type='str'),
    netmask=dict(required=True, type='str'),
    admin_password=dict(required=True, type='str', no_log=True),
    cli_password=dict(required=True, type='str', no_log=True),
    ssh_enabled=dict(default=False),
    allow_ssh_root_login=dict(default=False),
    deployment_size=dict(default='medium', type='str'),
    path_to_ova=dict(required=True, type='str'),
    ova_file=dict(required=True, type='str'),
    disk_mode=dict(default='thin'),
    vcenter=dict(required=True, type='str'),
    vcenter_user=dict(required=True, type='str'),
    vcenter_passwd=dict(required=True, type='str', no_log=True),
    extra_para=dict(type='str'),
    role=dict(required=True, type='str'),
    validate_certs=dict(required=True, type='bool'),
    mgr_username=dict(required=True, type='str'),
    state=dict(required=True, type='str'),
    force_redeploy=dict(required=True, type='bool'),
    service_boot_timeout=dict(required=True, type='int')
)

module = AnsibleModule(
    argument_spec=argument_spec,
    supports_check_mode=True,
    required_together=[['portgroup_ext', 'portgroup_transport']]
)


def get_content():
    try:
        content = connect_to_api(module.params['vcenter'], module.params['vcenter_user'],
                                 module.params['vcenter_passwd'])
        return content
    except vim.fault.InvalidLogin:
        module.fail_json(msg='exception while connecting to vCenter, login failure, check username and password')
    except requests.exceptions.ConnectionError:
        module.fail_json(msg='exception while connecting to vCenter, check hostname, FQDN or IP')


def main():
    hostname = module.params['ip_address']
    mgr_name = module.params['hostname']
    mgr_username = module.params['mgr_username']
    mgr_password = module.params['admin_password']
    validate_certs = module.params['validate_certs']
    force_redeploy = module.params['force_redeploy']
    state = module.params['state']
    manager_url = 'https://{}/api/v1'.format(hostname)
    headers = dict(Accept="application/json")
    content = get_content()
    wait_time_to_shutdown = 120

    nsx_manager_vm_exists = virtual_machine_exists(content, module.params['vmname'])
    if state == "present":
        if nsx_manager_vm_exists and not force_redeploy:
            if is_nsxt_manager_alive(manager_url, mgr_username, mgr_password, validate_certs, headers, module):
                module.exit_json(changed=False, msg='A NSX-T manager named {} is already present and operational'.format(module.params['vmname']))
        install_nsx_manager(module)
    elif state == "absent":
        vm = content.searchIndex.FindByDnsName(None, mgr_name, True)
        if vm:
            vm.PowerOffVM_Task()
            time.sleep(wait_time_to_shutdown)
            vm.Destroy_Task()
        else:
            module.fail_json(msg="NSX-T manager {} was not found".format(mgr_name))

if __name__ == '__main__':
    main()
