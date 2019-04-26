#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
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
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_transport_nodes
short_description: Create a Transport Node
description: Transport nodes are hypervisor hosts and NSX Edges that will participate
              in an NSX-T overlay. For a hypervisor host, this means that it hosts
              VMs that will communicate over NSX-T logical switches. For NSX Edges,
              this means that it will have logical router uplinks and downlinks.

              This API creates transport node for a host node (hypervisor) or edge node
              (router) in the transport network.

              When you run this command for a host, NSX Manager attempts to install the
              NSX kernel modules, which are packaged as VIB, RPM, or DEB files. For the
              installation to succeed, you must provide the host login credentials and the
              host thumbprint.

              To get the ESXi host thumbprint, SSH to the host and run the
              <b>openssl x509 -in /etc/vmware/ssl/rui.crt -fingerprint -sha256 -noout</b>
              command.

              To generate host key thumbprint using SHA-256 algorithm please follow the
              steps below.

              Log into the host, making sure that the connection is not vulnerable to a
              man in the middle attack. Check whether a public key already exists.
              Host public key is generally located at '/etc/ssh/ssh_host_rsa_key.pub'.
              If the key is not present then generate a new key by running the following
              command and follow the instructions.

              <b>ssh-keygen -t rsa</b>

              Now generate a SHA256 hash of the key using the following command. Please
              make sure to pass the appropriate file name if the public key is stored with
              a different file name other than the default 'id_rsa.pub'.

              <b>awk '{print $2}' id_rsa.pub | base64 -d | sha256sum -b | sed 's/ .*$//' | xxd -r -p | base64</b>
              This api is deprecated as part of FN+TN unification. Please use Transport Node API
              to install NSX components on a node.

              Additional documentation on creating a transport node can be found
              in the NSX-T Installation Guide.

              In order for the transport node to forward packets,
              the host_switch_spec property must be specified.

              Host switches (called bridges in OVS on KVM hypervisors) are the
              individual switches within the host virtual switch. Virtual machines
              are connected to the host switches.

              When creating a transport node, you need to specify if the host switches
              are already manually preconfigured on the node, or if NSX should create
              and manage the host switches. You specify this choice by the type
              of host switches you pass in the host_switch_spec property of the
              TransportNode request payload.

              For a KVM host, you can preconfigure the host switch, or you can have
              NSX Manager perform the configuration. For an ESXi host or NSX Edge
              node, NSX Manager always configures the host switch.

              To preconfigure the host switches on a KVM host, pass an array
              of PreconfiguredHostSwitchSpec objects that describes those host
              switches. In the current NSX-T release, only one prefonfigured host
              switch can be specified.  See the PreconfiguredHostSwitchSpec schema
              definition for documentation on the properties that must be provided.
              Preconfigured host switches are only supported on KVM hosts, not on
              ESXi hosts or NSX Edge nodes.

              To allow NSX to manage the host switch configuration on KVM hosts,
              ESXi hosts, or NSX Edge nodes, pass an array of StandardHostSwitchSpec
              objects in the host_switch_spec property, and NSX will automatically
              create host switches with the properties you provide. In the current
              NSX-T release, up to 5 host switches can be automatically managed.
              See the StandardHostSwitchSpec schema definition for documentation on
              the properties that must be provided.

              Note: previous versions of NSX-T used a property named host_switches
              to specify the host switch configuration on the transport node. That
              property is deprecated, but still functions. You should configure new
              host switches using the host_switch_spec property.

              The request should either provide node_deployement_info or node_id.

              If the host node (hypervisor) or edge node (router) is already added in
              system then it can be converted to transport node by providing node_id in
              request.

              If host node (hypervisor) or edge node (router) is not already present in
              system then information should be provided under node_deployment_info.

version_added: "2.7"
author: Rahul Raghuvanshi
options:
    hostname:
        description: Deployed NSX manager hostname.
        required: true
        type: str
    username:
        description: The username to authenticate with the NSX manager.
        required: true
        type: str
    password:
        description: The password to authenticate with the NSX manager.
        required: true
        type: str
    display_name:
        description: Display name
        required: true
        type: str
    description:
        description: Description of this resource
        required: False
        type: str
    resource_type:
        description: Must be set to the value TransportNode
        required: False
        type: str
    host_switch_spec:
        description: 'This property is used to either create standard host switches
                      or to inform NSX about preconfigured host switches that already
                      exist on the transport node.
                      Pass an array of either StandardHostSwitchSpec objects or
                      PreconfiguredHostSwitchSpec objects. It is an error to pass
                      an array containing different types of HostSwitchSpec objects.'
        host_switches:
            description: This property is deprecated in favor of 'host_switch_spec'. Property
                          'host_switches' can only be used for NSX managed transport nodes. 
                          'host_switch_spec' can be used for both NSX managed or manually 
                          preconfigured host switches.
            required: true
            type: array of PreconfiguredHostSwitch
        required: false
        resource_type:
            description: Selects the type of the transport zone profile
            required: true
            type: str
        type: dict
    maintenance_mode:
        description: The property is read-only, used for querying result. User could update
                      transport node maintenance mode by UpdateTransportNodeMaintenanceMode call.
        required: false
        type: str
    node_deployment_info:
        allocation_list:
            description: List of logical router ids to which this edge node is allocated.
            required: false
            type: list
        deployment_config:
            description: 'When this configuration is specified, edge fabric node of deployment_type
                          VIRTUAL_MACHINE will be deployed and registered with MP.'
            form_factor:
                description: Supported edge form factor.
                required: false
                type: str
            node_user_settings:
                audit_password:
                    description: "Password for the node audit user. For deployment, this property
                                  is required. After deployment, this property is ignored, and
                                  the node cli must be used to change the password. The password 
                                  specified must be at least 12 characters in length and must 
                                  contain at least one lowercase, one uppercase, one numeric 
                                  character and one special character (except quotes)."
                    required: false
                    type: str
                audit_username:
                    description: "The default username is \"audit\". To configure username, you
                                  must provide this property together with <b>audit_password</b>."
                    required: false
                    type: str
                cli_password:
                    description: "Password for the node cli user. For deployment, this property
                                  is required. After deployment, this property is ignored, and 
                                  the node cli must be used to change the password. The password 
                                  specified must be at least 12 characters in length and must 
                                  contain at least one lowercase, one uppercase, one numeric 
                                  character and one special character (except quotes)."
                    required: false
                    type: str
                cli_username:
                    description: "To configure username, you must provide this property together 
                                  with <b>cli_password</b>."
                    required: false
                    type: str
                description: "Username and password settings for the node. Note - these settings
                             will be honored only during node deployment. Post deployment, CLI 
                             must be used for changing the user settings, changes to these 
                             parameters will not have any effect."
                required: true
                root_password:
                    description: "Password for the node root user. For deployment, this property
                                 is required. After deployment, this property is ignored, and the
                                 node cli must be used to change the password. The password 
                                 specified must be at least 12 characters in length and must 
                                 contain at least one lowercase, one uppercase, one numeric 
                                 character and one special character (except quotes)."
                    required: false
                    type: str
                type: dict
            required: false
            type: dict
            vm_deployment_config:
                allow_ssh_root_login:
                    description: 'If true, the root user will be allowed to log into the VM.
                                  Allowing root SSH logins is not recommended for security 
                                  reasons.'
                    required: false
                    type: boolean
                compute_id:
                    description: 'The cluster node VM will be deployed on the specified cluster
                                  or resourcepool for specified VC server.'
                    required: true
                    type: str
                data_network_ids:
                    description: "List of distributed portgroup or VLAN logical identifiers to
                       which the datapath serving vnics of edge node vm will be connected."
                    required: true
                    type: list
                default_gateway_addresses:
                    description: 'The default gateway for the VM to be deployed must be specified
                                  if all the other VMs it communicates with are not in the same subnet.
                                  Do not specify this field and management_port_subnets to use DHCP.
                        
                                  Note: only single IPv4 default gateway address is supported and it
                                  must belong to management network.
                        
                                  IMPORTANT: VMs deployed using DHCP are currently not supported,
                                  so this parameter should be specified.'
                    required: false
                    type: list
                description: VM Deployment Configuration
                dns_servers:
                    description: 'List of DNS servers.
                                  If DHCP is used, the default DNS servers associated with
                                  the DHCP server will be used instead.
                                  Required if using static IP.'
                    required: false
                    type: list
                enable_ssh:
                    description: 'If true, the SSH service will automatically be started on the
                                  VM. Enabling SSH service is not recommended for security 
                                  reasons.'
                    required: false
                    type: boolean
                host_id:
                    description: "The service VM will be deployed on the specified host in the\
                       specified server within the cluster if host_id is specified.
                       Note: You must ensure that storage and specified networks are accessible
                       by this host."
                    required: false
                    type: str
                hostname:
                    description: Desired host name/FQDN for the VM to be deployed
                    required: true
                    type: str
                management_network_id:
                    description: 'Distributed portgroup identifier to which the management vnic
                                  of cluster node VM will be connected.'
                    required: true
                    type: str
                management_port_subnets:
                    description: 'IP Address and subnet configuration for the management port.
                                  Do not specify this field and default_gateway_addresses to
                                  use DHCP.
                        
                                  Note: only one IPv4 address is supported for the management 
                                  port.
                        
                                  IMPORTANT: VMs deployed using DHCP are currently not supported,
                                  so this parameter should be specified.'
                    required: false
                    type: array of IPSubnet
                ntp_servers:
                    description: 'List of NTP servers.
                      To use hostnames, a DNS server must be defined. If not using DHCP,
                      a DNS server should be specified under dns_servers.'
                    required: false
                    type: list
                placement_type:
                    description: "Specifies the config for the platform through which to deploy
                       the VM"
                    required: true
                    type: str
                required: true
                search_domains:
                    description: 'List of domain names that are used to complete unqualified host
                                  names.'
                    required: false
                    type: list
                storage_id:
                    description: Moref of the datastore in VC. If it is to be taken from 'Agent
                                 VM Settings', then it should be empty.
                    required: true
                    type: str
                type: dict
                vc_id:
                    description: 'The VC-specific identifiers will be resolved on this VC, so all
                                  other identifiers specified in the config must belong to this vCenter 
                                  server.'
                    required: true
                    type: str
        deployment_type:
            description: Specifies whether the service VM should be deployed on each host such
                          that it provides partner service locally on the host, or whether the 
                          service VMs can be deployed as a cluster. If deployment_type is 
                          CLUSTERED, then the clustered_deployment_count should be provided.
            required: false
            type: str
        description: None
        discovered_ip_addresses:
            description: Discovered IP Addresses of the fabric node, version 4 or 6
            required: false
            type: list
        discovered_node_id:
            description: Id of discovered node which was converted to create this node
            required: false
            type: str
        external_id:
            description: Current external id of this virtual machine in the system.
            required: false
            type: str
        fqdn:
            description: Domain name the entity binds to
            required: false
            type: str
        host_credential:
            description: Login credentials for the host
            password:
                description: Password for the user (optionally specified on PUT, unspecified
                  on GET)
                required: false
                type: str
            required: false
            thumbprint:
                description: Hexadecimal SHA256 hash of the vIDM server's X.509 certificate
                required: false
                type: str
            type: dict
            username:
                description: Username value of the log
                required: false
                type: str
        ip_addresses:
            description: Interface IP addresses
            required: false
            type: array of IPv4Address
        managed_by_server:
            description: The id of the vCenter server managing the ESXi type HostNode
            required: false
            type: str
        os_type:
            description: OS type of the discovered node
            required: true
            type: str
        os_version:
            description: OS version of the discovered node
            required: false
            type: str
        required: false
        resource_type:
            description: Selects the type of the transport zone profile
            required: true
            type: str
        type: dict
    node_id:
        description: Unique Id of the fabric node
        required: false
        type: str
    state:
        choices:
        - present
        - absent
        description: "State can be either 'present' or 'absent'. 
                      'present' is used to create or update resource. 
                      'absent' is used to delete resource."
        required: true
    transport_zone_endpoints:
        description: Transport zone endpoints.
        required: false
        type: array of TransportZoneEndPoint
    
'''

EXAMPLES = '''
- name: Create transport node
  nsxt_transport_nodes:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    resource_type: "TransportNode"
    display_name: "NSX Configured TN"
    description: "NSX configured Test Transport Node"
    host_switch_spec:
      resource_type: "StandardHostSwitchSpec"
      host_switches:
      - host_switch_profiles:
        - name: "uplinkProfile1"
          type: "UplinkHostSwitchProfile"
        host_switch_name: "hostswitch1"
        pnics:
        - device_name: "vmnic1"
          uplink_name: "uplink-1"
        ip_assignment_spec:
          resource_type: "StaticIpPoolSpec"
          ip_pool_name: "IPPool-IPV4-1"
    transport_zone_endpoints:
    - transport_zone_name: "TZ1"
    node_deployment_info:
      resource_type: "HostNode"
      display_name: "Host_1"
      ip_addresses: ["10.149.55.21"]
      os_type: "ESXI"
      os_version: "6.5.0"
      host_credential:
        username: "root"
        password: "ca$hc0w"
        thumbprint: "e7fd7dd84267da10f991812ca62b2bedea3a4a62965396a04728da1e7f8e1cb9"
    node_id: null
    state: "present"

'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native


FAILED_STATES = ["failed"]
IN_PROGRESS_STATES = ["pending", "in_progress"]
SUCCESS_STATES = ["partial_success", "success"]

def get_transport_node_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_transport_nodes(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url+ '/transport-nodes', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing transport nodes. Error [%s]' % (to_native(err)))
    return resp

def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint, display_name, exit_if_not_found=True):
    try:
      (rc, resp) = request(manager_url+ endpoint, headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing id for display name %s. Error [%s]' % (display_name, to_native(err)))

    for result in resp['results']:
        if result.__contains__('display_name') and result['display_name'] == display_name:
            return result['id']
    if exit_if_not_found:
        module.fail_json(msg='No id exist with display name %s' % display_name)

def get_tn_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    transport_nodes = get_transport_nodes(module, manager_url, mgr_username, mgr_password, validate_certs)
    for transport_node in transport_nodes['results']:
        if transport_node.__contains__('display_name') and transport_node['display_name'] == display_name:
            return transport_node
    return None

def wait_till_create(node_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      count = 0;
      while True:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s/state'% node_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          if any(resp['state'] in progress_status for progress_status in IN_PROGRESS_STATES):
              time.sleep(10)
              count = count + 1
              if count == 90:
                  #Wait for max 15 minutes for host to realize
                  module.fail_json(msg= 'Error creating transport node: %s'%(str(resp['state'])))
          elif any(resp['state'] in progress_status for progress_status in SUCCESS_STATES):
              time.sleep(5)
              return
          else:
              module.fail_json(msg= 'Error creating transport node: %s'%(str(resp['state'])))
    except Exception as err:
      module.fail_json(msg='Error accessing transport node. Error [%s]' % (to_native(err)))

def wait_till_delete(vm_id, module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      while True:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s/state'% vm_id, headers=dict(Accept='application/json'),
                        url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
          time.sleep(10)
    except Exception as err:
      time.sleep(5)
      return

def update_params_with_id (module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_params ):
    if transport_node_params.__contains__('host_switch_spec'):
        for host_switch in transport_node_params['host_switch_spec']['host_switches']:
            host_switch_profiles = host_switch.pop('host_switch_profiles', None)

            host_switch_profile_ids = []
            for host_switch_profile in host_switch_profiles:
                profile_obj = {}
                profile_obj['value'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                                                        "/host-switch-profiles?include_system_owned=true", host_switch_profile['name'])
                profile_obj['key'] = host_switch_profile['type']
                host_switch_profile_ids.append(profile_obj)
            host_switch['host_switch_profile_ids'] = host_switch_profile_ids
            ip_pool_id = None
            if host_switch.__contains__('ip_assignment_spec') and host_switch['ip_assignment_spec']['resource_type'] == 'StaticIpPoolSpec':
                ip_pool_name = host_switch['ip_assignment_spec'].pop('ip_pool_name', None)
                host_switch['ip_assignment_spec']['ip_pool_id'] = get_id_from_display_name (module, manager_url,
                                                                                            mgr_username, mgr_password, validate_certs,
                                                                                            "/pools/ip-pools", ip_pool_name)
    if transport_node_params.__contains__('transport_zone_endpoints'):
        for transport_zone_endpoint in transport_node_params['transport_zone_endpoints']:
            transport_zone_name = transport_zone_endpoint.pop('transport_zone_name', None)
            transport_zone_endpoint['transport_zone_id'] = get_id_from_display_name (module, manager_url,
                                                                                    mgr_username, mgr_password, validate_certs,
                                                                                    "/transport-zones", transport_zone_name)
    if transport_node_params['node_deployment_info']['resource_type'] == 'EdgeNode':
        vc_name = transport_node_params['node_deployment_info']['deployment_config']['vm_deployment_config'].pop('vc_name', None)
        transport_node_params['node_deployment_info']['deployment_config']['vm_deployment_config']['vc_id'] = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs,
                    "/fabric/compute-managers", vc_name)

    transport_node_params['display_name'] = transport_node_params.pop('display_name', None)
    return transport_node_params
#
# def ordered(obj):
#     if isinstance(obj, dict):
#         return sorted((k, ordered(v)) for k, v in obj.items())
#     if isinstance(obj, list):
#         return sorted(ordered(x) for x in obj)
#     else:
#         return obj

def id_exist_in_list_dict_obj(key, list_obj1, list_obj2):
    all_id_presents = False
    if len(list_obj1) != len(list_obj2):
        return all_id_presents
    for dict_obj1 in list_obj1:
        if dict_obj1.__contains__(key):
            for dict_obj2 in list_obj2:
                if dict_obj2.__contains__(key) and dict_obj1[key] == dict_obj2[key]:
                    all_id_presents = True
                    continue
            if not all_id_presents:
                return False
    return True
def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_with_ids):
    existing_transport_node = get_tn_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_with_ids['display_name'])
    if existing_transport_node is None:
        return False
    if existing_transport_node.__contains__('transport_zone_endpoints') and transport_node_with_ids.__contains__('transport_zone_endpoints'):
        return not id_exist_in_list_dict_obj('transport_zone_id', existing_transport_node['transport_zone_endpoints'], transport_node_with_ids['transport_zone_endpoints'])
    if existing_transport_node.__contains__('host_switch_spec') and existing_transport_node['host_switch_spec'].__contains__('host_switches') and \
        transport_node_with_ids.__contains__('host_switch_spec') and transport_node_with_ids['host_switch_spec'].__contains__('host_switches') and \
        existing_transport_node['host_switch_spec']['host_switches'] != transport_node_with_ids['host_switch_spec']['host_switches']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(display_name=dict(required=True, type='str'),
                       description=dict(required=False, type='str'),
                       resource_type=dict(required=False, choices=['TransportNode']),
                       host_switch_spec=dict(required=False, type='dict',
                       host_switches=dict(required=True, type='list'),
                       resource_type=dict(required=True, type='str')),
                       node_deployment_info=dict(required=False, type='dict',
                       discovered_node_id=dict(required=False, type='str'),
                       deployment_config=dict(required=False, type='dict',
                       node_user_settings=dict(required=True, type='dict',
                       cli_username=dict(required=False, type='str'),
                       audit_username=dict(required=False, type='str'),
                       root_password=dict(required=False, type='str'),
                       cli_password=dict(required=False, type='str'),
                       audit_password=dict(required=False, type='str')),
                       vm_deployment_config=dict(required=True, type='dict',
                       data_network_ids=dict(required=True, type='list'),
                       dns_servers=dict(required=False, type='list'),
                       ntp_servers=dict(required=False, type='list'),
                       management_network_id=dict(required=True, type='str'),
                       enable_ssh=dict(required=False, type='boolean'),
                       allow_ssh_root_login=dict(required=False, type='boolean'),
                       placement_type=dict(required=True, type='str'),
                       compute_id=dict(required=True, type='str'),
                       search_domains=dict(required=False, type='list'),
                       vc_id=dict(required=True, type='str'),
                       storage_id=dict(required=True, type='str'),
                       default_gateway_addresses=dict(required=False, type='list'),
                       management_port_subnets=dict(required=False, type='list'),
                       host_id=dict(required=False, type='str'),
                       hostname=dict(required=True, type='str')),
                       form_factor=dict(required=False, type='str')),
                       discovered_ip_addresses=dict(required=False, type='list'),
                       ip_addresses=dict(required=False, type='list'),
                       fqdn=dict(required=False, type='str'),
                       os_version=dict(required=False, type='str'),
                       managed_by_server=dict(required=False, type='str'),
                       host_credential=dict(required=False, type='dict',
                       username=dict(required=False, type='str'),
                       password=dict(required=False, type='str'),
                       thumbprint=dict(required=False, type='str')),
                       allocation_list=dict(required=False, type='list'),
                       os_type=dict(required=True, type='str'),
                       external_id=dict(required=False, type='str'),
                       resource_type=dict(required=True, type='str'),
                       deployment_type=dict(required=False, type='str')),
                       maintenance_mode=dict(required=False, type='str'),
                       transport_zone_endpoints=dict(required=False, type='list'),
                       node_id=dict(required=False, type='str'),
                       state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  transport_node_params = get_transport_node_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']
  display_name = module.params['display_name']
  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  transport_node_dict = get_tn_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, display_name)
  transport_node_id, revision = None, None
  if transport_node_dict:
    transport_node_id = transport_node_dict['id']
    revision = transport_node_dict['_revision']

  if state == 'present':
    body = update_params_with_id(module, manager_url, mgr_username, mgr_password, validate_certs, transport_node_params)
    updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, body)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'

    if not updated:
      # add the node
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(logical_switch_params)), id='12345')
      request_data = json.dumps(body)
      try:
          if not transport_node_id:
              transport_node_id = get_id_from_display_name (module, manager_url, mgr_username, mgr_password, validate_certs, '/transport-nodes', display_name, exit_if_not_found=False)
          if transport_node_id:
              module.exit_json(changed=False, id=transport_node_id, message="Transport node with display_name %s already exist."% module.params['display_name'])

          (rc, resp) = request(manager_url+ '/transport-nodes', data=request_data, headers=headers, method='POST',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
           module.fail_json(msg="Failed to add transport node. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

      wait_till_create(resp['node_id'], module, manager_url, mgr_username, mgr_password, validate_certs)
      time.sleep(5)
      module.exit_json(changed=True, id=resp["node_id"], body= str(resp), message="Transport node with display name %s created." % module.params['display_name'])
    else:
      if module.check_mode:
          module.exit_json(changed=True, debug_out=str(json.dumps(body)), id=transport_node_id)

      body['_revision'] = revision # update current revision
      request_data = json.dumps(body)
      id = transport_node_id
      try:
          (rc, resp) = request(manager_url+ '/transport-nodes/%s' % id, data=request_data, headers=headers, method='PUT',
                                url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
          module.fail_json(msg="Failed to update transport node with id %s. Request body [%s]. Error[%s]." % (id, request_data, to_native(err)))

      time.sleep(5)
      module.exit_json(changed=True, id=resp["node_id"], body= str(resp), message="Transport node with node id %s updated." % id)

  elif state == 'absent':
    # delete the array
    id = transport_node_id
    if id is None:
        module.exit_json(changed=False, msg='No transport node exist with display name %s' % display_name)
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(json.dumps(transport_node_params)), id=id)
    try:
        (rc, resp) = request(manager_url + "/transport-nodes/%s" % id, method='DELETE',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
    except Exception as err:
        module.fail_json(msg="Failed to delete transport node with id %s. Error[%s]." % (id, to_native(err)))

    wait_till_delete(id, module, manager_url, mgr_username, mgr_password, validate_certs)
    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Transport node with node id %s deleted." % id)



if __name__ == '__main__':
    main()
