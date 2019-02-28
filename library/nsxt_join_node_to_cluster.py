#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
import ssl
import socket
import hashlib
import time

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''TODO
author: Aleksey Nishev
'''

EXAMPLES = '''
    - name: Join node to cluster
      nsxt_join_node_to_cluster:
        hostname: "{{item.ip_address}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        master_node: "{{item.master_node}}"
        vip: "{{hostname}}"
      with_items:
        - "{{deploy_ova}}"
'''

RETURN = '''# '''


def get_cluster_id(vip_manager_url, mgr_username, mgr_password, validate_certs, headers, vip, module):
    try:
        (rc, resp) = request(vip_manager_url + '/cluster/status', headers=dict(Accept='application/json'),
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
        if (rc == 200):
            cluster_id = resp.get("cluster_id")
            if cluster_id:
                return cluster_id
            else:
                module.fail_json(msg='Failed to get cluster ID from NSX-T manager {}'.format(vip))
    except Exception as err:
        module.fail_json(msg='Failed to get cluster ID from NSX-T manager {}. Error: {}'.format(vip, err))


def get_api_cert_thumbprint(ip_address, module, mgr_hostname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((ip_address, 443))
    except Exception as err:
        module.fail_json(msg='Failed to get node ID from NSX-T manager {}. Error: {}'.format(mgr_hostname, err))
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        return thumb_sha256
    finally:
        wrappedSocket.close()


def get_node_ids(manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module):
    node_ids = list()
    try:
        (rc, resp) = request(manager_url + '/cluster/nodes', headers=dict(Accept='application/json'),
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
        if (rc == 200):
            for node in resp["results"]:
                listen_addr = node.get("appliance_mgmt_listen_addr")
                manager_role = node.get("manager_role")
                if listen_addr != mgr_hostname and manager_role is not None:
                    node_ids.append(node["id"])
            return node_ids
        else:
            return None
    except Exception as err:
        module.fail_json(msg='Failed to get node ID from NSX-T manager {}. Error: {}'.format(mgr_hostname, err))


def join_node_to_cluster(vip_manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module, request_data):
    try:
        (rc, resp) = request(vip_manager_url + '/cluster?action=join_cluster', data=request_data, headers=headers, method='POST',
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
        if (rc == 200):
            return True
        else:
            module.fail_json(msg='Failed to join NSX-T manager node {} to cluster. Response code: {}, Response: {}'.format(mgr_hostname, rc, resp))
    except Exception as err:
        module.fail_json(msg='Failed to join NSX-T manager node {} to cluster. Error: {}'.format(mgr_hostname, err))


def detach_nodes_from_cluster(manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module, node_ids):
    for node_id in node_ids:
        try:
            (rc, resp) = request(manager_url + '/cluster/' + node_id + '?action=remove_node&force=true', headers=dict(Accept='application/json'), method='POST',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=False)
            if (rc != 200):
                return False
        except Exception as err:
            # module.exit_json(changed=False, msg="manager_url: {}".format(manager_url))
            module.fail_json(msg='Failed to detach NSX-T manager node {} from cluster Error: {}'.format(mgr_hostname, err))
    return True


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(master_node=dict(required=True, type='bool'))
    argument_spec.update(vip=dict(required=True, type='str'))
    argument_spec.update(state=dict(required=True, type='str'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    master_node = module.params['master_node']
    vip = module.params['vip']
    state = module.params['state']

    validate_certs = module.params['validate_certs']
    manager_url = 'https://{}/api/v1'.format(mgr_hostname)
    vip_manager_url = 'https://{}/api/v1'.format(vip)
    headers = dict(Accept="application/json")
    headers['Content-Type'] = 'application/json'
    join_cluster_timeout = 300  # in seconds

    if state == "present":
        if master_node:
            module.exit_json(changed=False, msg="Skipping master node")

        cluster_id = get_cluster_id(vip_manager_url, mgr_username, mgr_password, validate_certs, headers, vip, module)
        thumbprint = get_api_cert_thumbprint(vip, module, mgr_hostname)

        if not thumbprint:
            module.fail_json(msg='Failed to get certificate thumbprint for IP address {}'.format(vip))

        request_data_dict = dict(
            cluster_id=cluster_id,
            ip_address=vip,
            username=mgr_username,
            password=mgr_password,
            certficate_sha256_thumbprint=thumbprint
        )
        request_data = json.dumps(request_data_dict)
        result = join_node_to_cluster(manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module, request_data)
        if result:
            module.exit_json(changed=True, msg="NSX-T manager node {} was successfully joint to cluster with ID {}".format(mgr_hostname, cluster_id))
            time.sleep(join_cluster_timeout)
    elif state == "absent":
        if master_node:
            node_ids = get_node_ids(manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module)
            result = detach_nodes_from_cluster(manager_url, mgr_username, mgr_password, validate_certs, headers, mgr_hostname, module, node_ids)
            if result:
                module.exit_json(changed=True, msg="nodes have been successfully removed from cluster")
            else:
                module.fail_json(msg='Failed to remove the nodes from cluster')
        else:
            module.exit_json(changed=False, msg="Skipping, not a master node")

if __name__ == '__main__':
    main()
