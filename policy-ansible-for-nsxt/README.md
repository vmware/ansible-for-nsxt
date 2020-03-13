# Ansible for NSX-T Policy API

This project supports the creation, update, and deletion of NSX-T resources using the latest Policy API.

## Prerequisites
1. Python3 >= 3.5.2
2. Ansible >= 2.8.1

## NSX-T Resources Supported
1. Tier-0 Gateway
   1. Tier-0 Locale Services
   2. Tier-0 Static Routes
   3. Tier-0 Interface
   4. Tier-0 BGP
   5. Tier-0 BGP Neighbors
   6. Tier-0 VRF
   7. Tier-0 BFD Peers
2. Tier-1 Gateway
   1. Tier-1 Locale Services
   2. Tier-1 Static Routes
   3. Tier-1 Interface
3. Segment
   1. Segment Port
4. Policy Group
5. Security Policy and Firewall rules
6. IP Pools
   1. IP Address Pool Block Subnet
   2. IP Address Pool Static Subnet
7. IP Blocks
8. BFD Config
9. VM Tags

Note that to add a new modules, it's base class name should be added in the BASE_RESOURCES in modules/nsxt_base_resource.py

## Supported Authentication Mechanisms
In any Ansible Module, you can use any of the following authentication mechanisms:

### Basic Authentication
By specifying the following fields in the playbook:
1. **username**: The username to authenticate with the NSX manager
2. **password**: The password to authenticate with the NSX manager

For example:
```yaml
- hosts: localhost
  tasks:
    - name: Update Tier0
      nsxt_tier0:
        hostname: "default"
        username: admin
        password: my-password
        validate_certs: False
        display_name: test-tier0-1
        state: present
```

### Prinicipal Identity
By specifying the following fields in the playbook:
1. **nsx_cert_path**: Path to the certificate created for the Principal Identity using which the CRUD operations should be performed
2. **nsx_key_path**: Path to the certificate key created for the Principal Identity using which the CRUD operations should be performed

For example:
```yaml
- hosts: localhost
  tasks:
    - name: Update Tier0
      nsxt_tier0:
        hostname: "default"
        nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
        nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
        validate_certs: False
        display_name: test-tier0-1
        state: present
```

### vIDM
When NSX-T is configured to use VMware Identity Manager (vIDM) for authentication, you can supply an Authorization header with an authentication type of *Remote*. The header content should consist of a base64-encoded string containing the username@domain and password separated by a single colon (":") character, as specified in RFC 1945 section 11.1.

For example, to authenticate a request using the credentials of user jsmith@example.com with password Sk2LkPM!, include the following key:value pair under **request_headers** in the playbook::
- Authorization: 'Remote anNtaXRoQGV4YW1wbGUuY29tOlNrMkxrUE0h'

For example:
```yaml
- hosts: localhost
  tasks:
    - name: Update Tier0
      nsxt_tier0:
        hostname: "default"
        request_headers:
          Authorization: 'Remote anNtaXRoQGV4YW1wbGUuY29tOlNrMkxrUE0h'
        validate_certs: False
        display_name: test-tier0-1
        state: present
```

### SSL Verification
You can use the flag *validate_certs* to perform SSL verification. You can also specify the path to a CA bundle using the paratemer *ca_path* in the playbook.

For example:
```yaml
- hosts: localhost
  tasks:
    - name: Update Tier0
      nsxt_tier0:
        hostname: "default"
        nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
        nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
        validate_certs: True
        ca_path: /path/to/my/ca-bundle
        display_name: test-tier0-1
        state: present
```

## Unit Testing
To test the Ansible modules or see examples of playbooks, please put the respective playbook from unit_tests folder to the base folder and run the ansible-playbook.

Please note that you must specify the correct vmware args in order to successfully update the resources.
