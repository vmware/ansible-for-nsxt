# Ansible for NSX-T

# Overview
This repository contains NSX-T Ansible Modules, which one can use with
Ansible to work with [VMware NSX-T Data Center][vmware-nsxt].

[vmware-nsxt]: https://www.vmware.com/products/nsx.html

For general information about Ansible, visit the [GitHub project page][an-github].

[an-github]: https://github.com/ansible/ansible

These modules are maintained by [VMware](https://www.vmware.com/).

Documentation on the NSX platform can be found at the [NSX-T Documentation page](https://docs.vmware.com/en/VMware-NSX-T/index.html)

### Supported NSX Objects/Workflows
The modules in this repository are focused on enabling automation of installation workflows of NSX-T.

#### Deployment and installation modules

* nsxt_deploy_ova
* nsxt_licenses
* nsxt_manager_status
* nsxt_licenses_facts
* nsxt_edge_clusters
* nsxt_edge_clusters_facts
* nsxt_fabric_compute_managers
* nsxt_fabric_compute_managers_facts
* nsxt_fabric_nodes
* nsxt_fabric_nodes_facts
* nsxt_compute_collection_fabric_templates
* nsxt_compute_collection_fabric_templates_facts
* nsxt_ip_pools
* nsxt_ip_pools_facts
* nsxt_uplink_profiles
* nsxt_uplink_profiles_facts
* nsxt_transport_zones
* nsxt_transport_zones_facts
* nsxt_transport_nodes
* nsxt_transport_nodes_facts
* nsxt_transport_node_collections
* nsxt_transport_node_collections_facts
* nsxt_transport_node_profiles
* nsxt_transport_node_profiles_facts
* nsxt_compute_collection_transport_templates
* nsxt_compute_collection_transport_templates_facts
* nsxt_controller_manager_auto_deployment

##### Logical networking modules
* nsxt_logical_ports
* nsxt_logical_ports_facts
* nsxt_logical_routers
* nsxt_logical_routers_facts
* nsxt_logical_router_ports
* nsxt_logical_router_ports_facts
* nsxt_logical_router_static_routes
* nsxt_logical_switches
* nsxt_logical_switches_facts
* nsxt_ip_blocks
* nsxt_ip_blocks_facts


# Prerequisites
We assume that ansible is already installed. 
These modules support ansible version 2.7 and onwards. 

* PyVmOmi - Python library for vCenter api.

* OVF Tools - Ovftool is used for ovf deployment. 


# Build & Run

### Install PyVmOmi
```
pip install --upgrade pyvmomi pyvim requests ssl
```
### Download and Install Ovf tool 4.3 - [Ovftool](https://my.vmware.com/web/vmware/details?downloadGroup=OVFTOOL430&productId=742)
(Note: Using ovftool version 4.0/4.1 causes OVA/OVF deployment failure with Error: cURL error: SSL connect error\nCompleted with errors\n)

### Download [ansible-for-nsxt](https://github.com/vmware/ansible-for-nsxt/archive/master.zip).
```
unzip ansible-for-nsxt-master.zip
cd ansible-for-nsxt-master
```
To run a sample Ansible playbook - To create a sample test topology using deployments and install module.

Edit test_basic_topology.yml and answerfile.yml to match values to your environment.
```
ansible-playbook test_basic_topology.yml -vvv
```

### Authentication
Ansible-for-nsxt supports two types of authentication. They are: 
* Basic server authentication
* Client based authentication

#### Basic server authentication
In basic server authentication client has to explicitly provide NSX username and password to the NSX manager. The credentials have to be listed in ansible-playbook i.e. *.yml files.

#### Client based authentication
In this case clients have to register their certificates to NSX manager. After registering the certificates, client has to create its own principal identity on NSX manager.
The process of certificate registration and creation of principal identity has to be donw using basic server authentication. Edit test_certificates.yml and test_principal_identities.yml to match the values according to the client's environment.
```
ansible-playbook test_certificates.yml -vvv
ansible-playbook test_principal_identities -vvv
```
The path of the .p12 file i.e the file containing public and private key has to be set to an environment variable named NSX_MANAGER_CERT_PATH. 
**Note:** MAke sure NSX_MANAGER_CERT_PATH is set in the same environment, where the module is being executed.

##### Generating certificates?
Following commands can be used in order to generate certificates.
```
openssl req -newkey rsa:2048 -nodes -keyout nsx_certificate.key -x509 -days 365 -out nsx_certificate.crt -subj "/C=US/ST=California/L=Palo Alto/O=VMware/CN=certauth-test" -sha256

openssl pkcs12 -export -out nsx_certificate.pfx -inkey nsx_certificate.key -in nsx_certificate.crt

openssl pkcs12 -in nsx_certificate.pfx -out nsx_certificate.p12 -nodes
```

The nsx_certificate.crt file generated as output from the above command contains the public key certificate.
the file nsx_certificate.p12 file contains the public and private key generated. The path of nsx_certificate.p12 file has to be set in the environment variable NSX_MANAGER_CERT_PATH.

# Interoperability

The following versions of NSX are supported:

 * NSX-T 2.4
 * Ansible 2.7

# Contributing

The ansible-for-nsxt project team welcomes contributions from the community. Before you start working with ansible-for-nsxt, please read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

# Support

The NSX-T Ansible modules in this repository are community supported. For bugs and feature requests please open a Github Issue and label it appropriately. As this is a community supported solution there is no SLA for resolutions.

# License
Copyright (c) 2018 VMware, Inc.  All rights reserved

The NSX-T Ansible modules in this repository are available under [BSD-2 license](https://github.com/vmware/ansible-for-nsxt/blob/master/LICENSE.txt) applies to all parts of the ansible-for-nsxt.
You may not use them except in compliance with the License.†
