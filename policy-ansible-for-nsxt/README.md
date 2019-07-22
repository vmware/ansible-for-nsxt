# Ansible for NSX-T Policy API

This project supports the creation, update, and deletion of NSX-T resources using the latest Policy API.

## Prerequisites
1. Python3 >= 3.5.2
2. Ansible >= 2.8.1

## Unit Testing
To test the Ansible modules or see examples of playbooks, please put the respective playbook from unit_tests folder to the base folder and run the ansible-playbook.

Please note that you must specify the correct vmware args in order to successfully update the resources.

## NSX-T Resources Supported
1. Tier-0 Gateway
   1. Tier-0 Locale Services
   2. Tier-0 Interface
2. Tier-1 Gateway
   1. Tier-1 Locale Services
   2. Tier-1 Interface
3. Segment
   1. Segment Port
4. Policy Group
5. Security Policy and Firewall rules
6. IP Pools
7. IP Blocks

Note that to add a new modules, it's base class name should be added in the BASE_RESOURCES in modules/nsxt_base_resource.py