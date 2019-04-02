# Deploy NSX-T Cluster

# Overview
The set of playbooks in this example deploy a full NSX Cluster. The playbooks
are divided based on the workflow.

There are 3 main playbooks and a common variable files:

* 01_deploy_first_node.yml
* 02_configure_compute_manager.yml
* 03_deploy_second_third_node.yml
* deploy_nsx_cluster_vars.yml

To run the example, copy all the files two-levels up, edit the variables file
to match your needs and run the playbooks in the order listed.

Validated against:
* NSX-T 2.4 GA

It currently does not configure a cluster Virtual IP
