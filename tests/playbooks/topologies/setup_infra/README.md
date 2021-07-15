# Setup Day-1 Infra

# Overview
The set of playbooks in this example deploy all the Day-1 Infra objects needed
to start using NSX-T. The playbooks are divided based on the workflow.

There are 4 main playbooks and a common variable file:

* 01_setup_transport_zones.yml
* 02_setup_TEP_IP_Pools.yml: In this example, a single IP Pool is used to provide TEP IP for both Edge and Host Transport nodes.
* 03_setup_transport_node_profiles.yml
* 04_setup_transport_nodes.yml: Creates both Edge and Host Transport nodes
* 05_setup_edge_cluster.yml
* setup_infra_vars.yml: The variables file

To delete all objects, change the 'state' to 'absent' in the variables file and run the playbooks in the reverse order:

* 05_setup_edge_cluster.yml
* 04_setup_transport_nodes.yml
* 03_setup_transport_node_profiles.yml
* 02_setup_TEP_IP_Pools.yml
* 01_setup_transport_zone.yml

Validated against:
* NSX-T 2.4 GA
* NSX-T 2.5 GA
