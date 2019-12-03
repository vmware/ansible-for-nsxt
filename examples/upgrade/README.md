# Upgrade NSX-T Cluster

# Overview
The set of playbooks in this example does a full NSX upgrade (including
Host Transport Nodes and Edge Transport Nodes). The playbooks
are divided based on the workflow.

There are 7 main playbooks and a common variable files:

* 01_upgrade_upload_mub.yml
* 02_upgrade_accept_eula.yml
* 03_upgrade_uc.yml
* 04_upgrade_update_plan.yml
* [ OPTIONAL ] 05_upgrade_update_groups.yml
* 06_upgrade_prechecks.yml
* 07_upgrade_run.yml
* upgrade_vars.yml

The following playbooks can be used to check the status of different objects during
the upgrade process
<<<<<<< HEAD
check_upgrade_groups_facts.yml
check_upgrade_pre_post_checks_facts.yml
check_upgrade_status_summary_facts.yml

=======

check_upgrade_groups_facts.yml

check_upgrade_pre_post_checks_facts.yml

check_upgrade_status_summary_facts.yml


>>>>>>> 5019aab38a7ad9affda3015001b7db55080318a2
To run the example, copy all the files two-levels up, edit the variables file
to match your needs and run the playbooks in the order listed.

Validated against:
* NSX-T 2.5 GA --> NSX-T 2.5.1 GA
