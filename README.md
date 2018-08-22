# ansible-for-nsxt

## Overview
This repository contains NSX-T Ansible Modules, which one can use with
Ansible to work with [VMware NSX-T][vmware-nsxt].

[vmware-nsxt]: https://www.vmware.com/products/nsx.html

For general information about Ansible, visit the [GitHub project page][an-github].

[an-github]: https://github.com/ansible/ansible

These modules are maintained by [VMware](https://www.vmware.com/).

Documentation on the NSX platform can be found at the [NSX-T Documentation page](https://docs.vmware.com/en/VMware-NSX-T/index.html)

## Try it out

### Prerequisites
We assume you already have ansible installed. 
Connecting VMs to NSX-T Logical Switches is supported from Ansible 2.6. 
Anyway, using the modules in this repo is also possible with eralier versions.
https://github.com/ansible/ansible/pull/37979

* PyVmOmi - you need it for the initial .ova deployment only
```
pip install --upgrade pyvmomi pyvim requests ssl
```

* OVF Tools
Again for the initial OVA deployment only


### Build & Run
git clone https://github.com/vmware/ansible-for-nsxt.git

## Documentation
Work in Progress ...

## Releases & Major Branches

# Interoperability

The following versions of NSX are supported:

 * NSX-T 2.2.*

# Contributing

The ansible-for-nsxt project team welcomes contributions from the community. Before you start working with ansible-for-nsxt, please read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

# License
Copyright (c) 2018 VMware, Inc.  All rights reserved

The NSX-T Ansible modules in this repository are available under [BSD-2 license](https://github.com/vmware/ansible-for-nsxt/blob/master/LICENSE.txt) applies to all parts of the ansible-for-nsxt.
You may not use them except in compliance with the License.†
