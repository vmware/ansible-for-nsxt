# Policy API Endpoint Libraries to deploy NSXT Components. 

While library files in the `library` folder provide the means to deploy NSXT elements, the deployments are done 
as groups of various API endpoints to define the element as a whole. This approach minimizes the complexities 
of deploying new elements such as order of operations, validation, and creation of each of the objects that define the 
element. However, advanced users might require to change specific objects without the need or knowledge of all fields 
that define all the objects in an element. 

The `per-endpoint-library` provides library files intended to be used against each of the separate endpoints as defined 
by the [NSXT API documentation](https://code.vmware.com/apis/696/nsx-t). Additionally, these libraries are not intended 
to replace the library files in the `library` folder, but to enhance the user experience based on specific use cases. 

## Use Cases and Benefits
- Individual object changes as opposed to elements as a whole.
- Ease of object creation or changes to objects without the requirement of creating an Ansible play with all fields and 
object definitions. 
- Best suitable when dynamically creating Ansible plays intended to make minimal or additional changes to a new or 
existing deployment.
 
## Drawbacks
-  Order of operations: Referenced objects must exist before referencing them. 


## Object references
The `display_name` is used to validate and confirm the existence of referenced objects. For example, the Play bellow 
utilizes the segment display_name `SEGMENT-TEST` to validate and ensure that the segment exists before attempting to 
create an interface attached to the segment. The same applies to the `tier0`, `locale_services`, and `edge` fields:

``` ---
- name: Create T0 Interfaces
  nsxt_t0_interfaces:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    display_name: "T0-INTERFACE-TEST"
    description: "T0 Interface deployment test"
    tier0: "T0-TEST"
    locale_service: "T0-TEST-LOCALE-SERVICES"
    mtu: 1500
    segment: SEGMENT-TEST
    edge: EDGE-TEST 
    subnets:
      - ip_addresses:
          - "10.1.1.1"
        prefix_len: 24
    state: present 
```

 
## Required Function files

- rest_functions.py
- nsxt_utils.py

