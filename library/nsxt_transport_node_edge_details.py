import yaml
import yamlordereddictloader
from collections import OrderedDict

import logging
logger = logging.getLogger('Transport Node Edge Details')
hdlr = logging.FileHandler('/var/log/chaperone/ChaperoneNSXtLog.log')
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(funcName)s: %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(10)

def main():
    module = AnsibleModule(
        argument_spec=dict(
        ),
        supports_check_mode=True
    )

    final_dict = {}
    main_dict = {}
    main_list= list()
    stream1 = open('/var/lib/chaperone/answerfile.yml', 'r')    
    dict1 = yaml.load(stream1, Loader=yamlordereddictloader.Loader)

    try:
        for data in dict1:
            if data.startswith('check_edge_ips') == True:
                content = dict1['check_edge_ips']
        logger.info(content)
        for edge_inf in dict1:
            if 'ip' in edge_inf and 'nsx_edge' in edge_inf:
                main_dict["ip_address"] = dict1[edge_inf]
                main_list.append(main_dict)
                main_dict={}

        logger.info(main_list)
        logger.info(content)
        if content == '1':
            final_dict['transport_edge_nodes'] = main_list
            module.exit_json(changed= True,id=final_dict, msg = "Successfully got the Transport Edge Nodes information")
        else:
            main_list =[]
            module.exit_json(changed= True,id=main_list, msg = "No Edge Transport Nodes")
       
        
                    
    except Exception as err:
        module.fail_json(changed=False, msg= "Failure: %s" %(err))

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
