import yaml
import yamlordereddictloader
from collections import OrderedDict

import logging
logger = logging.getLogger('Transport Node Host Details')
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
    sub_dict = {}
    main_dict = {}
    main_list= list()
    content_dict={}
    final_list = list()
    imp_list=list()
    stream1 = open('/var/lib/chaperone/answerfile.yml', 'r')    
    dict1 = yaml.load(stream1, Loader=yamlordereddictloader.Loader)

    try:
        for data in dict1:
            if data.startswith('check_compute_cluster') == True:
                sub_dict[data] = dict1[data]
        for count in range(len(sub_dict)):
            cluster= "cluster"+str(count+1)
            for content in dict1:
                if 'ip' in content and 'esxi_compute'+str(count+1) in content: 
                    main_list.append(dict1[content])
            main_dict[cluster] = main_list
            main_list=[]

        for check in range(len(sub_dict)):
            if(sub_dict["check_compute_cluster"+str(check+1)] == '1'):
                for i in main_dict["cluster"+str(check+1)]:
                    final_list.append(i)
        for key in range(len(final_list)):
            logger.info(final_list[key])
            content_dict["ip_address"]=final_list[key]
            imp_list.append(content_dict)
            content_dict={}
        logger.info(imp_list)
        final_dict['transport_host_nodes'] = imp_list
        module.exit_json(changed= True,id=final_dict, msg = "Successfully got the Transport Host Nodes information")
        
                    
    except Exception as err:
        module.fail_json(changed=False, msg= "Failure: %s" %(err))

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
