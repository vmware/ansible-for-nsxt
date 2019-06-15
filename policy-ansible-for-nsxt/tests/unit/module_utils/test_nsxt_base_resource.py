import unittest
import json
from unittest.mock import Mock, patch

from shutil import copyfile
import ansible.module_utils.basic as ansible_basic

# Copy policy_communicator.py to ansibles' module_utils to test.
import os 
path_policy_ansible_lib = os.getcwd()
path_ansible_lib =  os.path.dirname(os.path.abspath(ansible_basic.__file__)) + "/../"
policy_communicator_file = path_policy_ansible_lib + "/module_utils/policy_communicator.py"

copyfile(policy_communicator_file, path_ansible_lib + "module_utils/policy_communicator.py")

# now import it
from module_utils.nsxt_base_resource import NSXTBaseRealizableResource

# then delete it from ansible's module_utils
os.remove(path_ansible_lib + "module_utils/policy_communicator.py")


class DummyNSXTResource(NSXTBaseRealizableResource):
    def __init__(self, is_dummy_required=False):
        self.is_dummy_required = is_dummy_required

    @staticmethod
    def get_resource_base_url():
        return 'dummy'
    
    @staticmethod
    def get_resource_spec():
        return {
            "dummy": self.is_dummy_required
        }


class NSXTBaseRealizableResourceTestCase(unittest.TestCase):
    def test_realize(self):
        pass
    
    def test_check_for_update(self):
        dummy_resource = DummyNSXTResource()

        def test_with_no_existing_resource():
            self.assertFalse(dummy_resource.check_for_update(None, "dummy"))

        def test_with_same_params():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy": "dummy"}

            self.assertFalse(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_diff_params_simple():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy1": "dummy"}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_same_params_list_same_order():
            existing_params = {"dummy": ["dummy1", "dummy2"]}
            resource_params = {"dummy": ["dummy1", "dummy2"]}

            self.assertFalse(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_same_params_list_different_order():
            existing_params = {"dummy": ["dummy1", "dummy2"]}
            resource_params = {"dummy": ["dummy2", "dummy1"]}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_same_params_single_dict():
            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy": "dummy"}}

            self.assertFalse(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_diff_params_single_dict():
            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy1": "dummy"}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy": "dummy1"}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy1": {"dummy": "dummy"}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_same_params_multilevel_dict():
            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy": "dummy"}}}

            self.assertFalse(dummy_resource.check_for_update(existing_params, resource_params))
        
        def test_with_diff_params_multilevel_dict():
            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy1": {"dummy": {"dummy": "dummy"}}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy1": {"dummy": "dummy"}}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy1": "dummy"}}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy": "dummy1"}}}

            self.assertTrue(dummy_resource.check_for_update(existing_params, resource_params))

        test_with_no_existing_resource()
        test_with_same_params()
        test_with_diff_params_simple()
        test_with_same_params_list_same_order()
        test_with_same_params_list_different_order()
        test_with_same_params_single_dict()
        test_with_diff_params_single_dict()
        test_with_same_params_multilevel_dict()
        test_with_diff_params_multilevel_dict()

    def test_make_ansible_arg_spec(self):
        pass

    def test_update_req_arg_spec_of_specified_resource(self):
        pass

    def test_update_arg_spec_with_resource(self):
        pass
    
    def test_update_arg_spec_with_all_resources(self):
        pass
    
    def test_update_resource_arg_spec_with_arg_identifier(self):
        pass
    
    def test_getAttribute(self):
        pass
    
    def test_extract_resource_params(self):
        pass
    
    def test_achieve_present_state(self):
        pass
    
    def test_achieve_absent_state(self):
        pass
    
    def test_send_request_to_API(self):
        pass
    
    def test_achieve_state(self):
        pass
    
    def test_get_sub_resources_class_of(self):
        pass
    
    def test_wait_till_delete(self):
        pass
    
    def test_wait_till_create(self):
        pass
    
    def test_fill_missing_resource_params(self):
        pass