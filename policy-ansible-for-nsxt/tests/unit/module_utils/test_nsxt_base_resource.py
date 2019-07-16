#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import unittest
import json
from unittest.mock import Mock, patch

from shutil import copyfile
import ansible.module_utils.basic as ansible_basic

# Copy policy_communicator.py to ansibles' module_utils to test.
import os
path_policy_ansible_lib = os.getcwd()
path_ansible_lib = os.path.dirname(
    os.path.abspath(ansible_basic.__file__)) + "/../"
policy_communicator_file = (
    path_policy_ansible_lib + "/module_utils/policy_communicator.py")

copyfile(policy_communicator_file,
         path_ansible_lib + "module_utils/policy_communicator.py")

# now import it
import module_utils.nsxt_base_resource as nsxt_base_resource
from ansible.module_utils.policy_communicator import PolicyCommunicator

# then delete it from ansible's module_utils
os.remove(path_ansible_lib + "module_utils/policy_communicator.py")


class SimpleDummyNSXTResource(nsxt_base_resource.NSXTBaseRealizableResource):
    def __init__(self):
        self.resource_class = self.__class__
        self.validate_certs = False
        self.baseline_args = {}

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return 'dummy'

    @staticmethod
    def get_resource_spec():
        return {
            "dummy": dict(
                required=False
            )
        }


class NestedDummyNSXTResource(nsxt_base_resource.NSXTBaseRealizableResource):
    def __init__(self):
        self.resource_class = self.__class__
        self.validate_certs = False
        self.baseline_args = {}
        self.do_create_or_update_subresource_first = False
        self.do_delete_subresource_first = True

    @staticmethod
    def get_resource_base_url(baseline_args=None):
        return 'dummy'

    @staticmethod
    def get_resource_spec():
        return {
            "dummy": dict(
                required=False
            )
        }

    def create_or_update_subresource_first(self):
        # return True if subresource should be created/updated before parent
        # resource
        return self.do_create_or_update_subresource_first

    def delete_subresource_first(self):
        # return True if subresource should be deleted before parent resource
        return self.do_delete_subresource_first

    class SubDummyResource1(nsxt_base_resource.NSXTBaseRealizableResource):
        # This one does not override get_unique_arg_identifier
        def __init__(self):
            NestedDummyNSXTResource.__init__(self)

        @staticmethod
        def get_resource_base_url():
            return 'sub_dummy1'

        @staticmethod
        def get_resource_base_url(parent_info):
            parent_id = parent_info.get(
                "NestedDummyNSXTResource_id", 'default')
            return '{}-sub_dummy1'.format(parent_id)

        @staticmethod
        def get_resource_spec():
            return {
                "sub_dummy1": dict(
                    required=True
                )
            }

        def achieve_subresource_state_if_del_parent(self):
            # return True if the resource is to be realized with its own
            # specified state irrespective of the state of its parent resource.
            return True

    class SubDummyResource2(nsxt_base_resource.NSXTBaseRealizableResource):
        # This one overrides get_unique_arg_identifier
        def __init__(self):
            NestedDummyNSXTResource.__init__(self)

        def get_unique_arg_identifier(self):
            return (
                NestedDummyNSXTResource.SubDummyResource2.
                get_unique_arg_identifier())

        @staticmethod
        def get_unique_arg_identifier():
            return "sub_dummy_res_2"

        @staticmethod
        def get_resource_base_url(parent_info):
            parent_id = parent_info.get(
                "NestedDummyNSXTResource_id", 'default')
            return '{}-sub_dummy2'.format(parent_id)

        @staticmethod
        def get_resource_spec():
            return {
                "sub_dummy2": dict(
                    required=True
                )
            }


class MockAnsible(object):
    def __init__(self, params={}, check_mode=False):
        self.params = params
        self.check_mode = check_mode

    def fail_json(self, *args, **kwargs):
        pass


class NSXTBaseRealizableResourceTestCase(unittest.TestCase):
    def setUp(self):
        self.init_base_resources = nsxt_base_resource.BASE_RESOURCES
        return super().setUp()

    def tearDown(self):
        nsxt_base_resource.BASE_RESOURCES = self.init_base_resources
        return super().tearDown()

    @patch('module_utils.nsxt_base_resource.PolicyCommunicator')
    @patch('module_utils.nsxt_base_resource.AnsibleModule')
    def test_realize(self, mock_ansible_module, mock_policy_communicator):
        init_base_resources = nsxt_base_resource.BASE_RESOURCES
        nsxt_base_resource.BASE_RESOURCES = {"NestedDummyNSXTResource"}

        nested_dummy_resource = NestedDummyNSXTResource()
        nested_dummy_resource.resource_class = nested_dummy_resource.__class__

        my_params = None

        def my_getitem(id):
            return my_params[id]

        def my_get(id, default):
            return my_params.get(id, default)

        def my_pop(id):
            return my_params.pop(id)

        def my_contains(id):
            return id in my_params

        mock_ansible_module.return_value.params.__getitem__.side_effect = (
            my_getitem)
        mock_ansible_module.return_value.params.__contains__.side_effect = (
            my_contains)
        mock_ansible_module.return_value.params.get.side_effect = my_get
        mock_ansible_module.return_value.params.pop.side_effect = my_pop

        mock_ansible_module.return_value.check_mode = False

        nested_dummy_resource.module = mock_ansible_module

        mock_policy_communicator_instance = Mock()

        mock_policy_communicator.get_instance.return_value = (
            mock_policy_communicator_instance)

        mock_policy_communicator_instance.request.return_value = (200, "OK")

        def test_create():
            # when all resources state is present
            nonlocal my_params
            my_params = {
                "hostname": "dummy",
                "username": "dummy",
                "password": "dummy",
                "validate_certs": False,
                "state": "present",
                "id": "dummy",
                "SubDummyResource1_state": "present",
                "SubDummyResource1_id": "dummy1",
                "sub_dummy_res_2_state": "present",
                "sub_dummy_res_2_id": "dummy2",
            }
            expected_exec_logs = [
                {
                    'body': 'OK',
                    'resource_type': 'NestedDummyNSXTResource',
                    'message': ('NestedDummyNSXTResource with id dummy'
                                ' created.'),
                    'changed': True,
                    'id': 'dummy'
                },
                {
                    'body': 'OK',
                    'resource_type': 'SubDummyResource1',
                    'message': 'SubDummyResource1 with id dummy1 created.',
                    'changed': True,
                    'id': 'dummy1'
                },
                {
                    'body': 'OK',
                    'resource_type': 'SubDummyResource2',
                    'message': 'SubDummyResource2 with id dummy2 created.',
                    'changed': True,
                    'id': 'dummy2'
                }
            ]

            def test_create_base_resource_first():
                exec_logs = []
                nested_dummy_resource.realize(
                    successful_resource_exec_logs=exec_logs)
                self.assertEqual(exec_logs[0], expected_exec_logs[0])
                self.assertCountEqual(exec_logs[1:], expected_exec_logs[1:])

            def test_create_sub_resource_first():
                nonlocal my_params
                my_params['id'] = 'dummy'
                my_params["SubDummyResource1_id"] = "dummy1"
                my_params["sub_dummy_res_2_display_name"] = "dummy2"
                nested_dummy_resource.do_create_or_update_subresource_first = (
                    True)
                exec_logs = []
                nested_dummy_resource.realize(
                    successful_resource_exec_logs=exec_logs)
                self.assertCountEqual(exec_logs[:2], expected_exec_logs[1:])
                self.assertEqual(exec_logs[2], expected_exec_logs[0])

            test_create_base_resource_first()
            test_create_sub_resource_first()

        def test_delete():
            # when all resources state is absent
            nonlocal my_params
            my_params = {
                "hostname": "dummy",
                "username": "dummy",
                "password": "dummy",
                "validate_certs": False,
                "state": "absent",
                "id": "dummy",
                "SubDummyResource1_state": "absent",
                "SubDummyResource1_id": "dummy1",
                "sub_dummy_res_2_state": "absent",
                "sub_dummy_res_2_id": "dummy2",
            }
            expected_exec_logs = [
                {
                    'msg': 'No SubDummyResource2 exist with id dummy2',
                    'changed': False,
                    'resource_type': 'SubDummyResource2'
                },
                {
                    'msg': 'No SubDummyResource1 exist with id dummy1',
                    'changed': False,
                    'resource_type': 'SubDummyResource1'
                },
                {
                    'msg': 'No NestedDummyNSXTResource exist with id dummy',
                    'changed': False,
                    'resource_type': 'NestedDummyNSXTResource'
                }
            ]

            def test_delete_base_resource_first():
                nested_dummy_resource.do_delete_subresource_first = False
                exec_logs = []
                nested_dummy_resource.realize(
                    successful_resource_exec_logs=exec_logs)
                self.assertEqual(exec_logs[0], expected_exec_logs[2])
                self.assertCountEqual(exec_logs[1:], expected_exec_logs[:2])

            def test_delete_sub_resource_first():
                nonlocal my_params
                my_params['id'] = 'dummy'
                # SubDummyResource1_id and sub_dummy_res_2_display_name are
                # deleted from params. Specify them using display_name.
                # This also tests that user can specify either id or
                # display_name to identify resource.
                my_params["SubDummyResource1_display_name"] = "dummy1"
                my_params["sub_dummy_res_2_display_name"] = "dummy2"
                nested_dummy_resource.do_delete_subresource_first = True
                exec_logs = []
                nested_dummy_resource.realize(
                    successful_resource_exec_logs=exec_logs)
                self.assertEqual(exec_logs[2], expected_exec_logs[2])
                self.assertCountEqual(exec_logs[:2], expected_exec_logs[:2])

            test_delete_base_resource_first()
            test_delete_sub_resource_first()

        def test_detached_delete_parent():
            # when parent is absent but child is present
            nonlocal my_params
            my_params = {
                "hostname": "dummy",
                "username": "dummy",
                "password": "dummy",
                "validate_certs": False,
                "state": "absent",
                "id": "dummy",
                "SubDummyResource1_state": "present",
                "SubDummyResource1_id": "dummy1",
                "sub_dummy_res_2_state": "present",
                "sub_dummy_res_2_id": "dummy2",
            }
            expected_exec_logs = [
                {
                    'msg': 'No SubDummyResource2 exist with id dummy2',
                    'changed': False,
                    'resource_type': 'SubDummyResource2'
                },
                {
                    'resource_type': 'SubDummyResource1',
                    'id': 'dummy1',
                    'body': 'OK',
                    'message': 'SubDummyResource1 with id dummy1 created.',
                    'changed': True
                },
                {
                    'msg': 'No NestedDummyNSXTResource exist with id dummy',
                    'changed': False,
                    'resource_type': 'NestedDummyNSXTResource'
                }
            ]
            nested_dummy_resource.do_delete_subresource_first = True
            (nested_dummy_resource.
             do_achieve_subresource_state_if_del_parent) = (
                False)
            exec_logs = []
            nested_dummy_resource.realize(
                successful_resource_exec_logs=exec_logs)
            self.assertEqual(exec_logs[2], expected_exec_logs[2])
            self.assertCountEqual(exec_logs[:2], expected_exec_logs[:2])

        def test_detached_delete_child():
            # when parent is present but child is absent
            nonlocal my_params
            my_params = {
                "hostname": "dummy",
                "username": "dummy",
                "password": "dummy",
                "validate_certs": False,
                "state": "present",
                "display_name": "dummy",
                "SubDummyResource1_state": "absent",
                "SubDummyResource1_id": "dummy1",
                "sub_dummy_res_2_state": "present",
                "sub_dummy_res_2_id": "dummy2",
            }
            expected_exec_logs = [
                {
                    'changed': False,
                    'resource_type': 'SubDummyResource1',
                    'msg': 'No SubDummyResource1 exist with id dummy1'
                },
                {
                    'message': 'SubDummyResource2 with id dummy2 created.',
                    'changed': True,
                    'body': 'OK',
                    'resource_type': 'SubDummyResource2',
                    'id': 'dummy2'
                },
                {
                    'message': ('NestedDummyNSXTResource with id dummy'
                                ' created.'),
                    'changed': True,
                    'body': 'OK',
                    'resource_type': 'NestedDummyNSXTResource',
                    'id': 'dummy'
                }
            ]
            (nested_dummy_resource.
             do_achieve_subresource_state_if_del_parent) = (
                False)
            exec_logs = []
            nested_dummy_resource.realize(
                successful_resource_exec_logs=exec_logs)
            print(str(exec_logs))
            self.assertEqual(exec_logs[2], expected_exec_logs[2])
            self.assertCountEqual(exec_logs[:2], expected_exec_logs[:2])

        test_create()
        test_delete()
        test_detached_delete_parent()
        test_detached_delete_child()

        nsxt_base_resource.BASE_RESOURCES = init_base_resources

    def test_check_for_update(self):
        simple_dummy_resource = SimpleDummyNSXTResource()

        def test_with_no_existing_resource():
            self.assertFalse(simple_dummy_resource.check_for_update(
                None, "dummy"))

        def test_with_same_params():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy": "dummy"}

            self.assertFalse(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_diff_params_simple():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy1": "dummy"}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_same_params_list_same_order():
            existing_params = {"dummy": ["dummy1", "dummy2"]}
            resource_params = {"dummy": ["dummy1", "dummy2"]}

            self.assertFalse(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_same_params_list_different_order():
            existing_params = {"dummy": ["dummy1", "dummy2"]}
            resource_params = {"dummy": ["dummy2", "dummy1"]}

            self.assertFalse(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_same_params_single_dict():
            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy": "dummy"}}

            self.assertFalse(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_diff_params_single_dict():
            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy1": "dummy"}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy": {"dummy": "dummy1"}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

            existing_params = {"dummy": {"dummy": "dummy"}}
            resource_params = {"dummy1": {"dummy": "dummy"}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_same_params_multilevel_dict():
            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy": "dummy"}}}

            self.assertFalse(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

        def test_with_diff_params_multilevel_dict():
            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy1": {"dummy": {"dummy": "dummy"}}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy1": {"dummy": "dummy"}}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy1": "dummy"}}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

            existing_params = {"dummy": {"dummy": {"dummy": "dummy"}}}
            resource_params = {"dummy": {"dummy": {"dummy": "dummy1"}}}

            self.assertTrue(simple_dummy_resource.check_for_update(
                existing_params, resource_params))

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
        @patch('module_utils.nsxt_base_resource.AnsibleModule')
        def test_when_resource_in_base(mock_ansible_module):
            init_base_resources = nsxt_base_resource.BASE_RESOURCES
            nsxt_base_resource.BASE_RESOURCES = {"SimpleDummyNSXTResource"}
            simple_dummy_resource = SimpleDummyNSXTResource()
            simple_dummy_resource.resource_class = (
                simple_dummy_resource.__class__)
            mock_ansible_module.side_effect = None
            simple_dummy_resource._make_ansible_arg_spec()

            expected_arg_spec = simple_dummy_resource.get_resource_spec()
            expected_arg_spec.update(
                simple_dummy_resource._get_base_arg_spec_of_resource())
            expected_arg_spec.update(
                PolicyCommunicator.get_vmware_argument_spec())

            self.assertTrue(hasattr(simple_dummy_resource, "_arg_spec"))
            self.assertEqual(
                expected_arg_spec, simple_dummy_resource._arg_spec)
            nsxt_base_resource.BASE_RESOURCES = init_base_resources

        def test_when_resource_not_in_base():
            simple_dummy_resource = SimpleDummyNSXTResource()
            simple_dummy_resource._make_ansible_arg_spec()

            self.assertFalse(hasattr(simple_dummy_resource, "_arg_spec"))

        @patch('module_utils.nsxt_base_resource.AnsibleModule')
        def test_with_sub_resource(mock_ansible_module):
            init_base_resources = nsxt_base_resource.BASE_RESOURCES
            nsxt_base_resource.BASE_RESOURCES = {"NestedDummyNSXTResource"}
            nested_dummy_resource = NestedDummyNSXTResource()
            nested_dummy_resource.resource_class = (
                nested_dummy_resource.__class__)
            mock_ansible_module.side_effect = None
            nested_dummy_resource._make_ansible_arg_spec()

            expected_arg_spec = nested_dummy_resource.get_resource_spec()
            expected_arg_spec.update(
                nested_dummy_resource._get_base_arg_spec_of_resource())
            expected_arg_spec.update(
                PolicyCommunicator.get_vmware_argument_spec())

            sub_resources_classes = [NestedDummyNSXTResource.SubDummyResource1,
                                     NestedDummyNSXTResource.SubDummyResource2]
            for sub_resources_class in sub_resources_classes:
                sub_dummy_resource = sub_resources_class()
                expected_sub_dummy_arg_spec = (
                    sub_dummy_resource.get_resource_spec())
                expected_sub_dummy_arg_spec.update(
                    sub_dummy_resource._get_base_arg_spec_of_resource())
                # Prepend unique arg identifier to sub-resource
                sub_dummy_uniquq_arg_id = (
                    sub_dummy_resource.get_unique_arg_identifier())
                for key in list(expected_sub_dummy_arg_spec.keys()):
                    value = expected_sub_dummy_arg_spec.pop(key)
                    expected_sub_dummy_arg_spec[sub_dummy_uniquq_arg_id + "_" +
                                                key] = value

                expected_arg_spec.update(expected_sub_dummy_arg_spec)

            self.assertTrue(hasattr(nested_dummy_resource, "_arg_spec"))
            self.assertEqual(
                expected_arg_spec, nested_dummy_resource._arg_spec)
            nsxt_base_resource.BASE_RESOURCES = init_base_resources

        test_when_resource_in_base()
        test_when_resource_not_in_base()
        test_with_sub_resource()

    def test_get_attribute(self):
        simple_dummy_resource = SimpleDummyNSXTResource()

        def test_when_resource_in_base():
            mock_ansible_module = MockAnsible()
            simple_dummy_resource.module = mock_ansible_module
            init_base_resources = nsxt_base_resource.BASE_RESOURCES
            nsxt_base_resource.BASE_RESOURCES = {"SimpleDummyNSXTResource"}
            mock_ansible_module.params = {
                "dummy": "dummy",
                "SimpleDummyNSXTResource_dummy1": "dummy"
            }
            expected_value = "dummy"
            observed_value = simple_dummy_resource.get_attribute("dummy")
            self.assertEqual(expected_value, observed_value)

            observed_value = simple_dummy_resource.get_attribute("dummy1")
            self.assertEqual(expected_value, observed_value)

            expected_value = (nsxt_base_resource.NSXTBaseRealizableResource.
                              INCORRECT_ARGUMENT_NAME_VALUE)
            observed_value = simple_dummy_resource.get_attribute("dummy2")
            self.assertEqual(expected_value, observed_value)

            nsxt_base_resource.BASE_RESOURCES = init_base_resources

        def test_when_resource_not_in_base():
            mock_ansible_module = MockAnsible()
            simple_dummy_resource.module = mock_ansible_module
            mock_ansible_module.params = {
                "dummy": "dummy",
                "SimpleDummyNSXTResource_dummy1": "dummy"
            }
            expected_value = "dummy"
            observed_value = simple_dummy_resource.get_attribute("dummy1")
            self.assertEqual(expected_value, observed_value)

            expected_value = (nsxt_base_resource.NSXTBaseRealizableResource.
                              INCORRECT_ARGUMENT_NAME_VALUE)
            observed_value = simple_dummy_resource.get_attribute("dummy")
            self.assertEqual(expected_value, observed_value)

            observed_value = simple_dummy_resource.get_attribute("dummy2")
            self.assertEqual(expected_value, observed_value)

        test_when_resource_in_base()
        test_when_resource_not_in_base()

    def test_extract_resource_params(self):
        simple_dummy_resource = SimpleDummyNSXTResource()

        def test_when_resource_in_base():
            init_base_resources = nsxt_base_resource.BASE_RESOURCES
            nsxt_base_resource.BASE_RESOURCES = {"SimpleDummyNSXTResource"}

            mock_ansible_module = MockAnsible()
            simple_dummy_resource.module = mock_ansible_module

            mock_ansible_module.params = {
                # Note that AnsibleModule can have >= keys than the spec
                "dummy": "dummy",
                "redundant_dummy": "dummy"
            }

            expected_params = {
                "dummy": "dummy"
            }

            observed_params = simple_dummy_resource._extract_resource_params()

            self.assertEqual(expected_params, observed_params)

            nsxt_base_resource.BASE_RESOURCES = init_base_resources

        def test_when_resource_not_in_base():
            mock_ansible_module = MockAnsible()
            simple_dummy_resource.module = mock_ansible_module

            mock_ansible_module.params = {
                # Note that AnsibleModule can have >= keys than the spec
                "SimpleDummyNSXTResource_dummy": "dummy",
                "SimpleDummyNSXTResource_redundant_dummy": "dummy"
            }

            expected_params = {
                "dummy": "dummy"
            }

            observed_params = simple_dummy_resource._extract_resource_params()

            self.assertEqual(expected_params, observed_params)

        test_when_resource_in_base()
        test_when_resource_not_in_base()

    @patch('module_utils.policy_communicator.PolicyCommunicator')
    def test_send_request_to_API(self, mock_policy_communicator):
        mock_policy_communicator.request.return_value = (200, "OK")

        init_base_resources = nsxt_base_resource.BASE_RESOURCES
        nsxt_base_resource.BASE_RESOURCES = {"NestedDummyNSXTResource"}

        # Test Base Resource
        nested_dummy_resource = NestedDummyNSXTResource()
        nested_dummy_resource.policy_communicator = mock_policy_communicator
        nested_dummy_resource.validate_certs = False
        nested_dummy_resource.resource_class = nested_dummy_resource.__class__
        nested_dummy_resource._send_request_to_API()

        # Test Sub-Resource
        nested_subdummy_resource1 = (
            NestedDummyNSXTResource.SubDummyResource1())
        nested_subdummy_resource1.policy_communicator = (
            mock_policy_communicator)
        nested_subdummy_resource1.validate_certs = False
        nested_subdummy_resource1.resource_class = (
            nested_subdummy_resource1.__class__)
        nested_subdummy_resource1._parent_info = {
            "NestedDummyNSXTResource_id": "dummy"
        }
        nested_subdummy_resource1._send_request_to_API()

        self.assertEqual(mock_policy_communicator.request.call_count, 2)

        # Test when request throws exception
        with self.assertRaises(Exception):
            mock_policy_communicator.request = Mock()
            mock_policy_communicator.request.raiseError.side_effect = Mock(
                side_effect=Exception)

            nested_dummy_resource = NestedDummyNSXTResource()
            nested_dummy_resource.policy_communicator = (
                mock_policy_communicator)
            nested_dummy_resource.validate_certs = False
            nested_dummy_resource.resource_class = (
                nested_dummy_resource.__class__)
            nested_dummy_resource._send_request_to_API()

        self.assertEqual(mock_policy_communicator.request.call_count, 1)

        nsxt_base_resource.BASE_RESOURCES = init_base_resources

    @patch('module_utils.policy_communicator.PolicyCommunicator')
    def test_achieve_present_state(self, mock_policy_communicator):
        init_base_resources = nsxt_base_resource.BASE_RESOURCES
        nsxt_base_resource.BASE_RESOURCES = {"SimpleDummyNSXTResource"}
        simple_dummy_resource = SimpleDummyNSXTResource()
        simple_dummy_resource.id = "dummy"
        simple_dummy_resource.policy_communicator = mock_policy_communicator
        simple_dummy_resource.module = MockAnsible()
        simple_dummy_resource.existing_resource = {
            "_revision": 1
        }

        def test_when_resource_not_updated():
            simple_dummy_resource.resource_params = {}
            exec_logs = []
            # mock_policy_communicator.request.return_value = None
            simple_dummy_resource._achieve_present_state(exec_logs)

            self.assertEqual(mock_policy_communicator.request.call_count, 0)

            expected_exec_logs = [
                {
                    "changed": False,
                    "id": simple_dummy_resource.id,
                    "message": "%s with id %s already exists." %
                    (simple_dummy_resource.__class__.__name__,
                     simple_dummy_resource.id),
                    "resource_type": simple_dummy_resource.__class__.__name__
                }
            ]
            self.assertEqual(exec_logs, expected_exec_logs)

        policy_communicator_request_call_num = 1

        def test_when_resource_updated(is_created=False):
            def test_when_policy_request_succeeds():
                nonlocal policy_communicator_request_call_num
                simple_dummy_resource.resource_params = {
                    "dummy": "dummy"
                }
                exec_logs = []
                mock_policy_communicator.request.return_value = (200, "OK")
                simple_dummy_resource._achieve_present_state(exec_logs)

                self.assertEqual(mock_policy_communicator.request.call_count,
                                 policy_communicator_request_call_num)
                policy_communicator_request_call_num += 1

                if is_created:
                    expected_message = ("%s with id %s created." %
                                        (simple_dummy_resource.__class__.
                                         __name__, simple_dummy_resource.id))
                else:
                    expected_message = ("%s with id %s updated." %
                                        (simple_dummy_resource.__class__.
                                         __name__, simple_dummy_resource.id))

                expected_exec_logs = [
                    {
                        "changed": True,
                        "id": simple_dummy_resource.id,
                        "body": "OK",
                        "message": expected_message,
                        "resource_type": (
                            simple_dummy_resource.__class__.__name__)
                    }
                ]
                print(exec_logs)
                self.assertEqual(exec_logs, expected_exec_logs)

            def test_when_policy_request_fails():
                nonlocal policy_communicator_request_call_num
                simple_dummy_resource.resource_params = {
                    "dummy": "dummy"
                }
                exec_logs = []
                mock_policy_communicator.request.return_value = Mock(
                    side_effect=Exception)
                simple_dummy_resource._achieve_present_state(exec_logs)
                self.assertEqual(
                    mock_policy_communicator.request.call_count,
                    policy_communicator_request_call_num)
                policy_communicator_request_call_num += 1

            test_when_policy_request_succeeds()
            test_when_policy_request_fails()
            nonlocal policy_communicator_request_call_num

        def test_create_new_resource():
            simple_dummy_resource.existing_resource = None
            test_when_resource_updated(is_created=True)

        test_when_resource_not_updated()
        test_when_resource_updated()
        test_create_new_resource()
        nsxt_base_resource.BASE_RESOURCES = init_base_resources

    @patch('module_utils.policy_communicator.PolicyCommunicator')
    def test_achieve_absent_state(self, mock_policy_communicator):
        init_base_resources = nsxt_base_resource.BASE_RESOURCES
        nsxt_base_resource.BASE_RESOURCES = {"SimpleDummyNSXTResource"}
        simple_dummy_resource = SimpleDummyNSXTResource()
        simple_dummy_resource.id = "dummy"
        simple_dummy_resource.policy_communicator = mock_policy_communicator
        simple_dummy_resource.module = MockAnsible()

        def test_when_resource_exists_but_policy_request_fails():
            simple_dummy_resource.existing_resource = {}
            mock_policy_communicator.request.return_value = Mock(
                side_effect=Exception)

            exec_logs = []
            expected_exec_logs = []

            simple_dummy_resource._achieve_absent_state(exec_logs)

            self.assertEqual(exec_logs, expected_exec_logs)

        def test_when_resource_exists_and_policy_request_succeeds():
            simple_dummy_resource.existing_resource = {}
            mock_policy_communicator.request.side_effect = [
                (200, "OK"),
                Mock(side_effect=Exception)
            ]

            exec_logs = []
            expected_exec_logs = [
                {
                    "changed": True,
                    "id": simple_dummy_resource.id,
                    "message": "%s with id %s deleted." %
                    (simple_dummy_resource.__class__.__name__,
                     simple_dummy_resource.id)
                }
            ]

            simple_dummy_resource._achieve_absent_state(exec_logs)

            self.assertEqual(exec_logs, expected_exec_logs)

        def test_when_resource_does_not_exist():
            simple_dummy_resource.existing_resource = None

            exec_logs = []
            expected_exec_logs = [
                {
                    "changed": False,
                    "msg": 'No %s exist with id %s' %
                    (simple_dummy_resource.__class__.__name__,
                     simple_dummy_resource.id),
                    "resource_type": simple_dummy_resource.__class__.__name__
                }
            ]

            simple_dummy_resource._achieve_absent_state(exec_logs)

            self.assertEqual(exec_logs, expected_exec_logs)

        test_when_resource_exists_but_policy_request_fails()
        test_when_resource_exists_and_policy_request_succeeds()
        test_when_resource_does_not_exist()
        nsxt_base_resource.BASE_RESOURCES = init_base_resources

    def test_get_sub_resources_class_of(self):
        nested_dummy_resource = NestedDummyNSXTResource()

        expected_values = [NestedDummyNSXTResource.SubDummyResource1,
                           NestedDummyNSXTResource.SubDummyResource2]

        observed_values = list(
            nested_dummy_resource._get_sub_resources_class_of(
                nested_dummy_resource.__class__))

        self.assertCountEqual(expected_values, observed_values)

    def test_fill_missing_resource_params(self):
        simple_dummy_resource = SimpleDummyNSXTResource()

        def test_simple():
            def test_overwrite():
                existing_params = {
                    "dummy": "dummy"
                }
                resource_params = expected_resource_params = {
                    "dummy": "new_dummy"
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            def test_missing():
                existing_params = {
                    "dummy": "dummy"
                }
                resource_params = {
                    "dummy1": "dummy1"
                }
                expected_resource_params = {
                    "dummy": "dummy",
                    "dummy1": "dummy1"
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            test_overwrite()
            test_missing()

        def test_with_dict():
            def test_overwrite():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": {
                        "dummy2": "dummy2"
                    }
                }
                resource_params = expected_resource_params = {
                    "dummy": "dummy",
                    "dummy1": {
                        "dummy2": "dummy3"
                    }
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            def test_missing():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": {
                        "dummy2": "dummy2",
                        "dummy3": {
                            "dummy4": "dummy4"
                        }
                    },
                    "dummy5": {
                        "dummy6": "dummy6"
                    }
                }
                resource_params = {
                    "dummy": "dummy1",
                    "dummy1": {
                        "dummy2": "dummy2"
                    }
                }
                expected_resource_params = {
                    "dummy": "dummy1",
                    "dummy1": {
                        "dummy2": "dummy2",
                        "dummy3": {
                            "dummy4": "dummy4"
                        }
                    },
                    "dummy5": {
                        "dummy6": "dummy6"
                    }
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            test_overwrite()
            test_missing()

        def test_with_list():
            def test_overwrite():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy1"]
                }
                resource_params = expected_resource_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy2"]
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            def test_missing():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy1"]
                }
                resource_params = {
                    "dummy": "dummy1"
                }
                expected_resource_params = {
                    "dummy": "dummy1",
                    "dummy1": ["dummy1"]
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            test_overwrite()
            test_missing()

        def test_with_dict_and_list():
            def test_overwrite():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy1"],
                    "dummy2": {
                        "dummy3": ["dummy3"]
                    }
                }
                resource_params = expected_resource_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy2"],
                    "dummy2": {
                        "dummy3": ["dummy4"]
                    }
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            def test_missing():
                existing_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy1"],
                    "dummy2": {
                        "dummy3": ["dummy3"]
                    }
                }
                resource_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy2"],
                    "dummy2": {
                        "dummy4": "dummy4"
                    }
                }
                expected_resource_params = {
                    "dummy": "dummy",
                    "dummy1": ["dummy2"],
                    "dummy2": {
                        "dummy3": ["dummy3"],
                        "dummy4": "dummy4"
                    }
                }
                simple_dummy_resource._fill_missing_resource_params(
                    existing_params, resource_params)

                self.assertEqual(resource_params, expected_resource_params)

            test_overwrite()
            test_missing()

        test_simple()
        test_with_dict()
        test_with_list()
        test_with_dict_and_list()
