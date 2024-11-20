#!/usr/bin/env python
# -*- coding: utf-8 -*-
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


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils import common_utils


class CommonUtilsTestCase(unittest.TestCase):
    def test_deep_same(self):
        def test_with_same_none_none():
            a = None
            b = None

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_no_a():
            a = None
            b = 1

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_no_b():
            a = 1
            b = None

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_params():
            a = 1
            b = 1

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_diff_params_simple():
            a = 1
            b = "dummy"

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_scalar_mix():
            a = [1, "dummy"]
            b = [1, "dummy"]

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_diff_scalar_mix():
            a = [1, "dummy"]
            b = [2, "dummy"]

            self.assertFalse(common_utils.deep_same(a, b))

            a = [1, "dummy"]
            b = {"dummy": 1}

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_params_list_same_order():
            a = ["dummy1", "dummy2"]
            b = ["dummy1", "dummy2"]

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_same_params_list_different_order():
            a = ["dummy1", "dummy2"]
            b = ["dummy2", "dummy1"]

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_same_params_single_dict():
            a = {"dummy": "dummy"}
            b = {"dummy": "dummy"}

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_diff_params_single_dict():
            a = {"dummy": "dummy"}
            b = {"dummy1": "dummy"}

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": "dummy"}
            b = {"dummy": "dummy1"}

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": {"dummy": "dummy"}}
            b = {"dummy1": {"dummy": "dummy"}}

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_params_multilevel_dict():
            a = {"dummy": {"dummy": {"dummy": "dummy"}}}
            b = {"dummy": {"dummy": {"dummy": "dummy"}}}

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_diff_params_multilevel_dict():
            a = {"dummy": {"dummy": {"dummy": "dummy"}}}
            b = {"dummy1": {"dummy": {"dummy": "dummy"}}}

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": {"dummy": {"dummy": "dummy"}}}
            b = {"dummy": {"dummy1": {"dummy": "dummy"}}}

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": {"dummy": {"dummy": "dummy"}}}
            b = {"dummy": {"dummy": {"dummy1": "dummy"}}}

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": {"dummy": {"dummy": "dummy"}}}
            b = {"dummy": {"dummy": {"dummy": "dummy1"}}}

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_params_multilevel_list_dict():
            a = [{"dummy": "dummy"}]
            b = [{"dummy": "dummy"}]

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_diff_params_multilevel_list_dict():
            a = [{"dummy": "dummy"}]
            b = [{"dummy": "dummy1"}]

            self.assertFalse(common_utils.deep_same(a, b))

            a = {"dummy": [{"dummy1": "dummy"}]}
            b = {"dummy": [{"dummy": "dummy"}]}

            self.assertFalse(common_utils.deep_same(a, b))

        def test_with_same_params_multilevel_list_dict_same_order():
            a = [{"dummy": "dummy"}, {"dummy1": "dummy1"}]
            b = [{"dummy": "dummy"}, {"dummy1": "dummy1"}]

            self.assertTrue(common_utils.deep_same(a, b))

        def test_with_same_params_multilevel_list_dict_different_order():
            a = [{"dummy": "dummy"}, {"dummy1": "dummy1"}]
            b = [{"dummy1": "dummy1"}, {"dummy": "dummy"}]

            self.assertTrue(common_utils.deep_same(a, b))

        test_with_same_none_none()
        test_with_no_a()
        test_with_no_b()
        test_with_same_params()
        test_with_diff_params_simple()
        test_with_same_scalar_mix()
        test_with_diff_scalar_mix()
        test_with_same_params_list_same_order()
        test_with_same_params_list_different_order()
        test_with_same_params_single_dict()
        test_with_diff_params_single_dict()
        test_with_same_params_multilevel_dict()
        test_with_diff_params_multilevel_dict()
        test_with_same_params_multilevel_list_dict()
        test_with_diff_params_multilevel_list_dict()
        test_with_same_params_multilevel_list_dict_same_order()
        test_with_same_params_multilevel_list_dict_different_order()

    def test_check_for_update(self):

        def test_with_no_existing_resource():
            self.assertFalse(common_utils.check_for_update(
                None, "dummy"))

        def test_with_same_params():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy": "dummy"}

            self.assertFalse(common_utils.check_for_update(
                existing_params, resource_params))

        def test_with_diff_params_simple():
            existing_params = {"dummy": "dummy"}
            resource_params = {"dummy1": "dummy"}

            self.assertTrue(common_utils.check_for_update(
                existing_params, resource_params))

        test_with_no_existing_resource()
        test_with_same_params()
        test_with_diff_params_simple()

    def test_format_for_ansible_diff(self):
        def test_with_scalars():
            self.assertEqual(common_utils.format_for_ansible_diff(1, True),
                             {"before": 1, "after": True})

        def test_with_list():
            self.assertEqual(common_utils.format_for_ansible_diff([1, 2, 3], [1, 2, 4]),
                             {"before": [1, 2, 3], "after": [1, 2, 4]})

        def test_with_dict():
            self.assertEqual(
                common_utils.format_for_ansible_diff(
                    {"dummy": {"dummy1": 1}}, {"dummy": {"dummy2": 2}}
                ),
                {"before": {"dummy": {"dummy1": 1}}, "after": {"dummy": {"dummy2": 2}}}
            )

        test_with_scalars()
        test_with_list()
        test_with_dict()

    def test_diff_for_update(self):
        def test_both_none():
            self.assertEqual(common_utils.diff_for_update(None, None),
                             (False, {"before": {}, "after": {}}))

        def test_both_empty():
            self.assertEqual(common_utils.diff_for_update({}, {}),
                             (False, {"before": {}, "after": {}}))

        def test_existing_none():
            self.assertEqual(
                common_utils.diff_for_update(None, {"dummy": "dummy"}),
                (False, {"before": {"dummy": None}, "after": {"dummy": "dummy"}})
            )

        def test_existing_empty():
            self.assertEqual(
                common_utils.diff_for_update({}, {"dummy": "dummy"}),
                (False, {"before": {"dummy": None}, "after": {"dummy": "dummy"}})
            )

        def test_resource_none():
            self.assertEqual(
                common_utils.diff_for_update({"dummy": "dummy"}, None),
                (False, {"before": {}, "after": {}})
            )

        def test_resource_empty():
            self.assertEqual(
                common_utils.diff_for_update({"dummy": "dummy"}, {}),
                (False, {"before": {}, "after": {}})
            )

        def test_default_strict_keys():
            self.assertEqual(
                common_utils.diff_for_update(
                    {"dummy": "dummy", "dummy1": "dummy1"},
                    {"dummy1": "dummy1", "dummy2": "dummy2"},
                ),
                (
                    True,
                    {
                        "before": {"dummy1": "dummy1", "dummy2": None},
                        "after": {"dummy1": "dummy1", "dummy2": "dummy2"}
                    }
                )
            )

        def test_explicit_strict_keys():
            self.assertEqual(
                common_utils.diff_for_update(
                    {"dummy": "dummy", "dummy1": "dummy1"},
                    {"dummy": "dummy", "dummy2": "dummy2"},
                    ["dummy"]
                ),
                (False, {"before": {"dummy": "dummy"}, "after": {"dummy": "dummy"}})
            )

        def test_explicit_lazy_keys():
            self.assertEqual(
                common_utils.diff_for_update(
                    {"dummy": "dummy", "dummy1": "dummy1"},
                    {"dummy": "dummy", "dummy2": "dummy2", "dummy3": "dummy3"},
                    ["dummy"],
                    ["dummy3"]
                ),
                (False, {"before": {"dummy": "dummy"}, "after": {"dummy": "dummy"}})
            )

        def test_overlap_strict_lazy_keys():
            self.assertEqual(
                common_utils.diff_for_update(
                    {"dummy": "dummy", "dummy1": "dummy1"},
                    {"dummy": "dummy", "dummy2": "dummy2", "dummy3": "dummy3"},
                    ["dummy", "dummy3"],
                    ["dummy3"]
                ),
                (False, {"before": {"dummy": "dummy"}, "after": {"dummy": "dummy"}})
            )

        test_both_none()
        test_both_empty()
        test_existing_none()
        test_existing_empty()
        test_resource_none()
        test_resource_empty()
        test_default_strict_keys()
        test_explicit_strict_keys()
        test_explicit_lazy_keys()
        test_overlap_strict_lazy_keys()
