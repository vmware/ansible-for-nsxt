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

from module_utils.policy_communicator import PolicyCommunicator
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError


class PolicyCommunicatorTestCase(unittest.TestCase):
    def setUp(self):
        self.policy_communicator = PolicyCommunicator.get_instance(
            "dummy", "dummy", "dummy")

    def test_get_instance_with_same_credentials(self):
        pc1 = PolicyCommunicator.get_instance("dummy1", "dummy1", "dummy1")
        pc2 = PolicyCommunicator.get_instance("dummy1", "dummy1", "dummy1")

        self.assertEqual(pc1, pc2)

    def test_get_instance_with_different_credentials(self):
        pc1 = PolicyCommunicator.get_instance("dummy1", "dummy1", "dummy1")
        pc2 = PolicyCommunicator.get_instance("dummy2", "dummy2", "dummy2")

        self.assertNotEqual(pc1, pc2)

    @patch("module_utils.policy_communicator.open_url")
    def test_request_success_policy_response_with_success(self, mock_open_url):
        pc = self.policy_communicator

        expected_rc = 200
        expected_response = '{"dummy": "dummy"}'

        mock_response = Mock()
        mock_response.getcode.return_value = expected_rc
        mock_response.read.return_value.decode.return_value = expected_response
        mock_open_url.return_value = mock_response

        rc, response = pc.request("dummy")

        self.assertEqual(rc, 200)
        self.assertEqual(response, json.loads(expected_response))

    @patch("module_utils.policy_communicator.open_url")
    def test_request_success_policy_response_with_none(self, mock_open_url):
        pc = self.policy_communicator

        expected_rc = 200
        expected_response = None

        mock_fp = Mock()
        mock_fp.getcode.return_value = 200
        mock_fp.read.return_value.decode.return_value = expected_response
        mock_open_url.side_effect = HTTPError(
            url="dummy", code="dummy", msg=None, fp=mock_fp, hdrs=None)

        rc, response = pc.request("dummy")

        self.assertEqual(rc, 200)
        self.assertEqual(response, None)

    @patch("module_utils.policy_communicator.open_url")
    def test_request_success_policy_response_with_error(self, mock_open_url):
        pc = self.policy_communicator

        expected_rc = 200
        expected_response = '{"error_code": "5000212"}'

        mock_fp = Mock()
        mock_fp.getcode.return_value = 200
        mock_fp.read.return_value.decode.return_value = expected_response
        mock_open_url.side_effect = HTTPError(
            url="dummy", code="dummy", msg=None, fp=mock_fp, hdrs=None)

        with self.assertRaises(Exception):
            rc, response = pc.request("dummy")

    @patch("module_utils.policy_communicator.open_url")
    def test_request_failure(self, mock_open_url):
        pc = self.policy_communicator

        mock_response = Mock()
        mock_response.getcode.return_value = 400
        mock_response.read.return_value.decode.return_value = (
            '{"dummy": "dummy"}')
        mock_open_url.return_value = mock_response

        with self.assertRaises(Exception):
            rc, response = pc.request("dummy")
