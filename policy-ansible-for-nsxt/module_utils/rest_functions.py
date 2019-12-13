#!/usr/bin/python
#
# Copyright (c) 2008-2019 Virtustream Corporation
# All Rights Reserved
#
# This software contains the intellectual property of Virtustream Corporation
# or is licensed to Virtustream Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of Virtustream.

import json
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'

class Rest():

    def __init__(
            self,
            wait=0.3,
            timeout=15,
            verify=True,
            auth=None,
            port=443,
            cookies=None,
            validate_certs=True,
            headers=None,
            retries=3

    ):

        request_session = requests.session()
        self.wait = wait
        self.timeout = timeout
        self.auth = auth
        self.verify = verify
        self.port = port
        self.cookies = cookies
        self.validate_certs = validate_certs
        self.headers = headers if headers is not None else {"Content-Type": "application/json",
                                                            "Accept": "application/json"}
        self.endpoint = None
        self.token = None
        self.retries = retries
        self.session = request_session

    def __repr__(self):
        return "Rest( retries={retries}, wait={wait}, " \
               "timeout={timeout}, verify={verify}, auth={auth} )" \
               "port={port}, cookies={cookies}, validate_certs={validate_certs}, headers={headers}" \
            .format(
            retries=self.retries,
            wait=self.wait,
            timeout=self.timeout,
            verify=self.verify,
            auth=self.auth,
            port=self.port,
            cookies=self.cookies,
            validate_certs=self.validate_certs,
            headers=self.headers,
        )

    def _requests_retry_session(self):

        status_forcelist = (500, 502, 504),

        retry = Retry(
            total=self.retries,
            read=self.retries,
            connect=self.retries,
            backoff_factor=self.wait,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        return self.session

    def _update_endpoint(self, endpoint):

        if self.port == 443:
            if "https://" not in endpoint:
                endpoint = "https://{}".format(endpoint)
        elif self.port == 80:
            if "http://" not in endpoint:
                endpoint = "http://{}".format(endpoint)
        elif self.port:
            if ":{}".format(self.port) not in endpoint:
                split_endpoint = endpoint.split("/")
                if "http" not in split_endpoint[0]:
                    split_endpoint[0] += ":{}".format(self.port)
                else:
                    split_endpoint[2] += ":{}".format(self.port)
                endpoint = "".join(split_endpoint)

        if "http" not in endpoint:
            endpoint = "".join(["http://", endpoint])

        return endpoint

    def _update_session_params(self):
        if self.headers:
            self.session.headers = self.headers
        if self.cookies:
            self.session.cookies = self.cookies
        if self.auth:
            self.session.auth = self.auth

    def authenticate(self, username, password, endpoint=None, auth_type="basic", payload=None, **kwargs):
        response = None
        valid_auth_types = ["basic", "cookies", "token"]

        if auth_type not in valid_auth_types:
            raise TypeError("Invalid auth type {} \r"
                            'Valid requests types: ["basic", "cookies", "token"]'
                            .format(auth_type)
                            )

        self._update_session_params()

        if auth_type != "basic" and not endpoint:
            raise TypeError("Missing auth endpoint for type {}".format(auth_type))

        elif auth_type == "basic":
            self.session.auth = (username, password)

        elif auth_type == "cookies":
            response = self._requests_retry_session().post(self._update_endpoint(endpoint),
                                                           timeout=self.timeout,
                                                           verify=self.validate_certs,
                                                           data=json.dumps(payload),
                                                           **kwargs)
            self.session.cookies = response.cookies

        elif auth_type == "token":
            response = self._requests_retry_session().post(self._update_endpoint(endpoint),
                                                           timeout=self.timeout,
                                                           verify=self.validate_certs,
                                                           data=json.dumps(payload),
                                                           **kwargs)
            self.token = response

        return True, response

    def get(self, endpoint, **kwargs):
        """
        GET routine for Rest.

        Parameters:
            endpoint (str): Rest endpoint.
        Returns:
            Response from Rest.
        """

        self._update_session_params()
        endpoint = self._update_endpoint(endpoint)
        response = self._requests_retry_session().get(endpoint,
                                                      timeout=self.timeout,
                                                      verify=self.validate_certs,
                                                      **kwargs)

        return response

    def post(self, endpoint, payload, **kwargs):
        """
        POST routine for Rest.

        Parameters:
            endpoint (str): Rest endpoint.
            payload (object): Payload to send with endpoint.
        Returns:
            Response from Rest.
        """

        self._update_session_params()
        endpoint = self._update_endpoint(endpoint)
        response = self._requests_retry_session().post(endpoint,
                                                       data=json.dumps(payload),
                                                       timeout=self.timeout,
                                                       verify=self.validate_certs,
                                                       **kwargs)
        return response

    def put(self, endpoint, payload, **kwargs):
        """
        PUT routine for Rest.

        Parameters:
            endpoint (str): Rest endpoint.
            payload (object): Payload to send with endpoint.
        Returns:
            Response from Rest.
        """

        self._update_session_params()
        endpoint = self._update_endpoint(endpoint)
        response = self._requests_retry_session().put(endpoint,
                                                      data=json.dumps(payload),
                                                      timeout=self.timeout,
                                                      verify=self.validate_certs,
                                                      **kwargs)

        return response

    def delete(self, endpoint, **kwargs):
        """
        DELETE routine for Rest.

        Parameters:
            endpoint (str): Rest endpoint.
        Returns:
            Response from Rest.
        """

        self._update_session_params()
        endpoint = self._update_endpoint(endpoint)
        response = self._requests_retry_session().delete(endpoint,
                                                         timeout=self.timeout,
                                                         verify=self.validate_certs,
                                                         **kwargs)

        return response
