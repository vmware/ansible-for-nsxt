import json
import hashlib

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible.module_utils.Logger import Logger
logger = Logger.getInstance()


class MockResponse(object):
    def __init__(self, raw, code):
        self.raw = raw
        self.code = code

    def read(self):
        return self.raw

    def getcode(self):
        return self.code


class PolicyCommunicator:

    __instances = dict()

    @staticmethod
    def get_instance(mgr_username, mgr_hostname, mgr_password):
        key = tuple([mgr_username, mgr_hostname, mgr_password])
        if key not in PolicyCommunicator.__instances:
            PolicyCommunicator(mgr_username, mgr_hostname,
                               mgr_password)
        return PolicyCommunicator.__instances.get(key)

    def __init__(self, mgr_username, mgr_hostname, mgr_password):
        key = tuple([mgr_username, mgr_hostname, mgr_password])
        if key in PolicyCommunicator.__instances:
            raise Exception("The associated PolicyCommunicator is"
                            " already present! Please use getInstance to"
                            " retrieve it.")
        else:
            self.mgr_username = mgr_username
            self.policy_url = 'https://{}/policy/api/v1'.format(mgr_hostname)
            self.mgr_password = mgr_password
            self.active_requests = set()

            PolicyCommunicator.__instances[key] = self

    @staticmethod
    def get_vmware_argument_spec():
        return dict(
            hostname=dict(type='str', required=True),
            username=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            port=dict(type='int', default=443),
            validate_certs=dict(type='bool', requried=False, default=True)
        )

    def mock_request(self, data={}):
        r = MockResponse({
                "id": "mock1",
                "name": "mocked_resource",
                "data": data,
                "_revision": 1
            }, 200)
        return r

    def request(self, url, data=None, headers={'Accept': 'application/json',
                'Content-Type': 'application/json'}, method='GET',
                use_proxy=True, force=False, last_mod_time=None,
                timeout=300, validate_certs=True, http_agent=None,
                force_basic_auth=True, ignore_errors=False):
        url = self.policy_url + url
        request_id = self._get_request_id(url, data, method)
        if self.register_request(request_id):
            # new request
            try:
                # connect to the API server
                if data is not None:
                    data = json.dumps(data)
                response = open_url(url=url, data=data, headers=headers,
                                    method=method,
                                    use_proxy=use_proxy, force=force,
                                    last_mod_time=last_mod_time,
                                    timeout=timeout,
                                    validate_certs=validate_certs,
                                    url_username=self.mgr_username,
                                    url_password=self.mgr_password,
                                    http_agent=http_agent,
                                    force_basic_auth=force_basic_auth)
                # r = self.mock_request(data=data)
                resp_code = response.getcode()
                resp_raw_data = response.read().decode('utf-8') or None
                logger.log("Server response: " + str(resp_raw_data))
            except HTTPError as err:
                response = err.fp
                resp_code = response.getcode()
                resp_raw_data = err.fp.read().decode('utf-8')
                logger.log("Server Error Response: " + str(resp_raw_data))

            self.active_requests.remove(request_id)

            try:
                if resp_raw_data:
                    resp_data = json.loads(resp_raw_data)
                elif data is not None:
                    resp_data = json.loads(data)
                else:
                    resp_data = None
            except Exception as e:
                if ignore_errors:
                    pass
                else:
                    raise Exception(resp_raw_data)
            if resp_code >= 400 and not ignore_errors:
                raise Exception(resp_code, None)
            logger.log("Server RC: " + str(resp_data))
            if resp_data is not None and 'error_code' in resp_data:
                logger.log(str(resp_data['error_code']))
                logger.log(str(resp_data))
                raise Exception(resp_data['error_code'], resp_data)
            else:
                return resp_code, resp_data
        else:
            raise DuplicateRequestError

    def _get_request_id(self, url, data=None, method='GET'):
        request = dict()
        request["data"] = data
        request['request_url'] = url
        request['request_method'] = method

        return hashlib.md5(json.dumps(request, sort_keys=True).
                           encode('utf-8')).hexdigest()

    def register_request(self, request_id):
        """
            This creates a hash from URL and data and stores it in a cache.
            If a same hash is created, the request is identified as a duplicate
            and it returns False. Otherwise, returns True.
        """
        if request_id in self.active_requests:
            return False
        self.active_requests.add(request_id)
        return True


class DuplicateRequestError(Exception):
    pass
