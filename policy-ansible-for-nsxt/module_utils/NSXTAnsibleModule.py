from ansible.module_utils.PolicyCommunicator import PolicyCommunicator
from ansible.module_utils.PolicyCommunicator import DuplicateRequestError
import ansible.module_utils.constants as constants

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

from abc import ABC, abstractmethod

import time
import json

import inspect

from ansible.module_utils.Logger import Logger
logger = Logger.getInstance()


class NSXTAnsibleResource(ABC):

    INCORRECT_ARGUMENT_NAME_VALUE = "error_invalid_parameter"

    def __init__(self, resource_arg_spec, resource_class,
                 supports_check_mode=True):
        resource_arg_spec.update(
            # these are the base args for an NSXT Resource
            id=dict(
                required=True,
                type='str'
            ),
            display_name=dict(
                required=True,
                type='str'
            ),
            tags=dict(
                required=False,
                type='dict',
                scope=dict(
                    required=False,
                    type='str'
                ),
                tag=dict(
                    required=False,
                    type='str'
                )
            ),
            state=dict(
                required=True,
                choices=['present', 'absent']
            )
        )
        self.resource_class = resource_class
        self.arg_spec = PolicyCommunicator.get_vmware_argument_spec()
        self.resource_arg_spec = resource_arg_spec
        self.arg_spec.update(resource_arg_spec)

        self.module = AnsibleModule(argument_spec=self.arg_spec,
                                    supports_check_mode=supports_check_mode)

        mgr_hostname = self.module.params['hostname']
        mgr_username = self.module.params['username']
        mgr_password = self.module.params['password']

        self.policy_communicator = PolicyCommunicator.get_instance(
            mgr_username, mgr_hostname, mgr_password)

        self.validate_certs = self.getAttribute('validate_certs')
        self._state = self.getAttribute('state')
        self.id = self.getAttribute('id')

        self.resource_params = self._extract_resource_params(
            self.module.params.copy())
        try:
            self.existing_resource = self._send_request_to_API(
                "/" + self.id, ignore_error=False)
            self._fill_missing_resource_params(
                self.existing_resource, self.resource_params)
        except Exception as err:
            self.existing_resource = None

    def getAttribute(self, attribute):
        """
            attribute: String

            Returns the attribute from module params if specified.
            - If it's a sub-resource, the param name must have its class name
            as a prefix.
            - The prefix is optional for base resource.
        """
        if self.get_resource_name() in constants.BASE_RESOURCES:
            return self.module.params.get(
                attribute, self.module.params.get(
                    self.get_resource_name() + "_" + attribute,
                    self.INCORRECT_ARGUMENT_NAME_VALUE))
        else:
            return self.module.params.get(
                self.get_resource_name() + "_" + attribute,
                self.INCORRECT_ARGUMENT_NAME_VALUE)

    def _extract_resource_params(self, args=None,
                                 unwanted_resource_params=set()):
        # extract the params belonging to this resource only.
        unwanted_resource_params.add("state")
        params = {}
        for key in self.resource_arg_spec.keys():
            if key in self.module.params and \
                key not in unwanted_resource_params and \
                    self.module.params[key] is not None:
                params[key] = self.module.params[key]
        return params

    def _send_request_to_API(self, suffix="", ignore_error=True,
                             method='GET', data=None):
        try:
            (_, resp) = self.policy_communicator.request(
                self.resource_class.get_resource_base_url()
                + suffix, validate_certs=self.validate_certs,
                ignore_errors=ignore_error, method=method, data=data)
        except Exception as e:
            raise e
        return resp

    @staticmethod
    @abstractmethod
    def get_resource_base_url():
        # Must be overridden by the subclass
        raise NotImplementedError

    def get_resource_name(self):
        return self.__class__.__name__

    def _achieve_present_state(self, successful_resource_exec_logs):
        logger.log("with data=" + str(self.resource_params))
        self.update_resource_params()
        is_resource_updated = self.check_for_update(
            self.existing_resource, self.resource_params)

        if not is_resource_updated:
            # Either the resource does not exist or it exists but was not
            # updated in the YAML.
            if self.module.check_mode:
                successful_resource_exec_logs.append({
                    self.id: {
                        "changed": True,
                        "debug_out": str(json.dumps(self.resource_params)),
                        "id": '12345',
                        "resource_type": self.get_resource_name()
                    }
                })
                return
            try:
                if self.existing_resource:
                    # Resource already exists
                    logger.log("Resource was not updated")
                    successful_resource_exec_logs.append({
                        self.id: {
                            "changed": False,
                            "id": self.id,
                            "message": "%s with id %s already exists." %
                            (self.get_resource_name(), self.id),
                            "resource_type": self.get_resource_name()
                        }
                    })
                    return
                # Create a new resource
                logger.log("Resource does not exist")
                resp = self._send_request_to_API(suffix="/" + self.id,
                                                 method='PATCH',
                                                 data=self.resource_params)
                successful_resource_exec_logs.append({
                    self.id: {
                        "changed": True,
                        "id": resp["id"],
                        "body": str(resp),
                        "message": "%s with id %s created." %
                        (self.get_resource_name(), self.id),
                        "resource_type": self.get_resource_name()
                    }
                })
            except Exception as err:
                srel = successful_resource_exec_logs
                self.module.fail_json(msg="Failed to add %s with id %s."
                                          "Request body [%s]. Error[%s]."
                                          % (self.get_resource_name(),
                                             self.id, self.resource_params,
                                             to_native(err)
                                             ),
                                      successfully_updated_resources=srel)
        else:
            # The resource exists and was updated in the YAML.
            logger.log("Resource exists on server but was updated by user")
            if self.module.check_mode:
                successfully_updated_resources.append({
                    "changed": True,
                    "debug_out": str(json.dumps(self.resource_params)),
                    "id": self.id,
                    "resource_type": self.get_resource_name()
                })
                return
            self.resource_params['_revision'] = \
                self.existing_resource['_revision']
            try:
                resp = self._send_request_to_API(suffix="/"+self.id,
                                                 method="PATCH",
                                                 data=self.resource_params)
                successful_resource_exec_logs.append({
                    "changed": True,
                    "id": self.id,
                    "body": str(resp),
                    "message": "%s with id %s updated." %
                    (self.get_resource_name(), self.id),
                    "resource_type": self.get_resource_name()
                })
            except Exception as err:
                srel = successful_resource_exec_logs
                self.module.fail_json(msg="Failed to update %s with id %s."
                                          "Request body [%s]. Error[%s]." %
                                          (self.get_resource_name(), self.id,
                                           self.resource_params, to_native(err)
                                           ),
                                      successfully_updated_resources=srel)

    def _achieve_absent_state(self, successful_resource_exec_logs):
        if self.existing_resource is None:
            successful_resource_exec_logs.append({
                self.id: {
                    "changed": False,
                    "msg": 'No %s exist with id %s' %
                    (self.get_resource_name(), self.id),
                    "resource_type": self.get_resource_name()
                }
            })
            return
        if self.module.check_mode:
            successful_resource_exec_logs.append({
                "changed": True,
                "debug_out": str(json.dumps(self.resource_params)),
                "id": self.id,
                "resource_type": self.get_resource_name()
            })
            return
        try:
            _ = self._send_request_to_API("/" + self.id, method='DELETE')
            self._wait_till_delete()
            successful_resource_exec_logs.append({
                "changed": True,
                "id": self.id,
                "message": "%s with id %s deleted." %
                (self.get_resource_name(), self.id)
            })
        except Exception as err:
            srel = successful_resource_exec_logs
            self.module.fail_json(msg="Failed to delete %s with id %s. "
                                      "Error[%s]." % (self.get_resource_name(),
                                                      self.id, to_native(err)),
                                  successfully_updated_resources=srel)

    def achieve_state(self, successful_resource_exec_logs=[]):
        """
            Achieves `present` or `absent` state as specified in the YAML.
        """
        logger.log("Achieving " + self._state + " state")
        if self.id == self.INCORRECT_ARGUMENT_NAME_VALUE:
            # The resource was not specified in the YAML.
            return
        self.achieve_subresource_state(successful_resource_exec_logs)

        if self._state == 'present':
            self._achieve_present_state(successful_resource_exec_logs)
        else:
            self._achieve_absent_state(successful_resource_exec_logs)

        if self.get_resource_name() in constants.BASE_RESOURCES:
            self.module.exit_json(
                successfully_updated_resources=successful_resource_exec_logs)

    def achieve_subresource_state(self, successful_resource_exec_logs):
        """
            Achieve the state of each sub-resource.
        """
        for attr in self.__class__.__dict__.values():
            if inspect.isclass(attr) and issubclass(attr, NSXTAnsibleResource):
                sub_resource = attr()
                sub_resource.achieve_state(successful_resource_exec_logs)

    def wait_till_create(self):
        pass

    def _wait_till_delete(self):
        """
            Periodically checks if the resource still exists on the API server
            every 10 seconds. Returns after it has been deleted.
        """
        while True:
            try:
                self._send_request_to_API("/" + self.id)
                time.sleep(10)
            except DuplicateRequestError:
                self.module.fail_json(msg='Duplicate request')
            except Exception as err:
                time.sleep(5)
                return

    def update_resource_params(self):
        # Should be overridden in the subclass if needed
        pass

    def _fill_missing_resource_params(self, existing_params, resource_params):
        """
            resource_params: dict
            existing_params: dict

            Fills resource_params with the key:value from existing_params if
            missing in the former.
        """
        if not existing_params:
            return
        for k, v in existing_params.items():
            if k not in resource_params:
                resource_params[k] = v
            elif type(v).__name__ == 'dict':
                self._fill_missing_resource_params(v, resource_params[k])

    def check_for_update(self, existing_params, resource_params):
        """
            resource_params: dict
            existing_params: dict

            Compares the existing_params with resource_params and returns
            True if they are different.
        """
        if not existing_params:
            return False
        for k, v in resource_params.items():
            if k not in existing_params:
                return True
            elif type(v).__name__ == 'dict':
                if self.check_for_update(existing_params[k], v):
                    return True
            elif v != existing_params[k]:
                return True
        return False
