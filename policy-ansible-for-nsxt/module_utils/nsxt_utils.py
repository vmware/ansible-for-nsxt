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

from __future__ import absolute_import, division, print_function

__author__ = 'Juan Artiles <juan.artiles@virtustream.com>'


def get_nsxt_object(client, mgr_hostname, api_version, endpoint, name=None, return_json=True, **rest_settings):

    api_endpoint = '{}{}{}'.format(mgr_hostname, api_version, endpoint)

    try:
        response = client.get(api_endpoint, **rest_settings)
        if return_json:
            response_json = response.json()
        else:
            response_json = response
        if 200 <= response.status_code <= 299:
            if name:
                for item in response_json['results']:
                    if name in item['display_name'] == name:
                        return True, {"type": "success", "response": response, "data": item}

                return True, {"type": "success", "response": response, "data": []}
            else:
                return True, {"type": "success", "response": response, "data": response_json}
        else:
            return False, {"type": "error", "response": response, "data": response_json}
    except Exception as error:
        return False, {"type": "exception", "response": str(error)}


def create_nsxt_object(client, mgr_hostname, api_version, endpoint, resource_type, payload,
                       return_json=True, add_name=True, update=False, **rest_settings):
    api_version = api_version
    endpoint = endpoint

    if add_name:
        display_name = payload["display_name"]
        api_endpoint = '{}{}{}/{}'.format(mgr_hostname, api_version, endpoint, display_name)
    else:
        api_endpoint = '{}{}{}'.format(mgr_hostname, api_version, endpoint)
    if payload and resource_type:
        payload["resource_type"] = resource_type

    try:
        if not update:
            response = client.post(api_endpoint, payload, **rest_settings)
        else:
            response = client.put(api_endpoint, payload, **rest_settings)
        if 200 <= response.status_code <= 299:
            if return_json:
                response_json = response.json()
            else:
                response_json = response
            return True, {"type": "success", "response": response, "data": response_json}
        else:
            response_json = response.json()
            return False, {"type": "error", "response": response, "data": response_json}
    except Exception as error:
        return False, {"type": "exception", "response": str(error)}


def delete_nsxt_object(client, mgr_hostname, api_version, endpoint, name=None, **rest_settings):
    api_endpoint = '{}{}{}'.format(mgr_hostname, api_version, endpoint)
    if name:
        api_endpoint += "/{}".format(name)

    response = client.delete(api_endpoint, **rest_settings)
    if 200 <= response.status_code <= 299:
        return True, {"type": "success", "response": response, "data": response}
    else:
        return False, {"type": "error", "response": response, "data": response}

def get_params(args, remove_args=[]):
    default_remove_args = ['state', 'username', 'password', 'hostname', 'validate_certs', 'port']
    args_to_remove = remove_args + default_remove_args
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if not value:
            args.pop(key, None)
    return args