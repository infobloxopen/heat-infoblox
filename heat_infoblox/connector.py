# Copyright 2015 Infoblox Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json as jsonutils
import logging

import requests
from six.moves.urllib import parse

from heat_infoblox import ibexceptions as exc


LOG = logging.getLogger(__name__)


class Infoblox(object):
    """Infoblox class

    Defines methods for getting, creating, updating and
    removing objects from an Infoblox server instance.
    """

    def __init__(self, options):
        """Initialize a new Infoblox object instance

        Args:
            options (dict): Target options dictionary
        """

        self.sslverify = True
        if 'sslverify' in options:
            self.sslverify = options['sslverify']

        reqd_opts = ['url', 'username', 'password']
        default_opts = {'http_pool_connections': 5,
                        'http_pool_maxsize': 20,
                        'max_retries': 5}
        for opt in reqd_opts + default_opts.keys():
            setattr(self, opt, options.get(opt) or default_opts.get(opt))

        for opt in reqd_opts:
            LOG.debug("self.%s = %s" % (opt, getattr(self, opt)))
            if not getattr(self, opt):
                raise exc.InfobloxIsMisconfigured(option=opt)

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=self.max_retries,
            pool_connections=self.http_pool_connections,
            pool_maxsize=self.http_pool_maxsize)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.auth = (self.username, self.password)
        self.session.verify = self.sslverify

    def _construct_url(self, relative_path, query_params=None, extattrs=None):
        if query_params is None:
            query_params = {}
        if extattrs is None:
            extattrs = {}

        if not relative_path or relative_path[0] == '/':
            raise ValueError('Path in request must be relative.')
        query = ''
        if query_params or extattrs:
            query = '?'

        if extattrs:
            attrs_queries = []
            for key, value in extattrs.items():
                attrs_queries.append('*' + key + '=' + value['value'])
            query += '&'.join(attrs_queries)
        if query_params:
            if len(query) > 1:
                query += '&'
            query += parse.urlencode(query_params)

        baseurl = parse.urljoin(self.url, parse.quote(relative_path))
        LOG.debug("_construct_url: %s" % (baseurl + query))
        return baseurl + query

    def _validate_objtype_or_die(self, objtype):
        if not objtype:
            raise ValueError('WAPI object type can\'t be empty.')
        if '/' in objtype:
            raise ValueError('WAPI object type can\'t contains slash.')

    def get_object(self, objtype, payload=None, return_fields=None,
                   extattrs=None):
        """Retrieve a list of Infoblox objects of type 'objtype'

        Args:
            objtype  (str): Infoblox object type, e.g. 'view', 'tsig', etc.
            payload (dict): Payload with data to send
        Returns:
            A list of the Infoblox objects requested
        Raises:
            InfobloxObjectNotFound
        """
        if return_fields is None:
            return_fields = []
        if extattrs is None:
            extattrs = {}

        self._validate_objtype_or_die(objtype)

        query_params = dict()
        if return_fields:
            query_params['_return_fields'] = ','.join(return_fields)

        headers = {'Content-type': 'application/json'}

        data = jsonutils.dumps(payload)
        url = self._construct_url(objtype, query_params, extattrs)
        LOG.debug("DATA = %s" % data)

        r = self.session.get(url,
                             data=data,
                             verify=self.sslverify,
                             headers=headers)

        LOG.debug("RESPONSE[%s] = %s" % (r.status_code, r.content))

        if r.status_code != requests.codes.ok:
            raise exc.InfobloxSearchError(
                response=jsonutils.loads(r.content),
                objtype=objtype,
                content=r.content,
                code=r.status_code)

        return jsonutils.loads(r.content)

    def create_object(self, objtype, payload, return_fields=None):
        """Create an Infoblox object of type 'objtype'

        Args:
            objtype  (str): Infoblox object type, e.g. 'network', 'range', etc.
            payload (dict): Payload with data to send
        Returns:
            The object reference of the newly create object
        Raises:
            InfobloxException
        """
        if not return_fields:
            return_fields = []

        self._validate_objtype_or_die(objtype)

        query_params = dict()

        if return_fields:
            query_params['_return_fields'] = ','.join(return_fields)

        url = self._construct_url(objtype, query_params)

        headers = {'Content-type': 'application/json'}

        LOG.debug("DATA = %s" % jsonutils.dumps(payload))

        r = self.session.post(url,
                              data=jsonutils.dumps(payload),
                              verify=self.sslverify,
                              headers=headers)

        LOG.debug("RESPONSE = %s" % r)

        if r.status_code != requests.codes.CREATED:
            raise exc.InfobloxCannotCreateObject(
                response=jsonutils.loads(r.content),
                objtype=objtype,
                content=r.content,
                args=payload,
                code=r.status_code)

        return jsonutils.loads(r.content)

    def call_func(self, func_name, ref, payload, return_fields=None):
        LOG.debug("CALL_FUNC %s, %s, %s" % (func_name, ref, payload))
        if not return_fields:
            return_fields = []

        query_params = dict()
        query_params['_function'] = func_name

        if return_fields:
            query_params['_return_fields'] = ','.join(return_fields)

        LOG.debug("CALLING FUNC _construct_url")

        url = self._construct_url(ref, query_params)

        LOG.debug("FUNC_URL = %s" % url)
        LOG.debug("DATA = %s" % jsonutils.dumps(payload))

        headers = {'Content-type': 'application/json'}
        r = self.session.post(url,
                              data=jsonutils.dumps(payload),
                              verify=self.sslverify,
                              headers=headers)

        if r.status_code not in (requests.codes.CREATED,
                                 requests.codes.ok):
            raise exc.InfobloxFuncException(
                response=jsonutils.loads(r.content),
                ref=ref,
                func_name=func_name,
                content=r.content,
                code=r.status_code)

        return jsonutils.loads(r.content)

    def update_object(self, ref, payload):
        """Update an Infoblox object

        Args:
            ref      (str): Infoblox object reference
            payload (dict): Payload with data to send
        Returns:
            The object reference of the updated object
        Raises:
            InfobloxException
        """

        headers = {'Content-type': 'application/json'}
        r = self.session.put(self._construct_url(ref),
                             data=jsonutils.dumps(payload),
                             verify=self.sslverify,
                             headers=headers)

        if r.status_code != requests.codes.ok:
            raise exc.InfobloxCannotUpdateObject(
                response=jsonutils.loads(r.content),
                ref=ref,
                content=r.content,
                code=r.status_code)

        return jsonutils.loads(r.content)

    def delete_object(self, ref):
        """Remove an Infoblox object

        Args:
            ref      (str): Object reference
        Returns:
            The object reference of the removed object
        Raises:
            InfobloxException
        """
        r = self.session.delete(self._construct_url(ref),
                                verify=self.sslverify)

        if r.status_code != requests.codes.ok:
            raise exc.InfobloxCannotDeleteObject(
                response=jsonutils.loads(r.content),
                ref=ref,
                content=r.content,
                code=r.status_code)

        return jsonutils.loads(r.content)
