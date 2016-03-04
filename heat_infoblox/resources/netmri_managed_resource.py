# Copyright (c) 2015 Infoblox Inc.
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

import logging

from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from heat_infoblox import constants
from heat_infoblox import resource_utils

import infoblox_netmri as netmri

LOG = logging.getLogger(__name__)


class NetMRIManagedResource(resource.Resource):
    '''A resource managed via NetMRI jobs. The user may specify separate
       scripts for create and delete.'''

    PROPERTIES = (
        CREATE_JOB, DELETE_JOB,
        SOURCE, SCRIPT, JOB_SPEC, TEMPLATE,
        WAIT, INPUTS, TARGETS,
        DEVICE_ID, DEVICE_IP_ADDR, DEVICE_NET_IP_ADDR,
        NETWORK_VIEW
    ) = (
        'create_job', 'delete_job',
        'source', 'script', 'job_specification', 'config_template',
        'wait', 'inputs', 'targets',
        'device_id', 'device_ip_address', 'device_netview_ip_addr',
        'network_view'
    )

    ATTRIBUTES = (
        JOB,
        JOB_DETAILS
    ) = (
        'job',
        'job_details'
    )

    support_status = support.SupportStatus(support.UNSUPPORTED)

    job_schema = {
        SOURCE: properties.Schema(
            properties.Schema.MAP,
            required=True,
            schema={
                SCRIPT: properties.Schema(
                    properties.Schema.STRING,
                    _('The name or ID of the script to run.')
                ),
                JOB_SPEC: properties.Schema(
                    properties.Schema.STRING,
                    _('The name or ID of the job specification to run.')
                ),
                TEMPLATE: properties.Schema(
                    properties.Schema.STRING,
                    _('The name or ID of the config template to run.')
                ),
            }),
        WAIT: properties.Schema(
            properties.Schema.BOOLEAN,
            _('If true, the action will wait until the job completes.'),
            default=True),
        INPUTS: properties.Schema(
            properties.Schema.MAP,
            _('The key/value pair inputs for the job.')),
        TARGETS: properties.Schema(
            properties.Schema.LIST,
            _('A list of targets (devices) against which to execute '
              'this job.'),
            required=True,
            schema=properties.Schema(
                properties.Schema.MAP,
                schema={
                    DEVICE_ID: properties.Schema(
                        properties.Schema.STRING,
                        _('DeviceID of the device.')
                    ),
                    DEVICE_IP_ADDR: properties.Schema(
                        properties.Schema.STRING,
                        _('The IP address of the device, if not specifying '
                          'a device ID.'),
                        constraints=[constraints.CustomConstraint('ip_addr')]
                    ),
                    NETWORK_VIEW: properties.Schema(
                        properties.Schema.STRING,
                        _('The network view name for this device IP. Required '
                          'if specifying an IP and there are multiple network '
                          'views in the NetMRI.')
                    ),
                })),
    }

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.NETMRI),
        CREATE_JOB: properties.Schema(
            properties.Schema.MAP,
            _("The job to execute on resource creation."),
            required=True,
            schema=job_schema
        ),
        DELETE_JOB: properties.Schema(
            properties.Schema.MAP,
            _("The job to execute on resource deletion."),
            required=True,
            schema=job_schema
        )
    }

    attributes_schema = {
        JOB: attributes.Schema(
            _('The create job object as returned by the NetMRI API.'),
            attributes.Schema.MAP
        ),
        JOB_DETAILS: attributes.Schema(
            _('A list of targets with details about each.'),
            attributes.Schema.LIST
        )
    }

    @property
    def netmri(self):
        if not getattr(self, 'netmri_object', None):
            self.netmri_object = netmri.InfobloxNetMRI(
                self.properties[constants.CONNECTION][constants.URL],
                self.properties[constants.CONNECTION][constants.USERNAME],
                self.properties[constants.CONNECTION][constants.PASSWORD]
            )
        return self.netmri_object

    def _device_ids(self, job_map):
        ids = set()
        ips = set()
        view_names = set()
        need_all_views = False
        need_lookup = []
        for t in job_map[self.TARGETS]:
            device_id = t.get(self.DEVICE_ID, None)
            if device_id:
                ids.add(device_id)
            else:
                ip = t.get(self.DEVICE_IP_ADDR, None)
                if ip is None:
                    continue
                ips.add(ip)
                view_name = t.get(self.NETWORK_VIEW, None)
                if view_name is None:
                    need_all_views = True
                elif not need_all_views:
                    view_names.add(view_name)
                need_lookup.append([ip, view_name])

        if len(ips) > 0:
            ips = list(ips)

            # pull back all the used views by name, so we can have the IDs
            api_params = {'select': ['VirtualNetworkID', 'VirtualNetworkName']}
            if not need_all_views:
                api_params['VirtualNetworkName'] = list(view_names)
            views = self.netmri.api_request('virtual_networks/search',
                                            api_params)['virtual_networks']

            # map name -> ID for the views
            view_map = {}
            for nv in views:
                view_map[nv['VirtualNetworkName']] = nv['VirtualNetworkID']

            # for all the targets that needed lookup, map name to ID
            for t in need_lookup:
                if t[1] is not None:
                    if t[1] in view_map:
                        t[1] = view_map[t[1]]
                    else:
                        raise ValueError("Network View '%s' does not exist."
                                         % t[1])

            # create a map of IP -> [ views IDs ] found in the NetMRI
            # so we know all views in which an IP is found
            devices = self.netmri.api_request('devices/index', {
                'DeviceIPDotted': ips,
                'VirtualNetworkID': list(view_map.values()),
                'select': 'DeviceID,DeviceIPDotted,VirtualNetworkID'
            })
            device_map = {}
            for dev in devices['devices']:
                ip = dev['DeviceIPDotted']
                if ip not in device_map:
                    device_map[ip] = {}
                device_map[ip][dev['VirtualNetworkID']] = dev['DeviceID']

            # now, go through each target that needed lookup and find the right
            # DeviceID that goes with that IP/view combination. If there was no
            # view specified, there could be multiple devices corresponding to
            # the IP - that would be an error
            for t in need_lookup:
                if t[1] is None and len(device_map[t[0]]) > 2:
                    raise ValueError("No network view specified for target IP "
                                     "%s, and that IP exists in %d different "
                                     "views." % (t[0],
                                                 len(device_map[t[0]]) / 2))
                elif t[1]:
                    ids.add(device_map[t[0]][t[1]])
                else:
                    ips.add(device_map[t[0]].values()[0])

        return list(ids)

    def _execute_job(self, which_job):
        params = {}
        job_map = self.properties[which_job]
        script = job_map[self.SOURCE][self.SCRIPT]
        if script.isdigit():
            params['id'] = script
        else:
            params['name'] = script

        params['device_ids'] = self._device_ids(job_map)

        raw_inputs = job_map[self.INPUTS] or {}
        inputs = {}
        for var in raw_inputs:
            if var.startswith('$'):
                inputs[var] = raw_inputs[var]
            else:
                inputs['$' + var] = raw_inputs[var]

        params.update(inputs)

        return self.netmri.api_request('scripts/run', params)

    def handle_create(self):
        r = self._execute_job(self.CREATE_JOB)
        self.resource_id_set(r['JobID'])

    def check_create_complete(self, handler_data):
        if not self.properties[self.CREATE_JOB][self.WAIT]:
            return True

        job_id = int(self.resource_id)
        return self._check_job_complete(job_id)

    def _check_job_complete(self, job_id):
        job = self.netmri.show('job', job_id)['job']
        LOG.debug("job = %s", job)
        if job['completed_at']:
            return True

        return False

    def handle_delete(self):
        self._execute_job(self.DELETE_JOB)

    def _get_job_details(self):
        details = self.netmri.api_request('job_details/index',
                                          {'id': self.resource_id})
        device_ids = map(lambda x: x['DeviceID'], details['job_details'])
        devices = self.netmri.api_request('devices/index',
                                          {'DeviceID': device_ids})
        dev_map = dict(map(lambda x: (x['DeviceID'], x), devices['devices']))
        for detail in details['job_details']:
            detail['device'] = dev_map.get(detail['DeviceID'], None)
        return details['job_details']

    def _resolve_attribute(self, name):
        LOG.debug("attr '%s' for resource %s", name, self.resource_id)

        if name == self.JOB:
            job = self.netmri.show('job', int(self.resource_id))['job']
            return job

        if name == self.JOB_DETAILS:
            return self._get_job_details()

        return


def resource_mapping():
    return {
        'Infoblox::NetMRI::ManagedResource': NetMRIManagedResource,
    }
