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
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from heat_infoblox import constants
from heat_infoblox import netmri_resource_mixin as mri
from heat_infoblox import resource_utils

LOG = logging.getLogger(__name__)


class NetMRIManagedResource(resource.Resource, mri.NetMRIResourceMixin):

    '''A resource managed via NetMRI jobs.

       The user may specify separate scripts for create and delete.
    '''

    ATTRIBUTES = (
        JOB,
        JOB_DETAILS
    ) = (
        'job',
        'job_details'
    )

    CREATE_JOB = 'create_job'
    DELETE_JOB = 'delete_job'
    DELETE_JOB_ID = 'delete_job_id'

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.NETMRI),
        CREATE_JOB: properties.Schema(
            properties.Schema.MAP,
            _("The job to execute on resource creation."),
            required=True,
            schema=mri.NetMRIResourceMixin.job_schema
            ),
        DELETE_JOB: properties.Schema(
            properties.Schema.MAP,
            _("The job to execute on resource deletion."),
            required=True,
            schema=mri.NetMRIResourceMixin.job_schema
            )
    }

    attributes_schema = mri.NetMRIResourceMixin.job_attributes_schema

    def handle_create(self):
        r = self._execute_job(self.properties[self.CREATE_JOB])
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
        r = self._execute_job(self.properties[self.DELETE_JOB])
        self.metadata_set({self.DELETE_JOB_ID: r['JobID']})

    def check_delete_complete(self, handler_data):
        if not self.properties[self.DELETE_JOB][self.WAIT]:
            return True

        md = self.metadata_get()
        job_id = int(md[self.DELETE_JOB_ID])
        return self._check_job_complete(job_id)

    def _resolve_attribute(self, name):
        return self._resolve_job_attribute(name)


def resource_mapping():
    return {
        'Infoblox::NetMRI::ManagedResource': NetMRIManagedResource,
    }
