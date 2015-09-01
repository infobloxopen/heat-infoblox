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

from heat.common.i18n import _
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from heat_infoblox import resource_utils


class GridMember(resource.Resource):
    '''A resource which represents an Infoblox Grid Member.

    This is used to provision new grid members on an existing grid. See the
    Grid Master resource to create a new grid.
    '''

    support_status = support.SupportStatus(support.UNSUPPORTED)

    properties_schema = {
        "wapi_url": properties.Schema(
            properties.Schema.STRING,
            _('URL to the Infoblox WAPI.'),
            required=True
        ),
        "wapi_certificate": properties.Schema(
            properties.Schema.STRING,
            _('The certificate for validation of the WAPI URL.'),
            required=False
        ),
        "wapi_insecure_ignore_invalid_certificate": properties.Schema(
            properties.Schema.BOOLEAN,
            _('Do not require the certificate for validating the WAPI URL. '
              'This is NOT SECURE and should not be used in a production '
              'environment.'),
            default=False,
            required=False
        ),
        "wapi_username": properties.Schema(
            properties.Schema.STRING,
            _('Username to login to the WAPI.'),
            required=True
        ),
        "wapi_password": properties.Schema(
            properties.Schema.STRING,
            _('Password to login to the WAPI.'),
            required=True
        ),
        "name": properties.Schema(
            properties.Schema.STRING,
            _('Server name.'),
        ),
        "image": properties.Schema(
            properties.Schema.STRING,
            _('The ID or name of the image to boot with.'),
            required=True,
            constraints=[
                constraints.CustomConstraint('glance.image')
            ],
        ),
        "flavor": properties.Schema(
            properties.Schema.STRING,
            _('The ID or name of the flavor to boot onto.'),
            required=True,
            constraints=[
                constraints.CustomConstraint('nova.flavor')
            ]
        ),
        "availability_zone": properties.Schema(
            properties.Schema.STRING,
            _('Name of the availability zone for server placement.')
        ),
        "MGMT": resource_utils.port_schema("MGMT", True),
        "LAN1": resource_utils.port_schema("LAN1", True),
        "admin_pass": properties.Schema(
            properties.Schema.STRING,
            _('The administrator password for the server.'),
        ),
    }

    def handle_create(self):
        self.resource_id_set(self.physical_resource_name())


def resource_mapping():
    return {
        'Infoblox::Grid::Member': GridMember,
    }
