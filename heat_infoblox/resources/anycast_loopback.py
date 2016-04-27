# Copyright (c) 2016 Infoblox Inc.
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
from heat_infoblox import resource_utils


LOG = logging.getLogger(__name__)


class AnycastLoopback(resource.Resource):
    """A resource which represents an anycast loopback interface.

    This is used to assign anycast address to Grid Member loopback interface.
    """

    PROPERTIES = (
        IP, GRID_MEMBERS, ENABLE_BGP, ENABLE_OSPF,
        ) = (
        'ip', 'grid_members', 'enable_bgp', 'enable_ospf',
        )

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.DDI),
        IP: properties.Schema(
            properties.Schema.STRING,
            _('The Anycast Loopback IP address.'),
            required=True),
        GRID_MEMBERS: properties.Schema(
            properties.Schema.LIST,
            _('List of Grid Member Names for Anycast IP address'),
            schema=properties.Schema(
                properties.Schema.STRING
            ),
            required=True),
        ENABLE_BGP: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if the BGP advertisement setting is enabled '
              'for this interface or not.'),
            required=False),
        ENABLE_OSPF: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if the OSPF advertisement setting is enabled '
              'for this interface or not.'),
            required=False),
    }

    @property
    def infoblox(self):
        if not getattr(self, 'infoblox_object', None):
            conn = self.properties[constants.CONNECTION]
            self.infoblox_object = resource_utils.connect_to_infoblox(conn)
        return self.infoblox_object

    def handle_create(self):
        ip = self.properties[self.IP]
        for member_name in self.properties[self.GRID_MEMBERS]:
            self.infoblox.create_anycast_loopback(
                member_name,
                ip,
                self.properties[self.ENABLE_BGP],
                self.properties[self.ENABLE_OSPF])

    def handle_delete(self):
        ip = self.properties[self.IP]
        for member_name in self.properties[self.GRID_MEMBERS]:
            self.infoblox.delete_anycast_loopback(ip, member_name)


def resource_mapping():
    return {
        'Infoblox::Grid::AnycastLoopback': AnycastLoopback,
    }
