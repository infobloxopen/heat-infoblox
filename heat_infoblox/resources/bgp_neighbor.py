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
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support
from oslo_concurrency import lockutils

from heat_infoblox import constants
from heat_infoblox import resource_utils

LOG = logging.getLogger(__name__)


class BgpNeighbor(resource.Resource):
    """A resource which represents a BGP Neighbor configuration.

    This resource is used configure single BGP Neighbor on grid member. BGP
    AS resource has to be created prior to creating neighbors.
    """

    PROPERTIES = (
        GRID_MEMBER, AUTHENTICATION_MODE, BGP_NEIGHBOR_PASS,
        COMMENT, INTERFACE, NEIGHBOR_IP, REMOTE_AS
        ) = (
        'grid_member', 'authentication_mode', 'bgp_neighbor_pass',
        'comment', 'interface', 'neighbor_ip', 'remote_as'
        )

    AUTHENTICATION_MODES = ('MD5', 'NONE')
    INTERFACES = ('LAN_HA',)

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.DDI),
        GRID_MEMBER: properties.Schema(
            properties.Schema.STRING,
            _('Grid Member Name for BGP Neigbor configuration'),
            required=True),
        AUTHENTICATION_MODE: properties.Schema(
            properties.Schema.STRING,
            _('Determines the BGP authentication mode.'),
            constraints=[
                constraints.AllowedValues(AUTHENTICATION_MODES)
            ],
            update_allowed=True,
            required=True),
        BGP_NEIGHBOR_PASS: properties.Schema(
            properties.Schema.STRING,
            _('The password for the BGP neighbor. This is required only if '
              'authentication_mode is set to "MD5". '),
            update_allowed=True),
        COMMENT: properties.Schema(
            properties.Schema.STRING,
            _('User comments for this BGP neighbor.'),
            update_allowed=True),
        INTERFACE: properties.Schema(
            properties.Schema.STRING,
            _('The interface that sends BGP advertisement information.'),
            update_allowed=True,
            constraints=[
                constraints.AllowedValues(INTERFACES)
            ]),
        NEIGHBOR_IP: properties.Schema(
            properties.Schema.STRING,
            _('The IP address of the BGP neighbor.'),
            update_allowed=True,
            required=True),
        REMOTE_AS: properties.Schema(
            properties.Schema.INTEGER,
            _('The remote AS number of the BGP neighbor.'),
            update_allowed=True,
            required=True),
    }

    @property
    def infoblox(self):
        if not getattr(self, 'infoblox_object', None):
            conn = self.properties[constants.CONNECTION]
            self.infoblox_object = resource_utils.connect_to_infoblox(conn)
        return self.infoblox_object

    def handle_create(self):
        bgp_options_dict = {
            name: self.properties.get(name) for name in self.PROPERTIES}
        member_name = self.properties[self.GRID_MEMBER]
        # Create/update/delete actions are all doing read-change-update on bgp
        # configuration for particular member.Concurrent modifications leads to
        # missed data at scale and on bulk operations like deleting multiple
        # bgp neighbors.
        # Introduced semaphore to allow only one process to modify
        # particular grid member bgp configuration.
        with lockutils.lock(member_name,
                            external=True,
                            lock_file_prefix='infoblox-bgp-update'):
            self.infoblox.create_bgp_neighbor(member_name, bgp_options_dict)

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        if prop_diff:
            member_name = tmpl_diff['Properties']['grid_member']
            with lockutils.lock(member_name,
                                external=True,
                                lock_file_prefix='infoblox-bgp-update'):
                self.infoblox.create_bgp_neighbor(
                    member_name,
                    tmpl_diff['Properties'],
                    old_neighbor_ip=self.properties[self.NEIGHBOR_IP])

    def handle_delete(self):
        with lockutils.lock(self.properties[self.GRID_MEMBER],
                            external=True,
                            lock_file_prefix='infoblox-bgp-update'):
            self.infoblox.delete_bgp_neighbor(
                self.properties[self.GRID_MEMBER],
                self.properties[self.NEIGHBOR_IP])


def resource_mapping():
    return {
        'Infoblox::Grid::BgpNeighbor': BgpNeighbor,
    }
