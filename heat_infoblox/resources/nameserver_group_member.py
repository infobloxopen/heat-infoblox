# Copyright (c) 2015 Infoblox Inc.  # All Rights Reserved.
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

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from heat_infoblox import constants
from heat_infoblox import resource_utils

from oslo_concurrency import lockutils


LOG = logging.getLogger(__name__)


class NameServerGroupMember(resource.Resource):
    '''A resource which represents a name server group.

    Use this resource to create, modify, and delete name server groups in the
    grid.
    '''

    PROPERTIES = (
        GROUP_NAME, MEMBER_ROLE, MEMBER_SERVER, EXTERNAL_SERVER,
        MEMBER_NAME, GRID_REPLICATE, LEAD,
        ENABLE_PREFERRED_PRIMARIES, PREFERRED_PRIMARIES
    ) = (
        'group_name', 'member_role', 'member_server', 'external_server',
        'name', 'grid_replicate', 'lead',
        'enable_preferred_primaries', 'preferred_primaries'
    )

    # for now, only support grid members
    # not 'external_primary', 'external_secondary'
    MEMBER_ROLES = ['grid_primary', 'grid_secondary']

    ATTRIBUTES = (
        NS_GROUP,
    ) = (
        'name_server_group',
    )

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.DDI),
        GROUP_NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name server group name.')),
        MEMBER_ROLE: properties.Schema(
            properties.Schema.STRING,
            _('The role the member plays in the group.'),
            constraints=[
                constraints.AllowedValues(MEMBER_ROLES)
            ]),
        MEMBER_SERVER: properties.Schema(
            properties.Schema.MAP,
            _('A grid member settings in this group.'),
            schema={
                MEMBER_NAME: properties.Schema(
                    properties.Schema.STRING,
                    _('The member name.'),
                    required=True
                ),
                GRID_REPLICATE: properties.Schema(
                    properties.Schema.BOOLEAN,
                    _('Determines if grid replication or zone transfer will '
                      'be used to this server.'),
                    default=True
                ),
                LEAD: properties.Schema(
                    properties.Schema.BOOLEAN,
                    _('Determines if this member should serve as the lead '
                      'secondary for the group.'),
                    default=False
                ),
            }),
    }

    attributes_schema = {
        NS_GROUP: attributes.Schema(
            _('The name server group details.'),
            attributes.Schema.MAP)
    }

    def infoblox(self):
        if not getattr(self, 'infoblox_object', None):
            conn = self.properties[constants.CONNECTION]
            self.infoblox_object = resource_utils.connect_to_infoblox(conn)
        return self.infoblox_object

    def _remove_member(self, member_list, member):
        i = 0
        for m in member_list:
            if m['name'] == member['name']:
                del member_list[i]
            i += 1

    def _add_member(self, member_list, member):
        # remove it if it is already there, so we get any updates
        self._remove_member(member_list, member)
        member_list.append(member)

    def _get_ns_group(self, group_name):
        LOG.debug("LOADING NSGROUP: %s" % group_name)
        groups = self.infoblox().get_ns_group(
            group_name,
            return_fields=['name', 'grid_primary', 'grid_secondaries']
        )
        if len(groups) == 0:
            raise exception.EntityNotFound(entity='Name Server Group',
                                           name=group_name)
        return groups[0]

    def handle_create(self):
        with lockutils.lock(
                self.properties[self.MEMBER_SERVER][self.MEMBER_NAME],
                external=True,
                lock_file_prefix='infoblox-ns_group-update'):
            group_name = self.properties[self.GROUP_NAME]
            group = self._get_ns_group(group_name)
            LOG.debug("NSGROUP: %s" % group)

            member_role = self.properties[self.MEMBER_ROLE]
            member = self.properties[self.MEMBER_SERVER]
            if member_role == 'grid_primary':
                self._remove_member(group['grid_secondaries'], member)
                self._add_member(group['grid_primary'], member)
            elif member_role == 'grid_secondary':
                self._remove_member(group['grid_primary'], member)
                self._add_member(group['grid_secondaries'], member)

            self.infoblox().update_ns_group(group_name, group)
        self.resource_id_set(
            "%s/%s/%s" % (group_name, member_role, member['name'])
        )

    def handle_delete(self):
        LOG.debug("NSGROUP %s DELETE" % self.resource_id)
        if self.resource_id is None:
            return None

        group_name, member_role, member_name = self.resource_id.split('/')
        member = {'name': member_name}
        field_name = 'grid_primary'
        if member_role == 'grid_secondary':
            field_name = 'grid_secondaries'

        with lockutils.lock(
                self.properties[self.MEMBER_SERVER][self.MEMBER_NAME],
                external=True,
                lock_file_prefix='infoblox-ns_group-update'):
            group = self._get_ns_group(group_name)

            LOG.debug("NSGROUP for DELETE: %s" % group)
            self._remove_member(group[field_name], member)
            LOG.debug("NSGROUP update DELETE: %s" % group)
            self.infoblox().update_ns_group(group_name, group)

    def _resolve_attribute(self, name):
        LOG.debug("RESOLVE ATTRIBUTE: %s" % name)
        group_name = self.properties[self.GROUP_NAME]
        group = self._get_ns_group(group_name)
        if name == self.NS_GROUP:
            return group
        return None


def resource_mapping():
    return {
        'Infoblox::Grid::NameServerGroupMember': NameServerGroupMember,
    }
