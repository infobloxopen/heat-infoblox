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
from oslo_concurrency import lockutils

from heat_infoblox import constants
from heat_infoblox import resource_utils


LOG = logging.getLogger(__name__)


class AnycastLoopback(resource.Resource):
    """A resource which represents an anycast loopback interface.

    This is used to assign anycast address to Grid Member loopback interface.
    """

    PROPERTIES = (
        IP, GRID_MEMBERS, ENABLE_BGP, ENABLE_OSPF, ENABLE_DNS,
        ) = (
        'ip', 'grid_members', 'enable_bgp', 'enable_ospf', 'enable_dns',
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
            update_allowed=True,
            required=True),
        GRID_MEMBERS: properties.Schema(
            properties.Schema.LIST,
            _('List of Grid Member Names for Anycast IP address'),
            schema=properties.Schema(
                properties.Schema.STRING
            ),
            update_allowed=True,
            required=True),
        ENABLE_BGP: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if the BGP advertisement setting is enabled '
              'for this interface or not.'),
            update_allowed=True,
            required=False),
        ENABLE_OSPF: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if the OSPF advertisement setting is enabled '
              'for this interface or not.'),
            update_allowed=True,
            required=False),
        ENABLE_DNS: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if the Anycast IP will be used to serve DNS.'),
            update_allowed=True,
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
            with lockutils.lock(member_name,
                                external=True,
                                lock_file_prefix='infoblox-anycast'):
                self.infoblox.create_anycast_loopback(
                    member_name,
                    ip,
                    self.properties[self.ENABLE_BGP],
                    self.properties[self.ENABLE_OSPF])
            if self.properties[self.ENABLE_DNS]:
                with lockutils.lock(member_name,
                                    external=True,
                                    lock_file_prefix='infoblox-dns-ips'):
                    self.infoblox.add_member_dns_additional_ip(member_name,
                                                               ip)

    def _delete_ip_from_dns(self, member_name, ip):
        if self.properties[self.ENABLE_DNS]:
            with lockutils.lock(member_name,
                                external=True,
                                lock_file_prefix='infoblox-dns-ips'):
                self.infoblox.remove_member_dns_additional_ip(member_name,
                                                              ip)

    def _delete_anycast_ip_from_member(self, member_name):
        ip = self.properties[self.IP]
        self._delete_ip_from_dns(member_name, ip)
        with lockutils.lock(member_name,
                            external=True,
                            lock_file_prefix='infoblox-anycast'):
            self.infoblox.delete_anycast_loopback(ip, member_name)

    def handle_delete(self):
        for member_name in self.properties[self.GRID_MEMBERS]:
            self._delete_anycast_ip_from_member(member_name)

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        if not prop_diff:
            return
        new_members = set(tmpl_diff['Properties'][self.GRID_MEMBERS])
        old_members = set(self.properties.get(self.GRID_MEMBERS))
        to_remove = old_members - new_members
        if self.GRID_MEMBERS in prop_diff:
            for member in to_remove:
                self._delete_anycast_ip_from_member(member)

            if len(prop_diff) > 1:
                # Anycast settings were changed, need to update all members
                to_update = new_members
            else:
                # Anycast settings unchanged, so add it to new members
                to_update = new_members - old_members
        else:
            # Anycast settings were changed, so need to update all members
            to_update = new_members

        # Enable_dns field complicates update because it refers to
        # member:dns additional_ip_list which depends on the
        # additional_ip_list field from member.
        # To update ip for anycast loopback update has to be executed in
        # next order:
        # - delete old ip address from member:dns
        # - update anycast ip
        # - add updated ip address to member:dns

        # if ip changed or dns disabled - delete dns ip from existing members
        if (self.IP in prop_diff or (self.ENABLE_DNS in prop_diff and
                                     not prop_diff[self.ENABLE_DNS])):
            for member in old_members - to_remove:
                self._delete_ip_from_dns(member, self.properties[self.IP])
        # now create/update anycast loopback and dns ip
        for member in to_update:

            with lockutils.lock(member, external=True,
                                lock_file_prefix='infoblox-anycast'):
                self.infoblox.create_anycast_loopback(
                    member,
                    tmpl_diff['Properties'][self.IP],
                    tmpl_diff['Properties'][self.ENABLE_BGP],
                    tmpl_diff['Properties'][self.ENABLE_OSPF],
                    old_ip=self.properties[self.IP])

            if tmpl_diff['Properties'][self.ENABLE_DNS]:
                with lockutils.lock(member,
                                    external=True,
                                    lock_file_prefix='infoblox-dns-ips'):
                    self.infoblox.add_member_dns_additional_ip(
                        member, tmpl_diff['Properties'][self.IP])


def resource_mapping():
    return {
        'Infoblox::Grid::AnycastLoopback': AnycastLoopback,
    }
