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

from heat_infoblox import constants
from heat_infoblox import resource_utils

LOG = logging.getLogger(__name__)


class Ospf(resource.Resource):
    """A resource which represents an OSPF settings.

    This is used to configure OSPF parameters for the member.
    """

    PROPERTIES = (
        GRID_MEMBERS, ADVERTISE_INTERFACE_VLAN, AREA_ID, AREA_TYPE,
        AUTHENTICATION_KEY, AUTHENTICATION_TYPE, AUTO_CALC_COST_ENABLED,
        COMMENT, COST, DEAD_INTERVAL, HELLO_INTERVAL, INTERFACE,
        IS_IPV4, KEY_ID, RETRANSMIT_INTERVAL, TRANSMIT_DELAY
    ) = (
        'grid_members', 'advertise_interface_vlan', 'area_id', 'area_type',
        'authentication_key', 'authentication_type', 'auto_calc_cost_enabled',
        'comment', 'cost', 'dead_interval', 'hello_interval', 'interface',
        'is_ipv4', 'key_id', 'retransmit_interval', 'transmit_delay'
    )

    AREA_TYPES = (
        'NSSA',
        'STANDARD',
        'STUB'
    )

    AUTHENTICATION_TYPES = (
        'MESSAGE_DIGEST',
        'NONE',
        'SIMPLE'
    )

    INTERFACES = (
        'IP',
        'LAN_HA'
    )

    DELIM = '/'

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.DDI),
        GRID_MEMBERS: properties.Schema(
            properties.Schema.LIST,
            _('List of Grid Member Names for Anycast IP address'),
            schema=properties.Schema(
                properties.Schema.STRING
            ),
            update_allowed=True,
            required=True),
        ADVERTISE_INTERFACE_VLAN: properties.Schema(
            properties.Schema.STRING,
            _('The VLAN used as the advertising interface '
              'for sending OSPF announcements.'),
            update_allowed=True),
        AREA_ID: properties.Schema(
            properties.Schema.STRING,
            _('The area ID value of the OSPF settings.'),
            update_allowed=True,
            required=True),
        AREA_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('The OSPF area type.'),
            update_allowed=True,
            constraints=[
                constraints.AllowedValues(AREA_TYPES)
            ]),
        AUTHENTICATION_KEY: properties.Schema(
            properties.Schema.STRING,
            _('The authentication password to use for OSPF.'),
            update_allowed=True),
        AUTHENTICATION_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('The authentication type used for the OSPF advertisement.'),
            update_allowed=True,
            constraints=[
                constraints.AllowedValues(AUTHENTICATION_TYPES)
            ]),
        AUTO_CALC_COST_ENABLED: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Determines if auto calculate cost is enabled or not.'),
            update_allowed=True,
            required=True),
        COMMENT: properties.Schema(
            properties.Schema.STRING,
            _('A descriptive comment of the OSPF configuration.'),
            update_allowed=True),
        COST: properties.Schema(
            properties.Schema.INTEGER,
            _('The cost metric associated with the OSPF advertisement.'),
            update_allowed=True),
        DEAD_INTERVAL: properties.Schema(
            properties.Schema.INTEGER,
            _('The dead interval value of OSPF (in seconds).'),
            update_allowed=True),
        HELLO_INTERVAL: properties.Schema(
            properties.Schema.INTEGER,
            _('The hello interval value of OSPF.'),
            update_allowed=True,),
        INTERFACE: properties.Schema(
            properties.Schema.STRING,
            _('The interface that sends out OSPF advertisement information.'),
            update_allowed=True,
            constraints=[
                constraints.AllowedValues(INTERFACES)
            ]),
        IS_IPV4: properties.Schema(
            properties.Schema.BOOLEAN,
            _('The OSPF protocol version. '),
            update_allowed=True,
            required=True),
        KEY_ID: properties.Schema(
            properties.Schema.INTEGER,
            _('The hash key identifier to use for'
              ' "MESSAGE_DIGEST" authentication.'),
            update_allowed=True),
        RETRANSMIT_INTERVAL: properties.Schema(
            properties.Schema.INTEGER,
            _('The retransmit interval time of OSPF (in seconds).'),
            update_allowed=True),
        TRANSMIT_DELAY: properties.Schema(
            properties.Schema.INTEGER,
            _('The transmit delay value of OSPF (in seconds).'),
            update_allowed=True),
    }

    @property
    def infoblox(self):
        if not getattr(self, 'infoblox_object', None):
            conn = self.properties[constants.CONNECTION]
            self.infoblox_object = resource_utils.connect_to_infoblox(conn)
        return self.infoblox_object

    def handle_create(self):
        ospf_options_dict = {
            name: self.properties.get(name) for name in self.PROPERTIES}
        for member_name in self.properties[self.GRID_MEMBERS]:
            self.infoblox.create_ospf(member_name,
                                      ospf_options_dict)
        self.resource_id_set(self.properties[self.AREA_ID])

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        if prop_diff:
            new_members = set(tmpl_diff['Properties']['grid_members'])
            if 'grid_members' in prop_diff:
                old_members = set(self.properties.get('grid_members'))
                to_remove = old_members - new_members
                for member in to_remove:
                    self.infoblox.delete_ospf(self.properties[self.AREA_ID],
                                              member)

                if len(prop_diff) > 1:
                    # OSPF setting was changed, so need to update all members
                    to_add = new_members
                else:
                    # OSPF setting is not changes, so it add to new members
                    to_add = new_members - old_members
            else:
                # OSPF setting was changed, so need to update all members
                to_add = new_members

            for member in to_add:
                self.infoblox.create_ospf(
                    member,
                    tmpl_diff['Properties'],
                    old_area_id=self.properties[self.AREA_ID])

    def handle_delete(self):
        for member in self.properties[self.GRID_MEMBERS]:
            self.infoblox.delete_ospf(self.properties[self.AREA_ID], member)


def resource_mapping():
    return {
        'Infoblox::Grid::Ospf': Ospf,
    }
