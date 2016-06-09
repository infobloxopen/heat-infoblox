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

import httplib
import logging
import netaddr
import time

from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from heat_infoblox import resource_utils


LOG = logging.getLogger(__name__)


class HaPair(resource.Resource):
    '''A resource which represents an Infoblox HA pair.

    This is used to combine two instances into HA pair.
    '''

    PROPERTIES = (
        NAME, VIP_PORT, NODE1_HA_PORT, NODE2_HA_PORT,
        NODE1_LAN1_PORT, NODE2_LAN1_PORT,
        VIP_FLOATING_IP, NODE1_FLOATING_IP, NODE2_FLOATING_IP,
        VIRTUAL_ROUTER_ID, NODE_WAIT_TIMEOUT, NODE_WAIT_RETRIES,
        NODE1_ADMIN, NODE1_PASSWORD, NODE2_ADMIN, NODE2_PASSWORD,
        UPDATE_ALLOWED_ADDRESS_PAIRS
    ) = (
        'name', 'vip', 'node1_ha', 'node2_ha', 'node1_lan1', 'node2_lan1',
        'vip_floating_ip', 'node1_floating_ip', 'node2_floating_ip',
        'virtual_router_id', 'node_wait_timeout', 'node_wait_retries',
        'node1_admin', 'node1_password', 'node2_admin', 'node2_password',
        'update_allowed_address_pairs'
    )

    ATTRIBUTES = (
        NAME_ATTR,
    ) = (
        'name',
    )

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Member name.')),
        VIP_PORT: resource_utils.port_schema(VIP_PORT, True),
        NODE1_HA_PORT: resource_utils.port_schema(NODE1_HA_PORT, True),
        NODE2_HA_PORT: resource_utils.port_schema(NODE2_HA_PORT, True),
        NODE1_LAN1_PORT: resource_utils.port_schema(NODE1_LAN1_PORT, True),
        NODE2_LAN1_PORT: resource_utils.port_schema(NODE2_LAN1_PORT, True),
        VIP_FLOATING_IP: properties.Schema(
            properties.Schema.STRING,
            _('VIP floating IP.'),
            required=True),
        NODE1_FLOATING_IP: properties.Schema(
            properties.Schema.STRING,
            _('Node1 floating IP.'),
            required=True),
        NODE2_FLOATING_IP: properties.Schema(
            properties.Schema.STRING,
            _('Node2 floating IP.'),
            required=True),
        VIRTUAL_ROUTER_ID: properties.Schema(
            properties.Schema.NUMBER,
            _('Virtual router ID.'),
            required=True),
        NODE_WAIT_TIMEOUT: properties.Schema(
            properties.Schema.NUMBER,
            _('Timeout between node check retries.'),
            required=False,
            default=30),
        NODE_WAIT_RETRIES: properties.Schema(
            properties.Schema.NUMBER,
            _('Node check retries count.'),
            required=False,
            default=50),
        NODE1_ADMIN: properties.Schema(
            properties.Schema.STRING,
            _('Node1 admin member.'),
            required=False,
            default='admin'),
        NODE1_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('Node1 admin member password.'),
            required=False,
            default='infoblox'),
        NODE2_ADMIN: properties.Schema(
            properties.Schema.STRING,
            _('Node2 admin member.'),
            required=False,
            default='admin'),
        NODE2_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('Node1 admin member password.'),
            required=False,
            default='infoblox'),
        UPDATE_ALLOWED_ADDRESS_PAIRS: properties.Schema(
            properties.Schema.BOOLEAN,
            required=False,
            default=True
            ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('The member name.'),
            attributes.Schema.STRING)
    }

    def node(self, ip, username, password, sslverify=False, max_retries=30):
        conn = {'url': 'https://%s/wapi/v2.3/' % ip,
                'username': username,
                'password': password,
                'sslverify': sslverify,
                'max_retries': max_retries}
        return resource_utils.connect_to_infoblox(conn)

    def _get_first_ip(self, port_name, is_ipv4=True):
        port = self.client('neutron').show_port(
            self.properties[port_name])['port']
        for ip in port['fixed_ips']:
            if ':' in ip['ip_address']:
                if not is_ipv4:
                    return ip
            else:
                if is_ipv4:
                    return ip

    def wait_for_https(self, ip):
        retries = self.properties[self.NODE_WAIT_RETRIES]
        timeout = self.properties[self.NODE_WAIT_TIMEOUT]
        https = httplib.HTTPSConnection(ip)
        while retries >= 0:
            try:
                https.connect()
            except Exception:
                time.sleep(timeout)
                retries = retries - 1
                LOG.debug('Waiting for HTTPS. Retry %s' % retries)
            else:
                return True
        return False

    def handle_create(self):
        vip = self._get_first_ip(self.VIP_PORT)
        ipv4_vip = vip['ip_address']
        ipv4_node1_ha = self._get_first_ip(self.NODE1_HA_PORT)['ip_address']
        ipv4_node2_ha = self._get_first_ip(self.NODE2_HA_PORT)['ip_address']
        ipv4_node1_lan1 = self._get_first_ip(
            self.NODE1_LAN1_PORT)['ip_address']
        ipv4_node2_lan1 = self._get_first_ip(
            self.NODE2_LAN1_PORT)['ip_address']
        subnet = self.client('neutron').show_subnet(vip['subnet_id'])['subnet']
        subnet_mask = str(netaddr.IPNetwork(subnet['cidr']).netmask)
        gateway = subnet['gateway_ip']
        vrid = self.properties[self.VIRTUAL_ROUTER_ID]
        if self.properties[self.UPDATE_ALLOWED_ADDRESS_PAIRS]:
            resource_utils.fix_ha_ports_mac(
                self.client('neutron'),
                {'ipv4': {'address': ipv4_vip}}, vrid, True,
                (self.properties[self.NODE1_HA_PORT],
                 self.properties[self.NODE2_HA_PORT]))
        # Wait for node1 WAPI
        self.wait_for_https(self.properties[self.NODE1_FLOATING_IP])
        node1 = self.node(self.properties[self.NODE1_FLOATING_IP],
                          self.properties[self.NODE1_ADMIN],
                          self.properties[self.NODE1_PASSWORD])
        ha_pair_config = {
            'enable_ha': True,
            'router_id': vrid,
            'vip_setting': {
                'address': ipv4_vip,
                'gateway': gateway,
                'subnet_mask': subnet_mask
                },
            'node_info': [
                {
                    'lan_ha_port_setting': {
                        'ha_ip_address': ipv4_node1_ha,
                        'mgmt_lan': ipv4_node1_lan1
                    }
                },
                {
                    'lan_ha_port_setting': {
                        'ha_ip_address': ipv4_node2_ha,
                        'mgmt_lan': ipv4_node2_lan1
                    }
                }
            ]
        }
        node1.update_member('infoblox.localdomain', ha_pair_config)
        # Wait for VIP and node2 WAPI
        self.wait_for_https(self.properties[self.VIP_FLOATING_IP])
        self.wait_for_https(self.properties[self.NODE2_FLOATING_IP])
        node2 = self.node(self.properties[self.NODE2_FLOATING_IP],
                          self.properties[self.NODE2_ADMIN],
                          self.properties[self.NODE2_PASSWORD])
        # Default grid_name is 'Infoblox' and secret is 'test'
        # We just created VM so use default values.
        node2.join_grid('Infoblox', ipv4_vip, 'test')
        name = self.properties[self.NAME]
        self.resource_id_set(name)


def resource_mapping():
    return {
        'Infoblox::Grid::HaPair': HaPair,
    }
