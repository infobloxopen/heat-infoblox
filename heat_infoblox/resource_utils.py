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

from heat.common.i18n import _
from heat.engine import constraints
from heat.engine import properties

from heat_infoblox import connector
from heat_infoblox import constants

"""Utilities for specifying resources."""


def port_schema(port_name, is_required):
    return properties.Schema(
        properties.Schema.STRING,
        _('ID of an existing port to associate with the %s port.')
        % port_name,
        constraints=[
            constraints.CustomConstraint('neutron.port')
        ],
        required=is_required
    )

CONN_DESCR = {
    constants.NETMRI: {
        constants.API: "NetMRI API",
        constants.HOST: "The host name or IP address of the netmri.",
        constants.API_VERSION: 'The API version, for example "3".',
        constants.SSLVERIFY: "Flag to verify SSL, or path to a certificate.",
        constants.USE_SSL: "If true, HTTPS will be used",
        constants.USERNAME: 'The username for NetMRI.',
        constants.PASSWORD: 'The password for NetMRI.'
    },
    constants.DDI: {
        constants.API: "Infoblox WAPI",
        constants.URL: "The URL to the Infoblox WAPI (example: "
                       "'https://infoblox/wapi/v2.3')",
        constants.SSLVERIFY: "Flag to verify SSL, or path to a certificate.",
        constants.USERNAME: 'The username for Infoblox.',
        constants.PASSWORD: 'The password for Infoblox.'
    }
}


def connection_schema(conn_type):
    if conn_type == constants.NETMRI:
        conn_schema = {
            constants.HOST: properties.Schema(
                properties.Schema.STRING,
                CONN_DESCR[conn_type][constants.HOST],
                required=True
            ),
            constants.API_VERSION: properties.Schema(
                properties.Schema.STRING,
                CONN_DESCR[conn_type][constants.API_VERSION],
                required=True
            ),
            constants.USE_SSL: properties.Schema(
                properties.Schema.BOOLEAN,
                CONN_DESCR[conn_type][constants.USE_SSL],
                default=True
            )
        }
    else:
        conn_schema = {
            constants.URL: properties.Schema(
                properties.Schema.STRING,
                CONN_DESCR[conn_type][constants.URL],
                required=True
            )
        }

    conn_schema.update({
        constants.USERNAME: properties.Schema(
            properties.Schema.STRING,
            CONN_DESCR[conn_type][constants.USERNAME],
            required=True
        ),
        constants.PASSWORD: properties.Schema(
            properties.Schema.STRING,
            CONN_DESCR[conn_type][constants.PASSWORD],
            required=True
        ),
        constants.SSLVERIFY: properties.Schema(
            properties.Schema.BOOLEAN,
            CONN_DESCR[conn_type][constants.SSLVERIFY],
            default=True
        )
    })

    api_name = CONN_DESCR[conn_type][constants.API]
    return properties.Schema(
        properties.Schema.MAP,
        "The connection details for the %s" % api_name,
        required=True,
        schema=conn_schema
    )


def connect_to_infoblox(conn_params):
    from heat_infoblox import object_manipulator
    return object_manipulator.InfobloxObjectManipulator(
        connector.Infoblox({'url': conn_params[constants.URL],
                            'username': conn_params[constants.USERNAME],
                            'password': conn_params[constants.PASSWORD],
                            'sslverify': conn_params[constants.SSLVERIFY]}))


def get_vrrp_mac(vrid, use_ipv4):
    if not isinstance(vrid, int) or vrid < 1 or vrid > 255:
        raise ValueError('VRID should be an integer between 0 and 256.')
    VRRP_MAC_ADDR_BASE = '00:00:5E:00:'
    hvrid = hex(int(vrid)).upper()[-2:]
    if use_ipv4:
        return VRRP_MAC_ADDR_BASE + '01:' + hvrid
    else:
        return VRRP_MAC_ADDR_BASE + '02:' + hvrid


def get_ip_address(vip, use_ipv4, port_name):
    if not vip or not isinstance(vip, dict):
        raise ValueError('%s should be a dict.' % port_name)

    if use_ipv4:
        name = 'ipv4'
        addr = 'address'
    else:
        name = 'ipv6'
        addr = 'virtual_ip'

    ip = vip.get(name, None)
    if not ip or not isinstance(ip, dict):
        raise ValueError('%s["%s"] should be a dict.' % (port_name, name))

    address = ip.get(addr, None)
    if not address or not isinstance(address, basestring):
        raise ValueError(
            '%s["%s"]["%s"] should be an address.' % (port_name, name, addr))

    return address


def fix_ha_ports_mac(neutron, vip, vrid, use_ipv4, ports):
    for port in ports:
        props = {
            'allowed_address_pairs': [{
                'ip_address': get_ip_address(vip, use_ipv4, 'vip'),
                'mac_address': get_vrrp_mac(vrid, use_ipv4)
                }]
            }
        neutron.update_port(port, {'port': props})
