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
import netaddr

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


class GridMember(resource.Resource):
    '''A resource which represents an Infoblox Grid Member.

    This is used to provision new grid members on an existing grid. See the
    Grid Master resource to create a new grid.
    '''

    PROPERTIES = (
        NAME, MODEL, LICENSES, TEMP_LICENSES,
        REMOTE_CONSOLE, ADMIN_PASSWORD,
        MGMT_PORT, LAN1_PORT, LAN2_PORT, HA_PORT, CONFIG_ADDR_TYPE,
        GM_IP, GM_CERTIFICATE,
        NAT_IP,
        # only 'enable' supported for now
        DNS_SETTINGS, DNS_ENABLE, DNS_RECURSIVE_RESOLVER, DNS_PORTS,
        DNS_ENABLE_FIXED_RRSET_ORDER_FQDNS, DNS_FIXED_RRSET_ORDER_FQDNS,
        DNS_USE_FIXED_RRSET_ORDER_FQDNS,
        DNS_DTC_HEALTH_SOURCE, DNS_DTC_HEALTH_SOURCE_ADDRESS,
        DNS_RPZ_QNAME_WAIT_RECURSE, DNS_USE_RPZ_QNAME_WAIT_RECURSE,
        DNS_LOG_DTC_GSLB, DNS_LOG_DTC_HEALTH, DNS_UNBOUND_LOGGING_LEVEL,
        HA_PAIR, VIP_PORT, USE_IPV4_VIP, VIRTUAL_ROUTER_ID,
        LAN2_VIRTUAL_ROUTER_ID,
        NODE2_MGMT_PORT, NODE2_LAN1_PORT, NODE2_LAN2_PORT, NODE2_HA_PORT,
        VIP_VLAN_ID, VIP6_VLAN_ID, UPDATE_ALLOWED_ADDRESS_PAIRS
    ) = (
        'name', 'model', 'licenses', 'temp_licenses',
        'remote_console_enabled', 'admin_password',
        'MGMT', 'LAN1', 'LAN2', 'HA', 'config_addr_type',
        'gm_ip', 'gm_certificate',
        'nat_ip',
        'dns', 'enable', 'recursive_resolver', 'ports',
        'enable_fixed_rrset_order_fqdns', 'fixed_rrset_order_fqdns',
        'use_fixed_rrset_order_fqdns',
        'dtc_health_source', 'dtc_health_source_address',
        'rpz_qname_wait_recurse', 'use_rpz_qname_wait_recurse',
        'log_dtc_glsb', 'log_dtc_health', 'unbound_logging_level',
        'ha_pair', 'VIP', 'use_ipv4_vip', 'virtual_router_id',
        'lan2_virtual_router_id',
        'node2_MGMT', 'node2_LAN1', 'node2_LAN2', 'node2_HA',
        'vip_vlan_id', 'vip6_vlan_id', 'update_allowed_address_pairs'
    )

    ATTRIBUTES = (
        USER_DATA,
        NODE2_USER_DATA,
        NAME_ATTR,
        DNS_UNBOUND_CAPABLE
    ) = (
        'user_data',
        'node2_user_data',
        'name',
        'is_unbound_capable'
    )

    ALLOWED_MODELS = (
        'CP-V1400',
        'CP-V2200',
        'CP-V800',
        'IB-VM-100',
        'IB-VM-1410',
        'IB-VM-1420',
        'IB-VM-2210',
        'IB-VM-2220',
        'IB-VM-4010',
        'IB-VM-810',
        'IB-VM-820',
        'IB-VM-RSP',
        'Rev1',
        'Rev2'
    )

    ALLOWED_LICENSES_PRE_PROVISION = (
        'cloud_api',
        'dhcp',
        'dns',
        'dtc',
        'enterprise',
        'fireeye',
        'ms_management',
        'rpz',
        'vnios')

    ALLOWED_LICENSES_TEMP = (
        'dns',
        'rpz',
        'cloud',
        'cloud_api',
        'enterprise',
        'ipam',
        'vnios',
        'reporting')

    ALLOWED_CONFIG_ADDR_TYPES = (
        'IPV4',
        'IPV6',
        'BOTH')

    support_status = support.SupportStatus(
        support.UNSUPPORTED,
        _('See support.infoblox.com for support.'))

    properties_schema = {
        constants.CONNECTION:
            resource_utils.connection_schema(constants.DDI),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Member name.')),
        MODEL: properties.Schema(
            properties.Schema.STRING,
            _('Infoblox model name.'),
            constraints=[
                constraints.AllowedValues(ALLOWED_MODELS)
            ]),
        LICENSES: properties.Schema(
            properties.Schema.LIST,
            _('List of licenses to pre-provision.'),
            schema=properties.Schema(
                properties.Schema.STRING
            ),
            constraints=[
                constraints.AllowedValues(ALLOWED_LICENSES_PRE_PROVISION)
            ]),
        TEMP_LICENSES: properties.Schema(
            properties.Schema.LIST,
            _('List of temporary licenses to apply to the member.'),
            schema=properties.Schema(
                properties.Schema.STRING
            ),
            constraints=[
                constraints.AllowedValues(ALLOWED_LICENSES_TEMP)
            ]),
        REMOTE_CONSOLE: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Enable the remote console.')),
        ADMIN_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('The password to use for the admin user.')),
        GM_IP: properties.Schema(
            properties.Schema.STRING,
            _('The Gridmaster IP address.'),
            required=True),
        GM_CERTIFICATE: properties.Schema(
            properties.Schema.STRING,
            _('The Gridmaster SSL certificate for verification.'),
            required=False),
        NAT_IP: properties.Schema(
            properties.Schema.STRING,
            _('If the GM will see this member as a NATed address, enter that '
              'address here.'),
            required=False),
        MGMT_PORT: resource_utils.port_schema(MGMT_PORT, False),
        LAN1_PORT: resource_utils.port_schema(LAN1_PORT, True),
        LAN2_PORT: resource_utils.port_schema(LAN2_PORT, False),
        HA_PORT: resource_utils.port_schema(HA_PORT, False),
        CONFIG_ADDR_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('Address configuration types.'),
            constraints=[
                constraints.AllowedValues(ALLOWED_CONFIG_ADDR_TYPES)
            ],
            default='IPV4'),
        DNS_SETTINGS: properties.Schema(
            properties.Schema.MAP,
            _('The DNS settings for this member.'),
            required=False,
            schema={
                DNS_ENABLE: properties.Schema(
                    properties.Schema.BOOLEAN,
                    _('If true, enable DNS on this member.'),
                    default=False
                ),
            }),
        HA_PAIR: properties.Schema(
            properties.Schema.BOOLEAN,
            _('"True" if member should be configured as HA pair.'),
            required=False,
            default=False
            ),
        VIP_PORT: resource_utils.port_schema(VIP_PORT, False),
        USE_IPV4_VIP: properties.Schema(
            properties.Schema.BOOLEAN,
            required=False,
            default=True
            ),
        VIRTUAL_ROUTER_ID: properties.Schema(
            properties.Schema.INTEGER,
            _('Virtual Router ID. '
              'Warning: Must be unique on the local network.'),
            required=False,
            ),
        LAN2_VIRTUAL_ROUTER_ID: properties.Schema(
            properties.Schema.INTEGER,
            _('LAN2 Virtual Router ID. '
              'Should set if configured a LAN2 address.'),
            required=False,
            ),
        NODE2_MGMT_PORT: resource_utils.port_schema(NODE2_MGMT_PORT, False),
        NODE2_LAN1_PORT: resource_utils.port_schema(NODE2_LAN1_PORT, False),
        NODE2_LAN2_PORT: resource_utils.port_schema(NODE2_LAN2_PORT, False),
        NODE2_HA_PORT: resource_utils.port_schema(NODE2_HA_PORT, False),
        VIP_VLAN_ID: properties.Schema(
            properties.Schema.INTEGER,
            required=False,
            ),
        VIP6_VLAN_ID: properties.Schema(
            properties.Schema.INTEGER,
            required=False,
            ),
        UPDATE_ALLOWED_ADDRESS_PAIRS: properties.Schema(
            properties.Schema.BOOLEAN,
            required=False,
            default=True
            ),
    }

    attributes_schema = {
        USER_DATA: attributes.Schema(
            _('User data for the Nova boot process.'),
            attributes.Schema.STRING),
        NODE2_USER_DATA: attributes.Schema(
            _('Node 2 user data for the Nova boot process.'),
            attributes.Schema.STRING),
        NAME_ATTR: attributes.Schema(
            _('The member name.'),
            attributes.Schema.STRING)
    }

    def _make_network_settings(self, ip):
        subnet = self.client('neutron').show_subnet(ip['subnet_id'])['subnet']
        ipnet = netaddr.IPNetwork(subnet['cidr'])
        vip = {
            'address': ip['ip_address'],
            'subnet_mask': str(ipnet.netmask),
            'gateway': subnet['gateway_ip']
        }, subnet
        if self.properties[self.VIP_VLAN_ID]:
            vip['vlan_id'] = self.properties[self.VIP_VLAN_ID]
        return vip

    def _make_ipv6_settings(self, ip):
        subnet = self.client('neutron').show_subnet(ip['subnet_id'])['subnet']
        prefix = netaddr.IPNetwork(subnet['cidr'])
        autocfg = subnet['ipv6_ra_mode'] == "slaac"
        vip6 = {
            'virtual_ip': ip['ip_address'],
            'cidr_prefix': int(prefix.prefixlen),
            'gateway': subnet['gateway_ip'], 'enabled': True,
            'auto_router_config_enabled': autocfg
        }, subnet
        if self.properties[self.VIP6_VLAN_ID]:
            vip6['vlan_id'] = self.properties[self.VIP6_VLAN_ID]
        return vip6

    def infoblox(self):
        if not getattr(self, 'infoblox_object', None):
            conn = self.properties[constants.CONNECTION]
            self.infoblox_object = resource_utils.connect_to_infoblox(conn)
        return self.infoblox_object

    def _make_port_network_settings(self, port_name, return_subnets=False):
        if self.properties[port_name] is None:
            return None

        port = self.client('neutron').show_port(
            self.properties[port_name])['port']

        if port is None:
            return None

        ipv4 = None
        ipv6 = None
        ipv4_subnet = None
        ipv6_subnet = None
        for ip in port['fixed_ips']:
            if ':' in ip['ip_address'] and ipv6 is None:
                ipv6, ipv6_subnet = self._make_ipv6_settings(ip)
            else:
                if ipv4 is None:
                    ipv4, ipv4_subnet = self._make_network_settings(ip)
        result = {'ipv4': ipv4, 'ipv6': ipv6}
        if return_subnets:
            result['ipv4_subnet'] = ipv4_subnet
            result['ipv6_subnet'] = ipv6_subnet
        return result

    def handle_create(self):
        mgmt = self._make_port_network_settings(self.MGMT_PORT)
        lan1 = self._make_port_network_settings(self.LAN1_PORT)
        lan2 = self._make_port_network_settings(self.LAN2_PORT)

        name = self.properties[self.NAME]
        nat = self.properties[self.NAT_IP]

        ha_pair = self.properties[self.HA_PAIR]
        if ha_pair:
            vrid = self.properties[self.VIRTUAL_ROUTER_ID]
            lan2_vrid = self.properties[self.LAN2_VIRTUAL_ROUTER_ID]
            vip = self._make_port_network_settings(self.VIP_PORT)
            node1_ha = self._make_port_network_settings(self.HA_PORT)
            node2_ha = self._make_port_network_settings(self.NODE2_HA_PORT)
            node2_lan1 = self._make_port_network_settings(self.NODE2_LAN1_PORT)
            node2_mgmt = self._make_port_network_settings(self.NODE2_MGMT_PORT)
            use_ipv4_vip = self.properties[self.USE_IPV4_VIP]
            config_addr_type = self.properties[self.CONFIG_ADDR_TYPE]
            if self.properties[self.UPDATE_ALLOWED_ADDRESS_PAIRS]:
                # Add 'allowed_address_pairs' to HA ports.
                resource_utils.fix_ha_ports_mac(
                    self.client('neutron'),
                    vip, vrid, use_ipv4_vip,
                    (self.properties[self.HA_PORT],
                     self.properties[self.NODE2_HA_PORT]))
            # Create infoblox HA pair member
            self.infoblox().create_member(
                name=name, config_addr_type=config_addr_type,
                mgmt=mgmt, vip=vip, lan2=lan2, nat_ip=nat,
                ha_pair=ha_pair, use_v4_vrrp=use_ipv4_vip,
                node1_ha=node1_ha, node2_ha=node2_ha,
                node1_lan1=lan1, node2_lan1=node2_lan1,
                node2_mgmt=node2_mgmt, vrid=vrid, lan2_vrid=lan2_vrid)
        else:
            self.infoblox().create_member(name=name, mgmt=mgmt, vip=lan1,
                                          lan2=lan2, nat_ip=nat)

        self.infoblox().pre_provision_member(
            name,
            hwmodel=self.properties[self.MODEL], hwtype='IB-VNIOS',
            licenses=self.properties[self.LICENSES], ha_pair=ha_pair)

        dns = self.properties[self.DNS_SETTINGS]
        if dns:
            self.infoblox().configure_member_dns(
                name,
                enable_dns=dns['enable']
            )

        self.resource_id_set(name)

    def _remove_from_all_ns_groups(self):
        # This is a workaround needed because Juno Heat does not honor
        # dependencies in nested autoscale group stacks.
        fields = {'name', 'grid_primary', 'grid_secondaries'}
        with lockutils.lock(self.resource_id, external=True,
                            lock_file_prefix='infoblox-ns_group-update'):
            groups = self.infoblox().get_all_ns_groups(return_fields=fields)
            for group in groups:
                new_list = {}
                changed = False
                for field in ('grid_primary', 'grid_secondaries'):
                    new_list[field] = []
                    for member in group[field]:
                        if member['name'] != self.resource_id:
                            new_list[field].append(member)
                        else:
                            changed = True
                if changed:
                    self.infoblox().update_ns_group(group['name'], new_list)

    def handle_delete(self):
        if self.resource_id is not None:
            self._remove_from_all_ns_groups()
            self.infoblox().delete_member(self.resource_id)

    def _get_dhcp_status_for_port(self, port_settings):
        status = {'ipv4': False,
                  'ipv6': False}

        if port_settings['ipv4'] and port_settings['ipv4_subnet']:
            status['ipv4'] = port_settings['ipv4_subnet']['enable_dhcp']

        if port_settings['ipv6'] and port_settings['ipv6_subnet']:
            status['ipv6'] = port_settings['ipv6_subnet']['enable_dhcp']
        return status

    def _make_user_data(self, member, token, node=0):
        user_data = '#infoblox-config\n\n'

        temp_licenses = self.properties[self.TEMP_LICENSES]
        if temp_licenses and len(temp_licenses) > 0:
            user_data += 'temp_license: %s\n' % ','.join(temp_licenses)

        remote_console = self.properties[self.REMOTE_CONSOLE]
        if remote_console is not None:
            user_data += 'remote_console_enabled: %s\n' % remote_console

        admin_password = self.properties[self.ADMIN_PASSWORD]
        if admin_password is not None:
            user_data += 'default_admin_password: %s\n' % admin_password

        vip = member.get('vip_setting', None)
        ipv6 = member.get('ipv6_setting', None)
        enable_ha = member.get('enable_ha', False)
        if ipv6 and not ipv6.get('enabled', False):
            ipv6 = None

        lan1 = self._make_port_network_settings(self.LAN1_PORT,
                                                return_subnets=True)
        dhcp_status = self._get_dhcp_status_for_port(lan1)
        # Do not generate userdata for port if dhcp is enabled in subnet
        need_vip = vip and not dhcp_status.get('ipv4')
        need_ipv6 = ipv6 and not dhcp_status.get('ipv6')

        if need_vip or need_ipv6:
            user_data += 'lan1:\n'

        if need_vip:
            if enable_ha:
                node_info = member.get('node_info')
                user_data += '  v4_addr: %s\n' % node_info[
                    node]['lan_ha_port_setting']['mgmt_lan']
            else:
                user_data += '  v4_addr: %s\n' % vip['address']
            user_data += '  v4_netmask: %s\n' % vip['subnet_mask']
            user_data += '  v4_gw: %s\n' % vip['gateway']

        if need_ipv6:
            user_data += '  v6_addr: %s\n' % ipv6['virtual_ip']
            user_data += '  v6_cidr: %s\n' % ipv6['cidr_prefix']
            if not ipv6['auto_router_config_enabled']:
                user_data += '  v6_gw: %s\n' % ipv6['gateway']

        if token and len(token) > 0:
            user_data += 'gridmaster:\n'
            user_data += '  token: %s\n' % token[node]['token']
            user_data += '  ip_addr: %s\n' % self.properties[self.GM_IP]
            user_data += '  certificate: |\n    %s\n' % self.properties[
                self.GM_CERTIFICATE
            ].replace('\n', '\n    ')

        LOG.debug('user_data: %s' % user_data)

        return user_data

    def _get_member_tokens(self, member):
        token = self.infoblox().connector.call_func(
            'read_token',
            member['_ref'], {})['pnode_tokens']
        if len(token) == 0:
            self.infoblox().connector.call_func(
                'create_token',
                member['_ref'], {})['pnode_tokens']
            token = self.infoblox().connector.call_func(
                'read_token',
                member['_ref'], {})['pnode_tokens']
        return token

    def _resolve_attribute(self, name):
        member_name = self.resource_id
        member = self.infoblox().get_member_obj(
            member_name,
            fail_if_no_member=True,
            return_fields=['host_name', 'vip_setting', 'ipv6_setting',
                           'enable_ha', 'node_info'])
        LOG.debug("MEMBER for %s = %s" % (name, member))
        if name == self.USER_DATA:
            token = self._get_member_tokens(member)
            return self._make_user_data(member, token, 0)
        if name == self.NODE2_USER_DATA:
            token = self._get_member_tokens(member)
            return self._make_user_data(member, token, 1)
        if name == self.NAME_ATTR:
            return member['host_name']
        return None


def resource_mapping():
    return {
        'Infoblox::Grid::Member': GridMember,
    }
