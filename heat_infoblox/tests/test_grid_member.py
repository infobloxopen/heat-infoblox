# Copyright 2015 Infoblox Inc.
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

import copy
import mock
import os

from oslo_config import cfg

from heat.engine import stack
from heat.engine import template
from heat.tests import common
from heat.tests import utils
from heat_infoblox.resources import grid_member
from heat_infoblox.tests.utils import create_side_effect

grid_member_template = {
    'heat_template_version': '2013-05-23',
    'resources': {
        'my_member': {
            'type': 'Infoblox::Grid::Member',
            'properties': {
                'name': 'my-name',
                'wapi_url': 'https://127.0.0.1/wapi/v2.2/',
                'gm_ip': '10.1.1.2',
                'gm_certificate': 'testing',
                'LAN1': 'abc123'
            }
        }
    }
}

DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


class GridMemberTest(common.HeatTestCase):
    def setUp(self):
        heat_infoblox_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir))
        cfg.CONF.import_opt('plugin_dirs', 'heat.common.config')
        cfg.CONF.import_opt('lock_path', 'oslo_concurrency.lockutils',
                            group='oslo_concurrency')
        cfg.CONF.set_override('plugin_dirs', heat_infoblox_path)
        cfg.CONF.set_override('lock_path', '/tmp/', group='oslo_concurrency')
        super(GridMemberTest, self).setUp()

        self.ctx = utils.dummy_context()
        self.set_stack(grid_member_template)

        self.base_member = {
            'host_name': 'host.name',
            'vip_setting': {
                'subnet_mask': '255.255.255.0',
                'address': '1.1.1.2',
                'gateway': '1.1.1.1'
            },
            'ipv6_setting': {
                'auto_router_config_enabled': False,
                'enabled': False
            }
        }

        self.ipv4_member = self.base_member.copy()
        self.ipv6_member = self.base_member.copy()
        self.ipv6_member.pop('vip_setting')

        self.ipv6_member['ipv6_setting'] = {
            'auto_router_config_enabled': False,
            'enabled': True,
            'cidr_prefix': 64,
            'gateway': '2001:db81::1',
            'virtual_ip': '2001:db81::4'
        }

        self.ipv4_6_member = self.base_member.copy()
        self.ipv4_6_member['ipv6_setting'] = self.ipv6_member['ipv6_setting']

        self.ipv4_ha_member = self.ipv4_member.copy()
        self.ipv4_ha_member['enable_ha'] = True
        self.ipv4_ha_member['node_info'] = [
            {'lan_ha_port_setting': {'mgmt_lan': '1.1.1.2'}},
            {'lan_ha_port_setting': {'mgmt_lan': '1.1.1.3'}}
            ]

    def set_stack(self, stack_template):
        self.stack = stack.Stack(
            self.ctx, 'grid_member_test_stack',
            template.Template(stack_template)
        )
        self.my_member = self.stack['my_member']
        self.my_member.client = mock.MagicMock()
        self.my_member.infoblox_object = mock.MagicMock()
        self.my_member._get_member_tokens = mock.MagicMock()

    def set_member(self, mem):
        self.my_member.infoblox_object.get_member.return_value = [mem]

    def set_member_obj(self, mem):
        self.my_member.infoblox_object.get_member_obj.return_value = mem

    def set_token(self, t):
        self.my_member._get_member_tokens.return_value = [
            {'token': t[0]},
            {'token': t[1]}
        ]

    def set_interface(self, interface, tmpl=None):
        if tmpl is None:
            tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props[interface] = interface
        self.set_stack(tmpl)
        self.my_member.infoblox_object.create_member = mock.MagicMock()
        return tmpl

    def _empty_ifc(self):
        return {'ipv4': None, 'ipv6': None}

    def test_mgmt(self):
        self.set_interface('MGMT')
        self.my_member.handle_create()
        cm = self.my_member.infoblox_object.create_member
        cm.assert_called_with(name='my-name', mgmt=self._empty_ifc(),
                              vip=self._empty_ifc(), lan2=None, nat_ip=None)

    def test_lan2(self):
        self.set_interface('LAN2')
        self.my_member.handle_create()
        cm = self.my_member.infoblox_object.create_member
        cm.assert_called_with(name='my-name', lan2=self._empty_ifc(),
                              vip=self._empty_ifc(), mgmt=None, nat_ip=None)

    def test_mgmt_lan2(self):
        tmpl = self.set_interface('MGMT')
        self.set_interface('LAN2', tmpl=tmpl)
        self.my_member.handle_create()
        cm = self.my_member.infoblox_object.create_member
        cm.assert_called_with(name='my-name', mgmt=self._empty_ifc(),
                              vip=self._empty_ifc(), lan2=self._empty_ifc(),
                              nat_ip=None)

    def set_dns(self, dns, tmpl=None):
        if tmpl is None:
            tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['dns'] = dns
        self.set_stack(tmpl)
        self.my_member.client = mock.MagicMock()
        self.my_member.infoblox_object.create_member = mock.MagicMock()
        self.my_member.infoblox_object.pre_provision_member = mock.MagicMock()
        return tmpl

    def test_dns_settings_enabled(self):
        dns = {'enable': True}
        self.set_dns(dns)
        self.my_member.handle_create()
        config_dns = self.my_member.infoblox_object.configure_member_dns
        config_dns.assert_called_with('my-name', enable_dns=True)

    def test_dns_settings_disabled(self):
        dns = {'enable': False}
        self.set_dns(dns)
        self.my_member.handle_create()
        config_dns = self.my_member.infoblox_object.configure_member_dns
        config_dns.assert_called_with('my-name', enable_dns=False)

    def test_resource_mapping(self):
        mapping = grid_member.resource_mapping()
        self.assertEqual(1, len(mapping))
        self.assertEqual(grid_member.GridMember,
                         mapping['Infoblox::Grid::Member'])

    def test_user_data_lan1_ipv4(self):
        self.set_member_obj(self.ipv4_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v4_addr: 1.1.1.2\n'
            '  v4_netmask: 255.255.255.0\n'
            '  v4_gw: 1.1.1.1\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_member)

    def test_user_data_lan1_ipv4_dhcp_disabled(self):
        dhcp_status = mock.Mock(return_value={'ipv4': False, 'ipv6': True})
        self.set_member_obj(self.ipv4_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        self.my_member._get_dhcp_status_for_port = dhcp_status
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v4_addr: 1.1.1.2\n'
            '  v4_netmask: 255.255.255.0\n'
            '  v4_gw: 1.1.1.1\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_member)

    def test_user_data_lan1_ipv4_dhcp_enabled(self):
        dhcp_status = mock.Mock(return_value={'ipv4': True, 'ipv6': True})
        self.set_member_obj(self.ipv4_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        self.my_member._get_dhcp_status_for_port = dhcp_status
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_member)

    def test_user_data_lan1_ipv6(self):
        self.set_member_obj(self.ipv6_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v6_addr: 2001:db81::4\n'
            '  v6_cidr: 64\n'
            '  v6_gw: 2001:db81::1\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv6_member)

    def test_user_data_lan1_ipv4_6(self):
        self.set_member_obj(self.ipv4_6_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v4_addr: 1.1.1.2\n'
            '  v4_netmask: 255.255.255.0\n'
            '  v4_gw: 1.1.1.1\n'
            '  v6_addr: 2001:db81::4\n'
            '  v6_cidr: 64\n'
            '  v6_gw: 2001:db81::1\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_6_member)

    def test_user_data_ipv4_ha(self):
        self.set_member_obj(self.ipv4_ha_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v4_addr: 1.1.1.2\n'
            '  v4_netmask: 255.255.255.0\n'
            '  v4_gw: 1.1.1.1\n'
            'gridmaster:\n'
            '  token: abcdefg\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_ha_member)

    def test_user_data2_ipv4_ha(self):
        self.set_member_obj(self.ipv4_ha_member)
        self.set_token(['abcdefg', 'hijklmnop'])
        ud2 = self.my_member._resolve_attribute('node2_user_data')
        self.assertEqual(
            '#infoblox-config\n\nlan1:\n'
            '  v4_addr: 1.1.1.3\n'
            '  v4_netmask: 255.255.255.0\n'
            '  v4_gw: 1.1.1.1\n'
            'gridmaster:\n'
            '  token: hijklmnop\n'
            '  ip_addr: 10.1.1.2\n'
            '  certificate: |\n    testing\n',
            ud2
        )
        self.my_member._get_member_tokens.assert_called_once_with(
            self.ipv4_ha_member)

    def test_temp_licenses_none(self):
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertFalse('temp_license:' in ud)

    def test_temp_licenses_single(self):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['temp_licenses'] = ["vnios"]
        self.set_stack(tmpl)
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertTrue('temp_license: vnios\n' in ud)

    def test_temp_licenses_multiple(self):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['temp_licenses'] = ["vnios", "dns"]
        self.set_stack(tmpl)
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertTrue('temp_license: vnios,dns\n' in ud)

    def test_remote_console_enabled_none(self):
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertFalse('remote_console_enabled:' in ud)

    def test_remote_console_enabled_false(self):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['remote_console_enabled'] = False
        self.set_stack(tmpl)
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertTrue('remote_console_enabled: False\n' in ud)

    def test_remote_console_enabled_true(self):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['remote_console_enabled'] = True
        self.set_stack(tmpl)
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertTrue('remote_console_enabled: True\n' in ud)

    def test_admin_password_none(self):
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertFalse('default_admin_password:' in ud)

    def test_admin_password_set(self):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['admin_password'] = 'infoblox'
        self.set_stack(tmpl)
        self.set_member(self.base_member)
        self.set_token(['a', 'b'])
        ud = self.my_member._resolve_attribute('user_data')
        self.assertTrue('default_admin_password: infoblox\n' in ud)

    def test_resolve_attribute_name(self):
        self.set_member_obj(self.ipv4_member)
        name = self.my_member._resolve_attribute('name')
        self.assertEqual('host.name', name)
        self.my_member._get_member_tokens.assert_not_called()

    def test_handle_create(self):
        self.set_member(self.base_member)
        self.my_member.client = mock.MagicMock()
        self.my_member.resource_id = None
        self.my_member.handle_create()
        self.assertEqual('my-name', self.my_member.resource_id)

    def prepair_ha_pair_member(self, update_ports=True):
        tmpl = copy.deepcopy(grid_member_template)
        props = tmpl['resources']['my_member']['properties']
        props['update_allowed_address_pairs'] = update_ports
        props['admin_password'] = 'infoblox'
        props['ha_pair'] = True
        props['virtual_router_id'] = 123
        props['licenses'] = ['dns', 'dhcp', 'grid']
        ports = {
            'VIP': {
                'ipv4': {'address': '1.1.1.6', 'subnet_mask': '255.255.255.0',
                         'gateway': '1.1.1.1'
                         }
                },
            'LAN1': {
                'ipv4': {'address': '1.1.1.4', 'subnet_mask': '255.255.255.0',
                         'gateway': '1.1.1.1'
                         }
                },
            'HA': {
                'ipv4': {'address': '1.1.1.2', 'subnet_mask': '255.255.255.0',
                         'gateway': '1.1.1.1'
                         }
                },
            'node2_LAN1': {
                'ipv4': {'address': '1.1.1.5', 'subnet_mask': '255.255.255.0',
                         'gateway': '1.1.1.1'
                         }
                },
            'node2_HA': {
                'ipv4': {'address': '1.1.1.3', 'subnet_mask': '255.255.255.0',
                         'gateway': '1.1.1.1'
                         }
                },
            }
        for port in ports.keys():
            props[port] = port
        self.set_stack(tmpl)
        self.set_member_obj(self.ipv4_ha_member)
        self.my_member.client = mock.MagicMock()
        make_net_settings = mock.MagicMock()
        make_net_settings.side_effect = create_side_effect(ports)
        self.my_member._make_port_network_settings = make_net_settings
        self.my_member.resource_id = None
        clients = {'neutron': mock.MagicMock()}
        self.my_member.client.side_effect = create_side_effect(clients)
        return (props, clients, ports)

    def test_handle_create_ha_pair(self):
        (props, clients, ports) = self.prepair_ha_pair_member()
        # Call 'handle_create' method
        with mock.patch('heat_infoblox.resources.grid_member.'
                        'resource_utils.fix_ha_ports_mac') as fix_ha_ports:
            self.my_member.handle_create()
            fix_ha_ports.assert_called_once_with(
                clients['neutron'],
                ports['VIP'],
                props['virtual_router_id'],
                True,
                (props['HA'], props['node2_HA']))
        # Check calls
        self.assertEqual(
            [mock.call('MGMT'), mock.call('LAN1'), mock.call('LAN2'),
             mock.call('VIP'), mock.call('HA'), mock.call('node2_HA'),
             mock.call('node2_LAN1'), mock.call('node2_MGMT')],
            self.my_member._make_port_network_settings.call_args_list)
        infoblox = self.my_member.infoblox_object
        infoblox.create_member.assert_called_once_with(
            config_addr_type='IPV4', ha_pair=True, lan2=None, lan2_vrid=None,
            mgmt=None, name='my-name', nat_ip=None,
            node1_ha=ports['HA'],
            node1_lan1=ports['LAN1'],
            node2_ha=ports['node2_HA'],
            node2_lan1=ports['node2_LAN1'],
            node2_mgmt=None, use_v4_vrrp=True,
            vip=ports['VIP'],
            vrid=123)
        infoblox.pre_provision_member.assert_called_once_with(
            'my-name', ha_pair=True, hwmodel=None, hwtype='IB-VNIOS',
            licenses=props['licenses'])
        infoblox.configure_member_dns.assert_not_called()

    def test_update_allowed_address_pairs(self):
        # Prepair member with update_allowed_address_pairs set to False
        (props, clients, ports) = self.prepair_ha_pair_member(
            update_ports=False)
        # Call 'handle_create' method and check that fix_ha_ports not called
        with mock.patch('heat_infoblox.resources.grid_member.'
                        'resource_utils.fix_ha_ports_mac') as fix_ha_ports:
            self.my_member.handle_create()
            fix_ha_ports.assert_not_called()

    def test_handle_delete_none(self):
        self.set_member(self.base_member)
        self.my_member.resource_id = None
        self.assertIsNone(self.my_member.handle_delete())

    def test_handle_delete(self):
        self.set_member(self.base_member)
        self.my_member.resource_id = 'myname'
        self.my_member.infoblox_object.delete_member.return_value = None
        self.assertIsNone(self.my_member.handle_delete())

    def set_net_info(self, port, subnet):
        attrs = {'show_port.return_value': port,
                 'show_subnet.return_value': subnet}
        self.my_member.client = mock.Mock()
        self.my_member.client.return_value = mock.Mock(**attrs)

    def _make_port_subnet(self, ip, gw, cidr, v6mode=None, enable_dhcp=False):
        port = {
            'port': {
                'fixed_ips': [
                    {'ip_address': ip, 'subnet_id': 'junk'},
                ]
            }
        }
        subnet = {'subnet': {'cidr': cidr, 'gateway_ip': gw,
                             'enable_dhcp': enable_dhcp}}
        if v6mode is not None:
            subnet['subnet']['ipv6_ra_mode'] = v6mode

        return port, subnet

    def test_make_network_settings_ipv4(self):
        port, subnet = self._make_port_subnet('1.2.3.4', '1.2.3.10',
                                              '1.2.3.0/25')
        self.set_net_info(port, subnet)
        settings = self.my_member._make_port_network_settings('LAN1')
        expected = {'ipv4': {'address': '1.2.3.4', 'gateway': '1.2.3.10',
                    'subnet_mask': '255.255.255.128'}, 'ipv6': None}
        self.assertEqual(expected, settings)

    def test_make_network_settings_ipv6_slaac(self):
        port, subnet = self._make_port_subnet('1::4', '1::10',
                                              '1::0/64', 'slaac')
        self.set_net_info(port, subnet)
        settings = self.my_member._make_port_network_settings('LAN1')
        ipv6 = {'auto_router_config_enabled': True, 'cidr_prefix': 64,
                'enabled': True, 'gateway': '1::10', 'virtual_ip': '1::4'}
        expected = {'ipv4': None, 'ipv6': ipv6}
        self.assertEqual(expected, settings)

    def test_make_network_settings_ipv6_stateful(self):
        port, subnet = self._make_port_subnet('1::4', '1::10',
                                              '1::0/64', 'stateful')
        self.set_net_info(port, subnet)
        settings = self.my_member._make_port_network_settings('LAN1')
        ipv6 = {'auto_router_config_enabled': False, 'cidr_prefix': 64,
                'enabled': True, 'gateway': '1::10', 'virtual_ip': '1::4'}
        expected = {'ipv4': None, 'ipv6': ipv6}
        self.assertEqual(expected, settings)

    def test_make_network_settings_and_dhcp_status(self):
        port, subnet = self._make_port_subnet('1.2.3.4', '1.2.3.10',
                                              '1.2.3.0/25', enable_dhcp=True)
        self.set_net_info(port, subnet)
        settings = self.my_member._make_port_network_settings(
            'LAN1', return_subnets=True)
        expected = {'ipv4': {'address': '1.2.3.4', 'gateway': '1.2.3.10',
                             'subnet_mask': '255.255.255.128'},
                    'ipv6': None,
                    'ipv4_subnet': subnet['subnet'],
                    'ipv6_subnet': None}
        self.assertEqual(expected, settings)
        expected_dhcp_status = {'ipv4': True, 'ipv6': False}
        dhcp_status = self.my_member._get_dhcp_status_for_port(settings)
        self.assertEqual(expected_dhcp_status, dhcp_status)

    def test__get_dhcp_status_for_port(self):
        input_data = (
            {'ipv4': {'address': '1.2.3.4'},
             'ipv6': None,
             'ipv4_subnet': {'cidr': '1.2.3..0/24', 'enable_dhcp': True},
             'ipv6_subnet': None},
            {'ipv4': {'address': '1.2.3.4'},
             'ipv6': {'cidr_prefix': 64, 'virtual_ip': '1::4'},
             'ipv4_subnet': {'cidr': '1.2.3.0/24', 'enable_dhcp': True},
             'ipv6_subnet': {'cidr': '1::/64', 'enable_dhcp': True}},
            {'ipv4': {'address': '1.2.3.4'},
             'ipv6': {'cidr_prefix': 64, 'virtual_ip': '1::4'},
             'ipv4_subnet': {'cidr': '1.2.3.0/24', 'enable_dhcp': False},
             'ipv6_subnet': {'cidr': '1::/64', 'enable_dhcp': False}},
            {'ipv4': None,
             'ipv6': {'cidr_prefix': 64, 'virtual_ip': '1::4'},
             'ipv4_subnet': None,
             'ipv6_subnet': {'cidr': '1::/64', 'enable_dhcp': True}},
        )
        output_data = ({'ipv4': True, 'ipv6': False},
                       {'ipv4': True, 'ipv6': True},
                       {'ipv4': False, 'ipv6': False},
                       {'ipv4': False, 'ipv6': True},)
        for (input, output) in zip(input_data, output_data):
            self.assertEqual(output,
                             self.my_member._get_dhcp_status_for_port(input))

    def test_remove_from_all_ns_groups(self):
        groups = [
            {
                'name': 'my-group',
                'grid_primary': [{'name': 'foo-bar'}],
                'grid_secondaries': [{'name': 'my-name'}]
            },
            {
                'name': 'other-group',
                'grid_primary': [{'name': 'foo-bar'}],
                'grid_secondaries': [{'name': 'bar-foo'}]
            }
        ]
        ibobj = self.my_member.infoblox_object
        ibobj.get_all_ns_groups.return_value = groups
        self.my_member.resource_id = 'my-name'
        self.my_member._remove_from_all_ns_groups()
        ibobj.update_ns_group.assert_called_once_with(
            'my-group',
            {
                'grid_primary': [{'name': 'foo-bar'}],
                'grid_secondaries': []
            }
        )
