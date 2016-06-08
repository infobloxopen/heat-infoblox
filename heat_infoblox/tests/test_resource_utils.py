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

import mock

from heat.tests import common

from heat_infoblox import connector
from heat_infoblox import resource_utils


class ResourceUtilsTest(common.HeatTestCase):
    def setUp(self):
        super(ResourceUtilsTest, self).setUp()

    def test_wapi_config_file(self):

        connector.Infoblox = mock.MagicMock()
        resource_utils.connect_to_infoblox({'url': 'test_wapi_url',
                                            'username': 'test_username',
                                            'password': 'test_password',
                                            'sslverify': False})
        connector.Infoblox.assert_called_with({'url': 'test_wapi_url',
                                               'username': 'test_username',
                                               'password': 'test_password',
                                               'sslverify': False})

    def test_get_vrrp_mac(self):
        # For IPv4 should be '00:00:5E:00:01:00' with last octet = VRID
        mac_v4 = resource_utils.get_vrrp_mac(123, True)
        self.assertEqual(mac_v4, '00:00:5E:00:01:7B')
        # For IPv6 should be '00:00:5E:00:02:00' with last octet = VRID
        mac_v4 = resource_utils.get_vrrp_mac(153, True)
        self.assertEqual(mac_v4, '00:00:5E:00:01:99')
        # Check VRID type validation
        self.assertRaises(ValueError, resource_utils.get_vrrp_mac, None, True)
        self.assertRaises(ValueError, resource_utils.get_vrrp_mac, '11', True)

    def test_get_ip_address(self):
        vip = {
            'ipv4': {'address': '1.1.1.1'},
            'ipv6': {'virtual_ip': u'1234:5678:90ab:cdef::1'}
            }
        # Check get IPv4 address
        self.assertEqual(vip['ipv4']['address'],
                         resource_utils.get_ip_address(vip, True, 'vip'))
        # Check get IPv6 address
        self.assertEqual(vip['ipv6']['virtual_ip'],
                         resource_utils.get_ip_address(vip, False, 'vip'))
        # Check ip validation
        vip['ipv4']['address'] = 1
        vip['ipv6']['virtual_ip'] = None
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, True, 'vip')
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, False, 'vip')
        vip['ipv4'] = None
        vip['ipv6'] = None
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, True, 'vip')
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, False, 'vip')
        vip = {}
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, True, 'vip')
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, False, 'vip')
        vip = 1244
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, True, 'vip')
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, False, 'vip')
        vip = None
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, True, 'vip')
        self.assertRaises(ValueError, resource_utils.get_ip_address,
                          vip, False, 'vip')

    def test_fix_ha_ports_mac(self):
        neutron = mock.MagicMock()
        vip = {
            'ipv4': {'address': '1.1.1.1'},
            'ipv6': {'virtual_ip': '1234:5678:90ab:cdef::1'}
            }
        ports = ['port_1', 'port_2']
        vrid = 123
        mac_addr = '00:00:5E:00:01:7B'
        resource_utils.fix_ha_ports_mac(neutron, vip, vrid, use_ipv4=True,
                                        ports=ports)
        self.assertEqual(
            [mock.call(
                'port_1',
                {'port': {'allowed_address_pairs': [{
                    'ip_address': vip['ipv4']['address'],
                    'mac_address': mac_addr}]}}),
             mock.call(
                 'port_2',
                 {'port': {'allowed_address_pairs': [{
                     'ip_address': vip['ipv4']['address'],
                     'mac_address': mac_addr}]}})
             ],
            neutron.update_port.call_args_list
        )
        neutron = mock.MagicMock()
        vrid = 153
        mac_addr = '00:00:5E:00:02:99'
        resource_utils.fix_ha_ports_mac(neutron, vip, vrid, use_ipv4=False,
                                        ports=ports)
        self.assertEqual(
            [mock.call(
                'port_1',
                {'port': {'allowed_address_pairs': [{
                    'ip_address': vip['ipv6']['virtual_ip'],
                    'mac_address': mac_addr}]}}),
             mock.call(
                 'port_2',
                 {'port': {'allowed_address_pairs': [{
                     'ip_address': vip['ipv6']['virtual_ip'],
                     'mac_address': mac_addr}]}})
             ],
            neutron.update_port.call_args_list
        )
