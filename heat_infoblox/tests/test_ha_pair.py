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
import os

from oslo_config import cfg

from heat.engine import stack
from heat.engine import template
from heat.tests import common
from heat.tests import utils
from heat_infoblox.resources import ha_pair
from heat_infoblox.tests.utils import create_side_effect

ha_pair_template = {
    'heat_template_version': '2013-05-23',
    'resources': {
        'my_ha_pair': {
            'type': 'Infoblox::Grid::HaPair',
            'properties': {
                'name': 'HaPair1',
                'vip': 'VIP',
                'node1_ha': 'NODE1_HA',
                'node2_ha': 'NODE2_HA',
                'node1_lan1': 'NODE1_LAN1',
                'node2_lan1': 'NODE2_LAN1',
                'vip_floating_ip': 'VIP_FLOATING_IP',
                'node1_floating_ip': 'NODE1_FLOATING_IP',
                'node2_floating_ip': 'NODE2_FLOATING_IP',
                'virtual_router_id': 123
            }
        }
    }
}

DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


class HaPairTest(common.HeatTestCase):
    def setUp(self):
        heat_infoblox_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir))
        cfg.CONF.import_opt('plugin_dirs', 'heat.common.config')
        cfg.CONF.set_override('plugin_dirs', heat_infoblox_path)
        super(HaPairTest, self).setUp()
        self.ctx = utils.dummy_context()

    def set_stack(self, stack_template):
        self.stack = stack.Stack(
            self.ctx, 'ha_pair_test_stack',
            template.Template(stack_template)
        )
        self.my_ha_pair = self.stack['my_ha_pair']

    def test_resource_mapping(self):
        mapping = ha_pair.resource_mapping()
        self.assertEqual(1, len(mapping))
        self.assertEqual(ha_pair.HaPair,
                         mapping['Infoblox::Grid::HaPair'])

    def prepair_ha_pair(self, update_ports=True):
        props = ha_pair_template['resources']['my_ha_pair']['properties']
        props['update_allowed_address_pairs'] = update_ports
        self.set_stack(ha_pair_template)
        self.my_ha_pair.client = mock.MagicMock()
        get_first_ip = mock.MagicMock()
        ports = {
            'vip': {'ip_address': '1.1.1.6', 'subnet_id': 'vip_subnet'},
            'node1_lan1': {'ip_address': '1.1.1.4'},
            'node1_ha': {'ip_address': '1.1.1.2'},
            'node2_lan1': {'ip_address': '1.1.1.5'},
            'node2_ha': {'ip_address': '1.1.1.3'},
            }
        get_first_ip.side_effect = create_side_effect(ports)
        self.my_ha_pair._get_first_ip = get_first_ip
        self.my_ha_pair.node = mock.MagicMock()
        self.my_ha_pair.wait_for_https = mock.MagicMock()
        show_subnet = mock.MagicMock()
        show_subnet.return_value = {'subnet': {'cidr': '1.1.1.0/24',
                                               'gateway_ip': '1.1.1.1'}}
        neutron = mock.MagicMock()
        neutron.show_subnet = show_subnet
        self.my_ha_pair.client = mock.MagicMock(return_value=neutron)
        return (props, neutron, ports)

    def test_handle_create(self):
        (props, neutron, ports) = self.prepair_ha_pair()
        with mock.patch('heat_infoblox.resources.grid_member.'
                        'resource_utils.fix_ha_ports_mac') as fix_ha_ports:
            # Call 'handle_create' method
            self.my_ha_pair.handle_create()
            fix_ha_ports.assert_called_once_with(
                neutron,
                {'ipv4': {'address': ports['vip']['ip_address']}},
                props['virtual_router_id'],
                True,
                (props['node1_ha'], props['node2_ha']))
        # Check calls
        self.assertEqual(
            [mock.call('vip'), mock.call('node1_ha'), mock.call('node2_ha'),
             mock.call('node1_lan1'), mock.call('node2_lan1')],
            self.my_ha_pair._get_first_ip.mock_calls)
        self.assertEqual(
            [mock.call('NODE1_FLOATING_IP'), mock.call('VIP_FLOATING_IP'),
             mock.call('NODE2_FLOATING_IP')],
            self.my_ha_pair.wait_for_https.mock_calls)
        self.assertEqual(
            [mock.call('NODE1_FLOATING_IP', 'admin', 'infoblox'),
             mock.call().update_member(
                 'infoblox.localdomain',
                 {'enable_ha': True, 'router_id': 123,
                  'node_info': [
                      {'lan_ha_port_setting': {'mgmt_lan': '1.1.1.4',
                                               'ha_ip_address': '1.1.1.2'}},
                      {'lan_ha_port_setting': {'mgmt_lan': '1.1.1.5',
                                               'ha_ip_address': '1.1.1.3'}}],
                  'vip_setting': {'subnet_mask': '255.255.255.0',
                                  'gateway': '1.1.1.1',
                                  'address': '1.1.1.6'}
                  }),
             mock.call('NODE2_FLOATING_IP', 'admin', 'infoblox'),
             mock.call().join_grid('Infoblox', '1.1.1.6', 'test')
             ],
            self.my_ha_pair.node.mock_calls)

    def test_update_allowed_address_pairs(self):
        # Prepair member with update_allowed_address_pairs set to False
        (props, neutron, ports) = self.prepair_ha_pair(
            update_ports=False)
        # Call 'handle_create' method and check that fix_ha_ports not called
        with mock.patch('heat_infoblox.resources.grid_member.'
                        'resource_utils.fix_ha_ports_mac') as fix_ha_ports:
            self.my_ha_pair.handle_create()
            fix_ha_ports.assert_not_called()
