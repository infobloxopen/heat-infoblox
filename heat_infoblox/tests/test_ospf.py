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


my_template = {
    'heat_template_version': '2013-05-23',
    'resources': {
        'ospf': {
            'type': 'Infoblox::Grid::Ospf',
            'properties': {
                'advertise_interface_vlan': '',
                'area_id': '1',
                'area_type': 'STANDARD',
                'authentication_key': '',
                'authentication_type': 'NONE',
                'auto_calc_cost_enabled': True,
                'comment': '',
                'dead_interval': 5,
                'hello_interval': 10,
                'interface': 'LAN_HA',
                'is_ipv4': True,
                'key_id': 0,
                'retransmit_interval': 50,
                'transmit_delay': 5,
                'grid_members': ['member_name1', 'member_name2'],
            }
        }
    }
}


class OspfTest(common.HeatTestCase):
    def setUp(self):
        heat_infoblox_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir))
        cfg.CONF.import_opt('plugin_dirs', 'heat.common.config')
        cfg.CONF.set_override('plugin_dirs', heat_infoblox_path)
        super(OspfTest, self).setUp()

        self.ctx = utils.dummy_context()

    def set_stack(self, stack_template):
        self.stack = stack.Stack(
            self.ctx, 'my_template',
            template.Template(stack_template)
        )
        self.ospf = self.stack['ospf']
        self.ospf.infoblox_object = mock.Mock()

    def test_handle_create(self):
        self.set_stack(my_template)
        self.ospf.handle_create()
        opts = my_template['resources']['ospf']['properties'].copy()
        # set manually fields that are not present in input
        opts['cost'] = None
        calls = [mock.call('member_name1', opts),
                 mock.call('member_name2', opts)]
        self.ospf.infoblox_object.create_ospf.assert_has_calls(calls)

    def test_handle_delete(self):
        self.set_stack(my_template)
        self.ospf.handle_create()
        self.ospf.handle_delete()
        calls = [mock.call('1', 'member_name1'),
                 mock.call('1', 'member_name2')]
        self.ospf.infoblox_object.delete_ospf.assert_has_calls(calls)

    def test_create_delete_single_member(self):
        template = copy.deepcopy(my_template)
        prop = template['resources']['ospf']['properties']
        prop['grid_members'] = ['my_member1']
        self.set_stack(template)
        opts = prop.copy()
        opts['cost'] = None

        self.ospf.handle_create()
        self.ospf.infoblox_object.create_ospf.assert_called_with('my_member1',
                                                                 opts)
        self.ospf.handle_delete()
        self.ospf.infoblox_object.delete_ospf.assert_called_with('1',
                                                                 'my_member1')

    def test_handle_update(self):
        self.set_stack(my_template)
        self.ospf.handle_create()
        props = my_template['resources']['ospf']['properties'].copy()
        props['area_id'] = '2'
        props['grid_members'] = ['member_name2', 'member_name3']
        tmpl_diff = {'Properties': props}
        prop_diff = {'area_id': props['area_id'],
                     'grid_members': props['grid_members']}
        self.ospf.handle_update(None, tmpl_diff, prop_diff)
        self.ospf.infoblox_object.delete_ospf.assert_called_with(
            '1', 'member_name1')

        opts = my_template['resources']['ospf']['properties'].copy()
        opts['cost'] = None
        calls = [mock.call('member_name1', opts),
                 mock.call('member_name2', opts),
                 mock.call('member_name2', props, old_area_id='1'),
                 mock.call('member_name3', props, old_area_id='1')]
        self.ospf.infoblox_object.create_ospf.assert_has_calls(calls,
                                                               any_order=True)
