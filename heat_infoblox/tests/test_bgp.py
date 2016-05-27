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


my_template = {
    'heat_template_version': '2013-05-23',
    'resources': {
        'bgp': {
            'type': 'Infoblox::Grid::Bgp',
            'properties': {
                'grid_member': 'member_name1',
                'as': 20,
                'holddown': 50,
                'keepalive': 5,
                'link_detect': True,
                'authentication_mode': 'MD5',
                'bgp_neighbor_pass': 'password',
                'comment': 'some comment',
                'interface': 'LAN_HA',
                'neighbor_ip': '192.168.165.25',
                'remote_as': 100,
            }
        }
    }
}


class BgpTest(common.HeatTestCase):
    def setUp(self):
        heat_infoblox_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir))
        cfg.CONF.import_opt('plugin_dirs', 'heat.common.config')
        cfg.CONF.import_opt('lock_path', 'oslo_concurrency.lockutils',
                            group='oslo_concurrency')
        cfg.CONF.set_override('plugin_dirs', heat_infoblox_path)
        cfg.CONF.set_override('lock_path', '/tmp/', group='oslo_concurrency')
        super(BgpTest, self).setUp()

        self.ctx = utils.dummy_context()

    def set_stack(self, stack_template):
        self.stack = stack.Stack(
            self.ctx, 'my_template',
            template.Template(stack_template)
        )
        self.bgp = self.stack['bgp']
        self.bgp.infoblox_object = mock.Mock()

    def test_handle_create(self):
        self.set_stack(my_template)
        self.bgp.handle_create()
        opts = my_template['resources']['bgp']['properties'].copy()
        self.bgp.infoblox_object.create_bgp_as.assert_called_with(
            'member_name1', opts)

    def test_handle_delete(self):
        self.set_stack(my_template)
        self.bgp.handle_create()
        self.bgp.handle_delete()
        self.bgp.infoblox_object.delete_bgp_as.assert_called_with(
            'member_name1')

    def test_handle_update(self):
        self.set_stack(my_template)
        self.bgp.handle_create()
        props = my_template['resources']['bgp']['properties'].copy()
        props['neighbor_ip'] = '172.23.10.15'
        props['comment'] = 'new comment'
        tmpl_diff = {'Properties': props}
        prop_diff = {'neighbor_ip': props['neighbor_ip'],
                     'comment': props['comment']}
        self.bgp.handle_update(None, tmpl_diff, prop_diff)
        self.bgp.infoblox_object.create_bgp_as.assert_called_with(
            'member_name1', props, old_neighbor_ip='192.168.165.25')
