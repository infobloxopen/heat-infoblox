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
from heat_infoblox.resources import nameserver_group_member


my_template = {
    'heat_template_version': '2013-05-23',
    'resources': {
        'ns_group_member': {
            'type': 'Infoblox::Grid::NameServerGroupMember',
            'properties': {
                'group_name': 'foo',
                'member_server': {'name': 'my-member'},
                'member_role': 'grid_secondary'
            }
        }
    }
}


class NameServerGroupMemberTest(common.HeatTestCase):
    def setUp(self):
        heat_infoblox_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir))
        cfg.CONF.import_opt('plugin_dirs', 'heat.common.config')
        cfg.CONF.import_opt('lock_path', 'oslo_concurrency.lockutils',
                            group='oslo_concurrency')
        cfg.CONF.set_override('plugin_dirs', heat_infoblox_path)
        cfg.CONF.set_override('lock_path', '/tmp/', group='oslo_concurrency')
        super(NameServerGroupMemberTest, self).setUp()

        self.ctx = utils.dummy_context()

        self.base_group = {
            'name': 'foo',
            'grid_primary': [{'name': 'my-primary'}],
            'grid_secondaries': [],
        }

        group = self.base_group.copy()
        group['grid_secondaries'] = [
            {'name': 'my-member', 'grid_replicate': True, 'lead': False}
        ]
        self.added_group = group

        self.set_stack(my_template)

    def set_stack(self, stack_template):
        self.stack = stack.Stack(
            self.ctx, 'my_template',
            template.Template(stack_template)
        )
        self.ns_group_member = self.stack['ns_group_member']
        ibobj = mock.MagicMock()
        self.ns_group_member.infoblox_object = ibobj
        self.set_group(self.base_group)

    def set_group(self, group):
        ibobj = self.ns_group_member.infoblox_object
        ibobj.get_ns_group.return_value = [group]

    def test_resource_mapping(self):
        mapping = nameserver_group_member.resource_mapping()
        self.assertEqual(1, len(mapping))
        self.assertEqual(nameserver_group_member.NameServerGroupMember,
                         mapping['Infoblox::Grid::NameServerGroupMember'])

    def test_handle_create(self):
        self.ns_group_member.handle_create()
        ibobj = self.ns_group_member.infoblox_object
        ibobj.update_ns_group.assert_called_with('foo', self.added_group)
        self.assertEqual('foo/grid_secondary/my-member',
                         self.ns_group_member.resource_id)

    def test_handle_delete(self):
        self.set_group(self.added_group)
        self.ns_group_member.resource_id = 'foo/grid_secondary/my-member'
        self.ns_group_member.handle_delete()
        ibobj = self.ns_group_member.infoblox_object
        ibobj.update_ns_group.assert_called_with('foo', self.base_group)
