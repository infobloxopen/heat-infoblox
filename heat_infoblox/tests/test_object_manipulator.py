# Copyright 2016 Infoblox Inc.
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
import testtools

from heat_infoblox import object_manipulator

MEMBER_WITH_ANYCAST_IP = {
    '_ref': u'member/b25lLnZpcnR1YWxfbm9kZSQw:master-113.ft-ac.com',
    'additional_ip_list': [{
        'anycast': True,
        'enable_bgp': False,
        'enable_ospf': False,
        'interface': u'LOOPBACK',
        'ipv4_network_setting': {
            'address': u'172.252.5.2',
            'dscp': 0,
            'primary': False,
            'subnet_mask': u'255.255.255.255',
            'use_dscp': False}}]}


class TestObjectManipulator(testtools.TestCase):

    def _test_create_anycast_loopback(self, ip, expected_anycast_dict):
        member_name = 'member_name'
        connector = mock.Mock()
        connector.get_object.return_value = [MEMBER_WITH_ANYCAST_IP]

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.create_anycast_loopback(member_name, ip, enable_bgp=True,
                                   enable_ospf=True)

        connector.get_object.assert_called_once_with(
            'member', {'host_name': member_name},
            ['additional_ip_list'], extattrs=None)

        expected_ip_list = MEMBER_WITH_ANYCAST_IP['additional_ip_list'][:]
        expected_ip_list.append(expected_anycast_dict)
        connector.update_object.assert_called_once_with(
            MEMBER_WITH_ANYCAST_IP['_ref'],
            {'additional_ip_list': expected_ip_list})

    def test_create_anycast_loopback_v4(self):
        ip = '172.23.25.25'
        expected_anycast_dict = {'anycast': True,
                                 'ipv4_network_setting':
                                     {'subnet_mask': '255.255.255.255',
                                      'address': ip},
                                 'enable_bgp': True,
                                 'interface': 'LOOPBACK',
                                 'enable_ospf': True}
        self._test_create_anycast_loopback(ip, expected_anycast_dict)

    def test_create_anycast_loopback_v6(self):
        ip = 'fffe::5'
        expected_anycast_dict = {'anycast': True,
                                 'ipv6_network_setting':
                                     {'virtual_ip': ip},
                                 'enable_bgp': True,
                                 'interface': 'LOOPBACK',
                                 'enable_ospf': True}
        self._test_create_anycast_loopback(ip, expected_anycast_dict)

    def _test_delete_anycast_loopback(self, ip, members, expected_calls):
        connector = mock.Mock()
        connector.get_object.return_value = members

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.delete_anycast_loopback(ip)

        connector.get_object.assert_called_once_with(
            'member', return_fields=['additional_ip_list'])
        connector.update_object.assert_has_calls(expected_calls)

    def test_delete_anycast_loopback_single_anycast(self):
        ip = '172.23.25.25'
        members = [
            {'_ref': u'member/a25lL2ecnR1YWxfbm9kZSQw:master-113.ft-ac.com',
             'additional_ip_list': [{'anycast': True,
                                     'ipv4_network_setting':
                                         {'subnet_mask': '255.255.255.255',
                                          'address': ip},
                                     'enable_bgp': True,
                                     'interface': 'LOOPBACK',
                                     'enable_ospf': True}]},
            {'_ref': u'member/cnR1YWxf:master-host.infoblox.com',
             'additional_ip_list': [{'anycast': True,
                                     'ipv4_network_setting':
                                         {'subnet_mask': '255.255.255.255',
                                          'address': ip},
                                     'enable_bgp': True,
                                     'interface': 'LOOPBACK',
                                     'enable_ospf': True}]},
            MEMBER_WITH_ANYCAST_IP]
        # update should be called only for the first two members,
        # where anycast ip matches
        expected_calls = [
            mock.call(members[0]['_ref'], {'additional_ip_list': []}),
            mock.call(members[1]['_ref'], {'additional_ip_list': []})]
        self._test_delete_anycast_loopback(ip, members, expected_calls)

    def test_delete_anycast_loopback_multiple_anycast(self):
        ip = '172.23.25.25'
        members = [
            {'_ref': u'member/a25lLnZpcnR1YWxfbm9kZSQw:master-113.ft-ac.com',
             'additional_ip_list': [
                 {'anycast': True,
                  'ipv4_network_setting':
                      {'subnet_mask': '255.255.255.255',
                       'address': ip},
                  'enable_bgp': True,
                  'interface': 'LOOPBACK',
                  'enable_ospf': True},
                 MEMBER_WITH_ANYCAST_IP['additional_ip_list'][0]]},
            {'_ref': u'member/cnR1YWxf:master-host.infoblox.com',
             'additional_ip_list': [{'anycast': True,
                                     'ipv4_network_setting':
                                         {'subnet_mask': '255.255.255.255',
                                          'address': ip},
                                     'enable_bgp': True,
                                     'interface': 'LOOPBACK',
                                     'enable_ospf': True}]}]
        expected_calls = [
            mock.call(members[0]['_ref'],
                      {'additional_ip_list':
                          MEMBER_WITH_ANYCAST_IP['additional_ip_list']}),
            mock.call(members[1]['_ref'], {'additional_ip_list': []})]
        self._test_delete_anycast_loopback(ip, members, expected_calls)
