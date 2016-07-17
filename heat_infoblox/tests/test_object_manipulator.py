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


import copy
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

    def _test_create_anycast_loopback(self, ip, expected_anycast_dict,
                                      old_ip=None, ip_list=None):
        member_name = 'member_name'
        connector = mock.Mock()
        member = MEMBER_WITH_ANYCAST_IP.copy()
        if ip_list:
            member['additional_ip_list'] = ip_list
        connector.get_object.return_value = [member]

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.create_anycast_loopback(member_name, ip, enable_bgp=True,
                                   enable_ospf=True, old_ip=old_ip)

        connector.get_object.assert_called_once_with(
            'member', {'host_name': member_name},
            ['additional_ip_list'], extattrs=None)

        expected_ip_list = MEMBER_WITH_ANYCAST_IP['additional_ip_list'][:]
        if old_ip:
            for idx, val in enumerate(expected_ip_list):
                if ':' in old_ip:
                    if 'ipv6_network_setting' in val:
                        check_ip = val['ipv6_network_setting']['virtual_ip']
                    else:
                        continue
                else:
                    if 'ipv4_network_setting' in val:
                        check_ip = val['ipv4_network_setting']['address']
                    else:
                        continue
                if check_ip == old_ip:
                    expected_ip_list.pop(idx)
                    break
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
                                     {'virtual_ip': ip,
                                      'cidr_prefix': 128},
                                 'enable_bgp': True,
                                 'interface': 'LOOPBACK',
                                 'enable_ospf': True}
        self._test_create_anycast_loopback(ip, expected_anycast_dict)

    def test_create_anycast_loopback_old_ip_v4(self):
        ip = '172.23.25.26'
        old_ip = '172.252.5.2'
        ip_list = MEMBER_WITH_ANYCAST_IP['additional_ip_list'][:]
        ip_list.append(
            {
                'anycast': True,
                'ipv4_network_setting':
                    {'subnet_mask': '255.255.255.255',
                     'address': old_ip},
                'enable_bgp': True,
                'interface': 'LOOPBACK',
                'enable_ospf': True
            })
        expected_anycast_dict = {'anycast': True,
                                 'ipv4_network_setting':
                                     {'subnet_mask': '255.255.255.255',
                                      'address': ip},
                                 'enable_bgp': True,
                                 'interface': 'LOOPBACK',
                                 'enable_ospf': True}
        self._test_create_anycast_loopback(ip, expected_anycast_dict,
                                           old_ip=old_ip, ip_list=ip_list)

    def test_create_anycast_loopback_old_ip_v6(self):
        ip = 'fffe::5'
        old_ip = 'fffe::4'
        ip_list = MEMBER_WITH_ANYCAST_IP['additional_ip_list'][:]
        ip_list.append(
            {
                'anycast': True,
                'ipv6_network_setting':
                    {'subnet_mask': 128,
                     'virtual_ip': old_ip},
                'enable_bgp': True,
                'interface': 'LOOPBACK',
                'enable_ospf': True
            })
        expected_anycast_dict = {'anycast': True,
                                 'ipv6_network_setting':
                                     {'cidr_prefix': 128,
                                      'virtual_ip': ip},
                                 'enable_bgp': True,
                                 'interface': 'LOOPBACK',
                                 'enable_ospf': True}
        self._test_create_anycast_loopback(ip, expected_anycast_dict,
                                           old_ip=old_ip, ip_list=ip_list)

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

    def test__copy_fields_or_raise(self):
        fields = ['field-one', 'field-two']
        source = {'field-one': 1,
                  'field-two': 'text',
                  'non-copy': 12}
        dest = {}
        object_manipulator.InfobloxObjectManipulator._copy_fields_or_raise(
            source, dest, fields)
        self.assertEqual(2, len(dest))
        self.assertEqual(1, dest['field-one'])
        self.assertEqual('text', dest['field-two'])

    def test__copy_fields_or_raise_raises_value_error(self):
        fields = ['field-one']
        source = {'non-copy': 12}
        dest = {}
        objm = object_manipulator.InfobloxObjectManipulator
        self.assertRaises(ValueError,
                          objm._copy_fields_or_raise,
                          source,
                          dest,
                          fields)

    def _test_configuration_update(self, method_name, object_type, field,
                                   members, create_options, expected_options,
                                   **kwargs):
        member_name = 'my_member'

        connector = mock.Mock()
        connector.get_object.return_value = members
        om = object_manipulator.InfobloxObjectManipulator(connector)
        method_to_call = getattr(om, method_name)
        method_to_call(member_name, create_options)

        connector.get_object.assert_called_once_with(
            object_type, {'host_name': member_name},
            [field], extattrs=None)
        connector.update_object.assert_called_once_with(
            members[0]['_ref'], {field: expected_options})

    def _test_create_ospf(self, members, ospf_options, expected_options):
        self._test_configuration_update('create_ospf', 'member', 'ospf_list',
                                        members, ospf_options,
                                        expected_options)

    def test_create_ospf(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': []}]
        ospf_options = dict(advertise_interface_vlan=10,
                            area_id='1',
                            area_type='STANDARD',
                            authentication_key='12',
                            authentication_type='NONE',
                            interface='IP',
                            is_ipv4=True,
                            key_id=12,
                            auto_calc_cost_enabled=True)
        expected_option = ospf_options.copy()
        # Remove fields that are not used in current conditions
        del expected_option['authentication_key']
        del expected_option['key_id']
        self._test_create_ospf(members, ospf_options, [expected_option])

    def test_create_ospf_mesage_digest_and_ha(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': []}]
        ospf_options = dict(advertise_interface_vlan=10,
                            area_id='1',
                            area_type='STANDARD',
                            authentication_key='12',
                            authentication_type='MESSAGE_DIGEST',
                            interface='LAN_HA',
                            is_ipv4=True,
                            key_id=12,
                            cost=5,
                            auto_calc_cost_enabled=True)
        expected_option = ospf_options.copy()
        # Remove fields that are not used in current conditions
        del expected_option['advertise_interface_vlan']
        del expected_option['cost']
        self._test_create_ospf(members, ospf_options, [expected_option])

    def test_create_ospf_simple(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': []}]
        ospf_options = dict(advertise_interface_vlan=10,
                            area_id='1',
                            area_type='STANDARD',
                            authentication_key='12',
                            authentication_type='SIMPLE',
                            interface='LAN_HA',
                            is_ipv4=True,
                            key_id=12,
                            cost=5,
                            auto_calc_cost_enabled=False)
        expected_option = ospf_options.copy()
        # Remove fields that are not used in current conditions
        del expected_option['advertise_interface_vlan']
        del expected_option['key_id']
        self._test_create_ospf(members, ospf_options, [expected_option])

    def test_create_ospf_with_existent_settings(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': [{'area_id': '5',
                            'area_type': 'STANDARD',
                            'authentication_type': 'NONE',
                            'interface': 'IP',
                            'is_ipv4': 'true'}]}]
        ospf_options = dict(advertise_interface_vlan=10,
                            area_id='1',
                            area_type='STANDARD',
                            authentication_type='NONE',
                            interface='IP',
                            is_ipv4=True,
                            auto_calc_cost_enabled=True)

        expected_option = copy.deepcopy(members[0]['ospf_list'])
        expected_option.append(ospf_options)
        self._test_create_ospf(members, ospf_options, expected_option)

    def _test_delete_ospf(self, members, expected_options):
        area_id = '5'
        member_name = 'my_member'
        connector = mock.Mock()
        connector.get_object.return_value = members

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.delete_ospf(area_id, member_name)

        connector.get_object.assert_called_once_with(
            'member', {'host_name': 'my_member'},
            ['ospf_list'], extattrs=None)
        connector.update_object.assert_called_once_with(
            members[0]['_ref'], expected_options)

    def test_delete_ospf_single(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': [{'area_id': '5',
                            'area_type': 'STANDARD',
                            'authentication_type': 'NONE',
                            'interface': 'IP',
                            'is_ipv4': 'true'}]}]
        expected_options = {'ospf_list': []}
        self._test_delete_ospf(members, expected_options)

    def test_delete_ospf_multiple(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'ospf_list': [{'area_id': '5',
                            'area_type': 'STANDARD',
                            'authentication_type': 'NONE',
                            'interface': 'IP',
                            'is_ipv4': 'true'},
                           {'area_id': '2',
                            'area_type': 'STANDARD',
                            'authentication_type': 'NONE',
                            'interface': 'IP',
                            'is_ipv4': 'true'}]}]
        expected_options = {'ospf_list': [{'area_id': '2',
                                           'area_type': 'STANDARD',
                                           'authentication_type': 'NONE',
                                           'interface': 'IP',
                                           'is_ipv4': 'true'}]}
        self._test_delete_ospf(members, expected_options)

    def _test_bgp_as(self, members, bgp_options, expected_options, **kwargs):
        self._test_configuration_update('create_bgp_as', 'member', 'bgp_as',
                                        members, bgp_options, expected_options,
                                        **kwargs)

    def _test_bgp_neighbor(self, members, bgp_options, expected_options):
        self._test_configuration_update('create_bgp_neighbor', 'member',
                                        'bgp_as', members, bgp_options,
                                        expected_options)

    def test_create_bgp_as(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': []}]
        bgp_options = {'as': 2,
                       'holddown': 15,
                       'keepalive': 20,
                       'link_detect': True,
                       'authentication_mode': 'MD5',
                       'bgp_neighbor_pass': 'somepass',
                       'comment': 'comment',
                       'interface': 'LAN_HA',
                       'neighbor_ip': '192.168.1.10',
                       'remote_as': 20}
        expected_options = {'as': 2,
                            'holddown': 15,
                            'keepalive': 20,
                            'link_detect': True,
                            'neighbors': [
                                {'authentication_mode': 'MD5',
                                 'bgp_neighbor_pass': 'somepass',
                                 'comment': 'comment',
                                 'interface': 'LAN_HA',
                                 'neighbor_ip': '192.168.1.10',
                                 'remote_as': 20}]
                            }
        self._test_bgp_as(members, bgp_options, [expected_options])

    def test_update_bgp_as(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': True,
                         'neighbors': [
                             {'authentication_mode': 'MD5',
                              'bgp_neighbor_pass': 'somepass',
                              'comment': 'comment',
                              'interface': 'LAN_HA',
                              'neighbor_ip': '192.168.1.10',
                              'remote_as': 20}]
                         }
                        ]}]
        bgp_options = {'as': 10,
                       'holddown': 40,
                       'keepalive': 60,
                       'link_detect': False,
                       'authentication_mode': 'MD5',
                       'bgp_neighbor_pass': 'newpass',
                       'comment': 'new_comment',
                       'interface': 'LAN_HA',
                       'neighbor_ip': '192.168.1.25',
                       'remote_as': 30
                       }
        expected_options = {'as': 10,
                            'holddown': 40,
                            'keepalive': 60,
                            'link_detect': False,
                            'neighbors': [
                                {'authentication_mode': 'MD5',
                                 'bgp_neighbor_pass': 'newpass',
                                 'comment': 'new_comment',
                                 'interface': 'LAN_HA',
                                 'neighbor_ip': '192.168.1.25',
                                 'remote_as': 30}]
                            }
        self._test_bgp_as(members, bgp_options, [expected_options],
                          old_neighbor_ip='192.168.1.10')

    def test_delete_bgp_as(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': True}
                        ]}]
        member_name = 'my_member'
        expected_options = {'bgp_as': []}
        connector = mock.Mock()
        connector.get_object.return_value = members

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.delete_bgp_as(member_name)

        connector.get_object.assert_called_once_with(
            'member', {'host_name': 'my_member'},
            ['bgp_as'], extattrs=None)
        connector.update_object.assert_called_once_with(
            members[0]['_ref'], expected_options)

    def test_create_bgp_neighbor(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': True,
                         'neighbors': []}
                        ]}]
        bgp_options = {'authentication_mode': 'MD5',
                       'bgp_neighbor_pass': 'somepass',
                       'comment': 'comment',
                       'interface': 'LAN_HA',
                       'neighbor_ip': '192.168.1.10',
                       'remote_as': 20}
        expected_option = {'as': 2,
                           'holddown': 15,
                           'keepalive': 20,
                           'link_detect': True,
                           'neighbors': [{'authentication_mode': 'MD5',
                                          'bgp_neighbor_pass': 'somepass',
                                          'comment': 'comment',
                                          'interface': 'LAN_HA',
                                          'neighbor_ip': '192.168.1.10',
                                          'remote_as': 20,
                                          }]}
        self._test_bgp_neighbor(members, bgp_options, [expected_option])

    def test_create_bgp_neighbor_with_existent_neighbor(self):
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': False,
                         'neighbors': [{'authentication_mode': 'MD5',
                                        'bgp_neighbor_pass': 'somepass',
                                        'comment': 'comment',
                                        'interface': 'LAN_HA',
                                        'neighbor_ip': '192.168.1.15',
                                        'remote_as': 20,
                                        }]}
                        ]}]
        bgp_options = {'authentication_mode': 'MD5',
                       'bgp_neighbor_pass': 'new_pass',
                       'comment': 'comment2',
                       'interface': 'LAN_HA',
                       'neighbor_ip': '172.23.2.10',
                       'remote_as': 15}
        expected_option = {'as': 2,
                           'holddown': 15,
                           'keepalive': 20,
                           'link_detect': False,
                           'neighbors': [{'authentication_mode': 'MD5',
                                          'bgp_neighbor_pass': 'somepass',
                                          'comment': 'comment',
                                          'interface': 'LAN_HA',
                                          'neighbor_ip': '192.168.1.15',
                                          'remote_as': 20,
                                          },
                                         {'authentication_mode': 'MD5',
                                          'bgp_neighbor_pass': 'new_pass',
                                          'comment': 'comment2',
                                          'interface': 'LAN_HA',
                                          'neighbor_ip': '172.23.2.10',
                                          'remote_as': 15,
                                          }]}
        self._test_bgp_neighbor(members, bgp_options, [expected_option])

    def _test_delete_bgp(self, members, neighbor_ip, expected_options):
        member_name = 'my_member'
        connector = mock.Mock()
        connector.get_object.return_value = members

        om = object_manipulator.InfobloxObjectManipulator(connector)
        om.delete_bgp_neighbor(member_name, neighbor_ip)

        connector.get_object.assert_called_once_with(
            'member', {'host_name': 'my_member'},
            ['bgp_as'], extattrs=None)
        connector.update_object.assert_called_once_with(
            members[0]['_ref'], expected_options)

    def test_delete_bgp_single(self):
        neighbor_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': False,
                         'neighbors': [{'authentication_mode': 'MD5',
                                        'bgp_neighbor_pass': 'somepass',
                                        'comment': 'comment',
                                        'interface': 'LAN_HA',
                                        'neighbor_ip': neighbor_ip,
                                        'remote_as': 20,
                                        }]}]}]
        expected_options = {'bgp_as': [{'as': 2,
                                        'holddown': 15,
                                        'keepalive': 20,
                                        'link_detect': False,
                                        'neighbors': []}]}
        self._test_delete_bgp(members, neighbor_ip, expected_options)

    def test_delete_bgp_multiple(self):
        neighbor_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'bgp_as': [{'as': 2,
                         'holddown': 15,
                         'keepalive': 20,
                         'link_detect': False,
                         'neighbors': [{'authentication_mode': 'MD5',
                                        'bgp_neighbor_pass': 'somepass',
                                        'comment': 'comment',
                                        'interface': 'LAN_HA',
                                        'neighbor_ip': neighbor_ip,
                                        'remote_as': 20,
                                        },
                                       {'authentication_mode': 'MD5',
                                        'bgp_neighbor_pass': 'new_pass',
                                        'comment': 'comment2',
                                        'interface': 'LAN_HA',
                                        'neighbor_ip': '172.23.2.10',
                                        'remote_as': 15,
                                        }]}]}]
        expected_options = {'bgp_as': [{'as': 2,
                                        'holddown': 15,
                                        'keepalive': 20,
                                        'link_detect': False,
                                        'neighbors': [
                                            {'authentication_mode': 'MD5',
                                             'bgp_neighbor_pass': 'new_pass',
                                             'comment': 'comment2',
                                             'interface': 'LAN_HA',
                                             'neighbor_ip': '172.23.2.10',
                                             'remote_as': 15,
                                             }]}]}
        self._test_delete_bgp(members, neighbor_ip, expected_options)

    def _test_additional_ip_list(self, members, server_ip_list,
                                 expected_ip_list):
        self._test_configuration_update('add_member_dns_additional_ip',
                                        'member:dns', 'additional_ip_list',
                                        members, server_ip_list,
                                        expected_ip_list)

    def test_add_member_dns_additional_ip(self):
        anycast_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'additional_ip_list': []}]
        expected_options = [anycast_ip]
        self._test_additional_ip_list(members, anycast_ip, expected_options)

    def test_add_member_dns_additional_ip_existent_ips(self):
        anycast_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'additional_ip_list': ['172.23.23.13']}]
        expected_options = ['172.23.23.13', anycast_ip]
        self._test_additional_ip_list(members, anycast_ip, expected_options)

    def _test_remove_ip_list(self, members, server_ip_list,
                             expected_ip_list):
        self._test_configuration_update('remove_member_dns_additional_ip',
                                        'member:dns', 'additional_ip_list',
                                        members, server_ip_list,
                                        expected_ip_list)

    def test_remove_member_dns_additional_ip(self):
        anycast_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'additional_ip_list': [anycast_ip]}]
        expected_options = []
        self._test_remove_ip_list(members, anycast_ip, expected_options)

    def test_remove_member_dns_additional_ip_multiple_ips(self):
        anycast_ip = '192.168.1.15'
        members = [
            {'_ref': u'member/b35lLnZpcnR1YWxa3fskZSQw:master-113.ft-ac.com',
             'additional_ip_list': ['14.53.23.3', anycast_ip]}]
        expected_options = ['14.53.23.3']
        self._test_remove_ip_list(members, anycast_ip, expected_options)
