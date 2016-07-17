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


import gettext
import logging

from heat_infoblox import ibexceptions as exc
from heat_infoblox import resource_utils

_ = gettext.gettext

LOG = logging.getLogger(__name__)


class InfobloxObjectManipulator(object):
    FIELDS = ['ttl', 'use_ttl']

    def __init__(self, connector):
        self.connector = connector

    def get_member(self, member_name, return_fields=None, extattrs=None):
        obj = {'host_name': member_name}
        return self.connector.get_object(
            'member', obj, return_fields, extattrs
        )

    def create_member(self, name=None, platform='VNIOS',
                      config_addr_type='IPV4', vip=None, mgmt=None, lan2=None,
                      nat_ip=None,
                      ha_pair=False, use_v4_vrrp=True, vrid=None,
                      node1_ha=None, node2_ha=None,
                      node1_lan1=None, node2_lan1=None,
                      node2_mgmt=None, node2_lan2=None, lan2_vrid=None):
        member_data = {'host_name': name, 'platform': platform}
        extra_data = {}

        if ha_pair:
            # For HA pair we use IPv4 or IPv6 address, not both
            node1 = {}
            node2 = {}
            if config_addr_type == 'IPV6':
                ipv4 = False
            elif config_addr_type == 'BOTH':
                ipv4 = use_v4_vrrp
            else:  # default configuration is 'IPV4'
                ipv4 = True
            node1['ha_ip_address'] = resource_utils.get_ip_address(
                node1_ha, ipv4, 'node1_ha')
            node1['mgmt_lan'] = resource_utils.get_ip_address(
                node1_lan1, ipv4, 'node1_lan1')
            node2['ha_ip_address'] = resource_utils.get_ip_address(
                node2_ha, ipv4, 'node2_ha')
            node2['mgmt_lan'] = resource_utils.get_ip_address(
                node2_lan1, ipv4, 'node2_lan1')
            extra_data = {
                'enable_ha': True,
                'router_id': vrid,
                'node_info': [
                    {'lan_ha_port_setting': node1},
                    {'lan_ha_port_setting': node2}
                    ]
                }

        if config_addr_type in ('IPV4', 'BOTH'):
            # Check that IPv4 address available
            resource_utils.get_ip_address(vip, True, 'vip')
            # Copy IPv4 address settings
            extra_data['vip_setting'] = vip['ipv4'].copy()
        if config_addr_type in ('IPV6', 'BOTH'):
            # Check that IPv6 address available
            resource_utils.get_ip_address(vip, False, 'vip')
            # Copy IPv6 address settings
            extra_data['ipv6_setting'] = vip['ipv6'].copy()
        if nat_ip:
            extra_data['nat_setting'] = {
                'enabled': True,
                'external_virtual_ip': nat_ip
            }

        if mgmt:
            if config_addr_type in ('IPV4', 'BOTH'):
                # Check that MGMT IPv4 address available
                resource_utils.get_ip_address(mgmt, True, 'MGMT')
                extra_data['mgmt_port_setting'] = {"enabled": True}
                if ha_pair:
                    # Check that node2 MGMT IPv4 address available
                    resource_utils.get_ip_address(node2_mgmt, True,
                                                  'node2_MGMT')
                    extra_data['node_info'][0] = {
                        'mgmt_network_setting': mgmt['ipv4']}
                    extra_data['node_info'][1] = {
                        'mgmt_network_setting': node2_mgmt['ipv4']}
                else:
                    extra_data['node_info'] = [
                        {'mgmt_network_setting': mgmt['ipv4']}]
            if config_addr_type in ('IPV6', 'BOTH'):
                # Check that IPv6 address available
                resource_utils.get_ip_address(mgmt, False, 'MGMT')
                extra_data['v6_mgmt_network_setting'] = {"enabled": True}
                if ha_pair:
                    # Check that node2 MGMT IPv4 address available
                    resource_utils.get_ip_address(node2_mgmt, True,
                                                  'node2_MGMT')
                    extra_data['node_info'][0] = {
                        'v6_mgmt_network_setting': mgmt['ipv4']}
                    extra_data['node_info'][1] = {
                        'v6_mgmt_network_setting': node2_mgmt['ipv4']}
                else:
                    extra_data['node_info'] = [
                        {'v6_mgmt_network_setting': mgmt['ipv4']}]

        if lan2 and lan2.get('ipv4', None):
            extra_data['lan2_enabled'] = True
            extra_data['lan2_port_setting'] = {
                'enabled': True,
                'network_setting': lan2['ipv4']
            }
            if ha_pair:
                extra_data['virtual_router_id'] = lan2_vrid

        return self._create_infoblox_object('member', member_data, extra_data)

    def pre_provision_member(self, member_name,
                             hwmodel=None, hwtype='IB-VNIOS',
                             licenses=None, ha_pair=False):
        if licenses is None:
            licenses = []
        if not isinstance(licenses, list):
            licenses = [licenses]
        hw_info = {'hwmodel': hwmodel, 'hwtype': hwtype}
        extra_data = {'pre_provisioning': {
            'hardware_info': [hw_info, hw_info] if ha_pair else [hw_info],
            'licenses': licenses}
        }
        self._update_infoblox_object('member', {'host_name': member_name},
                                     extra_data)

    def configure_member_dns(self, member_name,
                             enable_dns=False):
        extra_data = {'enable_dns': enable_dns}
        self._update_infoblox_object('member:dns', {'host_name': member_name},
                                     extra_data)

    def delete_member(self, member_name):
        member_data = {'host_name': member_name}
        self._delete_infoblox_object('member', member_data)

    def add_member_dns_additional_ip(self, member_name, ip):
        return_fields = ['additional_ip_list']
        member_dns = self.get_member_obj(member_name, return_fields,
                                         fail_if_no_member=True,
                                         object_type='member:dns')
        additional_ips = member_dns.get('additional_ip_list') or []
        additional_ips.append(ip)
        payload = {'additional_ip_list': additional_ips}
        self._update_infoblox_object_by_ref(member_dns['_ref'], payload)

    def remove_member_dns_additional_ip(self, member_name, ip):
        return_fields = ['additional_ip_list']
        member_dns = self.get_member_obj(member_name, return_fields,
                                         object_type='member:dns')
        if not member_dns or not member_dns.get('additional_ip_list'):
            return
        updated_ips = [orig_ip for orig_ip in member_dns['additional_ip_list']
                       if orig_ip != str(ip)]
        payload = {'additional_ip_list': updated_ips}
        self._update_infoblox_object_by_ref(member_dns['_ref'], payload)

    def update_member(self, member_name, update_data):
        self._update_infoblox_object('member', {'host_name': member_name},
                                     update_data)

    def join_grid(self, grid_name, master_ip, shared_secret):
        gm_params = {'grid_name': grid_name, 'master': master_ip,
                     'shared_secret': shared_secret}
        self.connector.call_func('join', 'grid', gm_params)

    def create_anycast_loopback(self, member_name, ip, enable_bgp=False,
                                enable_ospf=False, old_ip=None):
        anycast_loopback = {
            'anycast': True,
            'enable_bgp': enable_bgp,
            'enable_ospf': enable_ospf,
            'interface': 'LOOPBACK'}
        if ':' in ip:
            anycast_loopback['ipv6_network_setting'] = {
                'virtual_ip': ip,
                'cidr_prefix': 128}
        else:
            anycast_loopback['ipv4_network_setting'] = {
                'address': ip,
                'subnet_mask': '255.255.255.255'}

        member = self._get_infoblox_object_or_none(
            'member', {'host_name': member_name},
            return_fields=['additional_ip_list'])

        # Should we raise some exception here or just log object not found?
        if not member:
            LOG.error(_("Grid Member %(name)s is not found, can not assign "
                        "Anycast Loopback ip %(ip)s"),
                      {'name': member_name, 'ip': ip})
            return

        additional_ip_list = []
        if member and 'additional_ip_list' in member:
            if old_ip is not None:
                if ':' in old_ip:
                    net = 'ipv6_network_setting'
                    ip_field = 'virtual_ip'
                else:
                    net = 'ipv4_network_setting'
                    ip_field = 'address'
                for add_ip in member['additional_ip_list']:
                    if net in add_ip and add_ip[net][ip_field] == old_ip:
                        continue  # skip old settings
                    additional_ip_list.append(add_ip)
            else:
                additional_ip_list = member['additional_ip_list'][:]

        additional_ip_list.append(anycast_loopback)

        payload = {'additional_ip_list': additional_ip_list}
        self._update_infoblox_object_by_ref(member['_ref'], payload)

    def delete_anycast_loopback(self, ip, member_name=None):
        """Delete anycast loopback ip address.

        :param ip: anycast ip address to delete from loopback interface
        :param member_name: name of grid member on which anycast ip should
                            be deleted. If member name is None, then anycast
                            address is deleted from each member where found.
        """
        members_for_update = []
        if member_name:
            member = self._get_infoblox_object_or_none(
                'member', {'host_name': member_name},
                return_fields=['additional_ip_list'])
            if member and member['additional_ip_list']:
                members_for_update.append(member)
        else:
            members_for_update = self.connector.get_object(
                'member', return_fields=['additional_ip_list'])

        for member in members_for_update:
            # update members only if address to remove is found
            update_this_member = False
            new_ip_list = []
            for iface in member['additional_ip_list']:
                ipv4 = iface.get('ipv4_network_setting')
                if ipv4 and ip in ipv4['address']:
                    update_this_member = True
                    continue
                ipv6 = iface.get('ipv6_network_setting')
                if ipv6 and ip in ipv6['virtual_ip']:
                    update_this_member = True
                    continue
                new_ip_list.append(iface)
            if update_this_member:
                payload = {'additional_ip_list': new_ip_list}
                self._update_infoblox_object_by_ref(member['_ref'], payload)

    def get_all_ns_groups(self, return_fields=None, extattrs=None):
        obj = {}
        return self.connector.get_object(
            'nsgroup', obj, return_fields, extattrs
        )

    def get_ns_group(self, group_name, return_fields=None, extattrs=None):
        obj = {'name': group_name}
        return self.connector.get_object(
            'nsgroup', obj, return_fields, extattrs
        )

    def update_ns_group(self, group_name, group):
        self._update_infoblox_object('nsgroup', {'name': group_name},
                                     group)

    @staticmethod
    def _copy_fields_or_raise(source_dict, dest_dict, fields):
        for field in fields:
            if field not in source_dict:
                raise ValueError(_("Field '{}' is required").format(field))
            else:
                dest_dict[field] = source_dict[field]

    def create_ospf(self, member_name, ospf_options_dict, old_area_id=None):
        """Add ospf settings to the grid member.

        If old_area_id is passed ospf settings are updated instead of creation
        """
        required_fields = ('area_id', 'area_type', 'auto_calc_cost_enabled',
                           'authentication_type', 'is_ipv4', 'interface')
        optional_fields = ('comment', 'dead_interval', 'hello_interval',
                           'interface', 'retransmit_interval',
                           'transmit_delay')
        opts = {}
        self._copy_fields_or_raise(ospf_options_dict, opts, required_fields)

        conditional_fields = []
        # Process fields that become required depending on another field value
        if opts['auto_calc_cost_enabled'] is False:
            conditional_fields.append('cost')
        if opts['interface'] == 'IP':
            conditional_fields.append('advertise_interface_vlan')

        if opts['authentication_type'] == 'MESSAGE_DIGEST':
            conditional_fields.extend(['authentication_key', 'key_id'])
        elif opts['authentication_type'] == 'SIMPLE':
            conditional_fields.append('authentication_key')
        self._copy_fields_or_raise(ospf_options_dict, opts, conditional_fields)

        # Copy optional fields if value is set
        for field in optional_fields:
            if ospf_options_dict.get(field):
                opts[field] = ospf_options_dict[field]

        member = self._get_infoblox_object_or_none(
            'member', {'host_name': member_name},
            return_fields=['ospf_list'])

        if not member:
            LOG.error(_("Grid Member %(name)s is not found"),
                      {'name': member_name})
            return
        # Remove old area_id in case of update
        ospf_list = [ospf for ospf in member['ospf_list']
                     if (old_area_id is None or
                         str(old_area_id) != ospf.get('area_id'))]
        ospf_list.append(opts)
        payload = {'ospf_list': ospf_list}
        self._update_infoblox_object_by_ref(member['_ref'], payload)

    def delete_ospf(self, area_id, member_name):
        """Delete ospf setting for particular area_id from the grid member."""
        member = self._get_infoblox_object_or_none(
            'member', {'host_name': member_name},
            return_fields=['ospf_list'])
        if member and member['ospf_list']:
            # update member only if area_id match
            update_this_member = False
            new_ospf_list = []
            for ospf_settings in member['ospf_list']:
                if str(area_id) == ospf_settings.get('area_id'):
                    update_this_member = True
                    continue
                new_ospf_list.append(ospf_settings)
            if update_this_member:
                payload = {'ospf_list': new_ospf_list}
                self._update_infoblox_object_by_ref(member['_ref'], payload)

    def get_member_obj(self, member_name, return_fields,
                       fail_if_no_member=False, object_type='member'):
        member = self._get_infoblox_object_or_none(
            object_type, {'host_name': member_name},
            return_fields=return_fields)
        if fail_if_no_member and not member:
            raise exc.InfobloxGridMemberNotFound(name=member_name)
        return member

    def create_bgp_as(self, member_name, bgp_opts, old_neighbor_ip=None):
        """Configure BGP AS on grid member.

        Creates or updates BGP Autonomous System configuration on grid member.
        Additionally configures one BGP Neighbor. Adding BGP AS configuration
        requires at least one Neighbor to be configured on member.
        """
        bgp_fields = ('as', 'holddown', 'keepalive', 'link_detect')
        neighbor_fields = ('authentication_mode', 'bgp_neighbor_pass',
                           'comment', 'interface', 'neighbor_ip', 'remote_as')

        member = self.get_member_obj(member_name, ['bgp_as'],
                                     fail_if_no_member=True)
        bgp_as_from_member = member.get('bgp_as') or []
        bgp_as = {field: bgp_opts[field] for field in bgp_fields
                  if bgp_opts.get(field) is not None}
        new_neighbor = {field: bgp_opts[field]
                        for field in neighbor_fields
                        if bgp_opts.get(field) is not None}

        # If old_neighbor_ip is defined then we are doing update.
        # Original neighbors are preserved, but old_neighbor_ip has to be
        # removed from this list, since this neighbor is regenerated as
        # new_neighbor.
        neighbors = []
        if old_neighbor_ip and bgp_as_from_member:
            neighbors = [neighbor
                         for neighbor in bgp_as_from_member[0]['neighbors']
                         if str(old_neighbor_ip) != neighbor['neighbor_ip']]
        neighbors.append(new_neighbor)

        if len(bgp_as_from_member) > 0:
            bgp_as_from_member[0].update(bgp_as)
        else:
            bgp_as_from_member.append(bgp_as)
        bgp_as_from_member[0]['neighbors'] = neighbors

        payload = {'bgp_as': bgp_as_from_member}
        self._update_infoblox_object_by_ref(member['_ref'], payload)

    def delete_bgp_as(self, member_name):
        """Delete BGP AS from grid member."""
        member = self.get_member_obj(member_name, ['bgp_as'])

        if member:
            payload = {'bgp_as': []}
            self._update_infoblox_object_by_ref(member['_ref'], payload)

    def create_bgp_neighbor(self, member_name, bgp_neighbor_opts,
                            old_neighbor_ip=None):
        """Configure BGP neighbor on grid member.

        Adds new BGP neighbor to existent BGP neighbor list. Updates neighbor
        if 'old_neighbor_ip' is specified.
        """
        neighbor_fields = ('authentication_mode', 'bgp_neighbor_pass',
                           'comment', 'interface', 'neighbor_ip', 'remote_as')

        member = self.get_member_obj(member_name, ['bgp_as'],
                                     fail_if_no_member=True)

        bgp_as_from_member = member.get('bgp_as')
        if not bgp_as_from_member:
            raise exc.InfobloxBgpAsNotConfigured(name=member_name)

        new_neighbor = {field: bgp_neighbor_opts[field]
                        for field in neighbor_fields
                        if bgp_neighbor_opts.get(field) is not None}

        # Remove old neighbor from neighbors list in case of update
        neighbors = [neighbor
                     for neighbor in bgp_as_from_member[0]['neighbors']
                     if (old_neighbor_ip is None or
                         str(old_neighbor_ip) != neighbor['neighbor_ip'])]
        neighbors.append(new_neighbor)

        bgp_as_from_member[0]['neighbors'] = neighbors
        payload = {'bgp_as': bgp_as_from_member}
        self._update_infoblox_object_by_ref(member['_ref'], payload)

    def delete_bgp_neighbor(self, member_name, neighbor_ip):
        """Delete BGP neighbor from grid member."""
        member = self.get_member_obj(member_name, ['bgp_as'])

        if member and member['bgp_as']:
            neighbors = []
            update_member = False
            for neighbor in member['bgp_as'][0]['neighbors']:
                if str(neighbor_ip) == neighbor['neighbor_ip']:
                    update_member = True
                else:
                    neighbors.append(neighbor)
            if update_member:
                member['bgp_as'][0]['neighbors'] = neighbors
                payload = {'bgp_as': member['bgp_as']}
                self._update_infoblox_object_by_ref(member['_ref'], payload)

    def create_dns_view(self, net_view_name, dns_view_name):
        dns_view_data = {'name': dns_view_name,
                         'network_view': net_view_name}
        return self._create_infoblox_object('view', dns_view_data)

    def delete_dns_view(self, net_view_name):
        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('view', net_view_data)

    def create_network_view(self, net_view_name, tenant_id):
        net_view_data = {'name': net_view_name}
        extattrs = {'extattrs': {'TenantID': {'value': tenant_id}}}
        return self._create_infoblox_object('networkview',
                                            net_view_data, extattrs)

    def delete_network_view(self, net_view_name):
        if net_view_name == 'default':
            # never delete default network view
            return

        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('networkview', net_view_data)

    def create_tsig(self, name, algorithm, secret):
        tsig = {
            'name': name,
            'key': secret
        }
        self._create_infoblox_object(
            'tsig', tsig,
            check_if_exists=True)

    def delete_tsig(self, name, algorithm, secret):
        tsig = {
            'name': name,
            'key': secret
        }
        self._delete_infoblox_object(
            'tsig', tsig,
            check_if_exists=True)

    def create_multi_tenant_dns_view(self, net_view, tenant):
        if not net_view:
            net_view = "%s.%s" % (self.connector.network_view, tenant)
        dns_view = "%s.%s" % (self.connector.dns_view, net_view)

        try:
            self.create_network_view(
                net_view_name=net_view,
                tenant_id=tenant)

            self.create_dns_view(
                net_view_name=net_view,
                dns_view_name=dns_view)
        except exc.InfobloxException as e:
            LOG.warning(_("Issue happens during views creating: %s"), e)

        LOG.debug("net_view: %s, dns_view: %s" % (net_view, dns_view))
        return dns_view

    def get_dns_view(self, tenant):
        if not self.connector.multi_tenant:
            return self.connector.dns_view
        else:
            # Look for the network view with the specified TenantID EA
            net_view = self._get_infoblox_object_or_none(
                'networkview',
                return_fields=['name'],
                extattrs={'TenantID': {'value': tenant}})
            if net_view:
                net_view = net_view['name']

            return self.create_multi_tenant_dns_view(net_view, tenant)

    def create_zone_auth(self, fqdn, dns_view):
        try:
            self._create_infoblox_object(
                'zone_auth',
                {'fqdn': fqdn, 'view': dns_view},
                {'ns_group': self.connector.ns_group,
                 'restart_if_needed': True},
                check_if_exists=True)
        except exc.InfobloxCannotCreateObject as e:
            LOG.warning(e)

    def delete_zone_auth(self, fqdn):
        self._delete_infoblox_object(
            'zone_auth', {'fqdn': fqdn})

    def _create_infoblox_object(self, obj_type, payload,
                                additional_create_kwargs=None,
                                check_if_exists=True,
                                return_fields=None):
        if additional_create_kwargs is None:
            additional_create_kwargs = {}

        ib_object = None
        if check_if_exists:
            ib_object = self._get_infoblox_object_or_none(obj_type, payload)
            if ib_object:
                LOG.info(_(
                    "Infoblox %(obj_type)s already exists: %(ib_object)s"),
                    {'obj_type': obj_type, 'ib_object': ib_object})

        if not ib_object:
            payload.update(additional_create_kwargs)
            ib_object = self.connector.create_object(obj_type, payload,
                                                     return_fields)
            LOG.info(_("Infoblox %(obj_type)s was created: %(ib_object)s"),
                     {'obj_type': obj_type, 'ib_object': ib_object})

        return ib_object

    def _get_infoblox_object_or_none(self, obj_type, payload=None,
                                     return_fields=None, extattrs=None):
        ib_object = self.connector.get_object(obj_type, payload, return_fields,
                                              extattrs=extattrs)
        if ib_object:
            if return_fields:
                return ib_object[0]
            else:
                return ib_object[0]['_ref']

        return None

    def _update_infoblox_object(self, obj_type, payload, update_kwargs):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be updated because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg % {'obj_type': obj_type,
                                        'payload': payload})
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, {'obj_type': obj_type, 'payload': payload})
            LOG.info(e)

        if ib_object_ref:
            self._update_infoblox_object_by_ref(ib_object_ref, update_kwargs)

    def _update_infoblox_object_by_ref(self, ref, update_kwargs):
        self.connector.update_object(ref, update_kwargs)
        LOG.info(_('Infoblox object was updated: %s'), ref)

    def _delete_infoblox_object(self, obj_type, payload):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be deleted because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg, obj_type, payload)
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, {'obj_type': obj_type, 'payload': payload})
            LOG.info(e)

        if ib_object_ref:
            self.connector.delete_object(ib_object_ref)
            LOG.info(_('Infoblox object was deleted: %s'), ib_object_ref)
