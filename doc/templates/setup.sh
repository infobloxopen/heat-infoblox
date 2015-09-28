#!/bin/bash

TENANT_NAME=${1:-nios}

if [[ "$OS_USERNAME" != "admin" ]]; then
  echo "Setup must be done as OpenStack admin."
  exit 1
fi

openstack project create $TENANT_NAME
openstack user create nios --project $TENANT_NAME --password infoblox
openstack role add --user nios --project $TENANT_NAME Member
openstack role add --user admin --project $TENANT_NAME Member

nova flavor-create --is-public true vnios810.55 auto 2048 55 2 --swap 0 --ephemeral 0
nova flavor-create --is-public true vnios820.160 auto 3584 160 2 --swap 0 --ephemeral 0

glance image-create --name nios-7.2.3-810-55.qcow2 --visibility public --container-format bare --disk-format qcow2 --file nios-7.2.0-vagrant-2015-09-22-10-43-2015-09-25-13-03-02_x86_64-55G-810-disk1.qcow2

glance image-create --name nios-7.2.3-820-160.qcow2 --visibility public --container-format bare --disk-format qcow2 --file nios-7.2.0-vagrant-2015-09-22-10-43-2015-09-25-13-15-28_x86_64-160G-820-disk1.qcow2

TENANT_ID=$(openstack project show $TENANT_NAME -f value -c id)
neutron net-create --tenant-id $TENANT_ID management-net
neutron net-create --tenant-id $TENANT_ID service-net

neutron subnet-create --name management management-net --tenant-id $TENANT_ID 10.1.0.0/24
neutron subnet-create --name service service-net --tenant-id $TENANT_ID 10.2.0.0/24

neutron router-create router --tenant-id $TENANT_ID
neutron router-gateway-set router public
neutron router-interface-add router service

SEC_GROUPS=$(neutron security-group-list -f value -c id -c name | cut -f 1 -d ' ')
for id in $SEC_GROUPS
do
#   echo "Checking for $TENANT_ID in $id"
   if neutron security-group-show $id | grep -q $TENANT_ID ; then
     neutron security-group-rule-create --direction ingress $id
   fi
done

