#!/bin/bash

TENANT_NAME=${1:-nios}

if [[ "$OS_USERNAME" != "admin" ]]; then
  echo "Setup must be done as OpenStack admin."
  exit 1
fi

openstack project create $TENANT_NAME
openstack user create nios --project $TENANT_NAME --password infoblox
openstack role add --user admin --project $TENANT_NAME Member
openstack role add --user nios --project $TENANT_NAME Member
openstack role add --user nios --project $TENANT_NAME heat_stack_owner

nova flavor-create --is-public true vnios810.55 auto 2048 55 2 --swap 0 --ephemeral 0
nova flavor-create --is-public true vnios820.160 auto 3584 160 2 --swap 0 --ephemeral 0

glance image-create --name nios-7.2.3-810-55.qcow2 --is-public true --container-format bare --disk-format qcow2 --file nios-7.2.0-vagrant-2015-09-22-10-43-2015-09-25-13-03-02_x86_64-55G-810-disk1.qcow2

glance image-create --name nios-7.2.3-820-160.qcow2 --is-public true --container-format bare --disk-format qcow2 --file nios-7.2.0-vagrant-2015-09-22-10-43-2015-09-25-13-15-28_x86_64-160G-820-disk1.qcow2

TENANT_ID=$(openstack project show $TENANT_NAME -f value -c id)
neutron net-create --tenant-id $TENANT_ID management-net
neutron net-create --tenant-id $TENANT_ID service-net
neutron net-create --tenant-id $TENANT_ID service-2-net
neutron net-create --tenant-id $TENANT_ID ha-net

cat <<EOF
The rest of this stuff doesn't work in Juno, you should switch to the nios user
and do it all manually:

neutron subnet-create --name management management-net 10.1.0.0/24
neutron subnet-create --name service service-net 10.2.0.0/24
neutron subnet-create --name service-2 service-2-net 10.3.0.0/24
neutron subnet-create --name ha ha-net 10.4.0.0/24

neutron router-create router
neutron router-gateway-set router public
neutron router-interface-add router service
neutron router-interface-add router management
neutron router-interface-add router service-2

neutron security-group-rule-create --direction ingress default


EOF

