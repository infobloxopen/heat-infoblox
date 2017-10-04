# Openstack Autoscale NIOS instances

# Upload image to Openstack server
openstack image create  --disk-format raw --public --file nios-8.2.0-358074-2017-07-05-15-01-39-ddi.qcow2  MAIN_358074

# If there are already create stacks that cannot be re-used, please remove them
openstack stack list
openstack stack remove <Stack Name>

# Create GM stack ( Change image name )
openstack stack create -f yaml -t gm_flex.yaml --parameter "imageName=MAIN_358074" FlexGM

# Configure GM ( Cert download, service configs, environment file creation ) Change GM floating IP
sh config-gm.sh <UI IP of Master>

# Create autoscale stack ( Change environment file name )
openstack stack create  -e gm-<UI IP>env.yaml -f yaml -t autoscale.yaml autoscale

# Send DNS load for Alarm trigger

# Tracking
watch ceilometer alarm-list
watch ceilometer sample-list -m nios.dns.qps
watch openstack server list 

