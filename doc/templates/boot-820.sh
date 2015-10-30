#!/bin/bash

TENANT_NAME=${1:-nios}

if [[ "$OS_USERNAME" != $TENANT_NAME ]]; then
  echo "OS_USERNAME should be set to $TENANT_NAME"
  exit 1
fi

MGMT_NET=$(neutron net-list -c id -c name -f csv | grep management | cut -f 1 -d ',' | tr -d \")
SERVICE_NET=$(neutron net-list -c id -c name -f csv | grep service | cut -f 1 -d ',' | tr -d \")
neutron port-create -c id -c fixed_ips service-net > /tmp/port.$$
SERVICE_IP=$(cat /tmp/port.$$ | grep fixed_ips | cut -f 2 -d, | cut -f 2 -d : | tr -d '"}| ')
SERVICE_PORT=$(cat /tmp/port.$$ |  grep ' id ' | cut -f 2 -d, | cut -f 3 -d \| | tr -d '"}| ')
SERVICE_SUBNET=$(cat /tmp/port.$$ | grep fixed_ips | cut -f 1 -d, | cut -f 2 -d : | tr -d '"}| ')
SERVICE_GW=$(neutron subnet-show -f value -c gateway_ip $SERVICE_SUBNET)

cat > /tmp/user_data.$$.yaml <<EOF
#infoblox-config

remote_console_enabled: true
default_admin_password: infoblox
temp_license: vnios,enterprise,cloud,dns,dhcp
lan1:
 v4_addr: $SERVICE_IP
 v4_netmask: 255.255.255.0
 v4_gw: $SERVICE_GW
gridmaster:
  certificate: -----BEGIN CERTIFICATE-----MIIDdzCCAl8CEE1KYfmypDvEmhBrmE1MBhYwDQYJKoZIhvcNAQEFBQAwejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5nMRkwFwYDVQQDExB3d3cuaW5mb2Jsb3guY29tMB4XDTE1MDkyNDE0MjY1M1oXDTE2MDkyMzE0MjY1M1owejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5nMRkwFwYDVQQDExB3d3cuaW5mb2Jsb3guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA51WBtEHxomjU+TlIAATeOXq1xT/CbNW1hENnspZufoW55bjKDXXMMBuhUeptzjzthDcaNZF2la1US1OyY98SkwX+8dFSENYQAvT4kyRmpIoxmMxSl0r3gPdTOWTbc2GSMd2OUx3AlR9/fvGu5Znevt8g+zkhE3SSsKi+pa0nTs7SsI7XZ7uRfdcJTRfry4fsTTZWE1X8NTmpZzbjzAWQXPAh12mWgUoCWZZpG+8YkidUI5J8TEBwNRxnNfyqF6D1DFDYJAqzEGFh0LxNqcJt4Ih1Rl+4fmPnuvhzyMMrOVqZk/pK1atBhNjeBCRfLn5EnYmgxD2nkoS+QKPe15BgPQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAHOLJzCzbxxI04Hq1nffbRlLNH0iWvzz2hwlgJ0jHl9PEbXVtTm+diF/D0ehd7Vw/icR9AVOhegVkoPcKxIBVoNFMhLRMjnqNsz/mI+UKF6SsEzOOSqtG3ljWDFrA9mHmy8UuhBfu0tYSn4jhCZB9B3LKfsS1Gd2HO7wdu1WfcYh+U2c3HifqWRAhg9OjA8qPt9206cKIxS4Wc/q4Z/RNZIPzDBb9zaWNJNiK6Cbgv3SyewTCFklK+lHrh8mAZu62NjDge/UgRPH2F3LH9pVgkYrK9kvK4vcs9bOPyP3ELxY9khMZlZS2avdsxvE+f0nhNbAbGpQ4x1w1FUsCWxvUN-----END CERTIFICATE-----
  token: testtesttesttesttesttest
  ip_addr: 10.2.0.6
EOF

# If a meta-data key named 'nios' exists, then this instance will be polled for QPS with ceilometer.
nova boot --meta 'nios=yes' --config-drive True --image nios-7.2.3-820-160.qcow2 --flavor vnios820.160 --nic net-id=$MGMT_NET --nic port-id=$SERVICE_PORT --user-data /tmp/user_data.$$.yaml nios-$$

