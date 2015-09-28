===============================
heat-infoblox
===============================

OpenStack Heat resources for orchestrating Infoblox appliances.

Enabling In DevStack
--------------------

To enable use of Infoblox Heat resources in DevStack, add this repository as a
plugin:

     enable_plugin heat-infoblox https://github.com/infobloxopen/heat-infoblox.git
     enable_service heat-infoblox


Features
--------

* Provides Infoblox::Grid::Member and Infoblox::Grid::NameServerGroupMember
resources.

OpenStack Configuration
-----------------------

After installation of the package, you must configure the connection
parameters for the WAPI.

In the ``heat.conf`` you must create an ``[infoblox]`` stanza with the
following parameters.

*wapi_url* - the URL used to reach the WAPI. Minimum version supported is
2.2.1. Example: ``https://172.16.98.66/wapi/v2.2.1/``.

*username* - the username to authenticate to the WAPI service

*password* - the password to authenticate to the WAPI service

*sslverify* - if True, then the SSL certificate for the WAPI service will be
validated

The Heat engine must be restarted after installation and configuration of the
package.

Note that storing these in the configuration file is not ideal and will change
in a future build. In the configuration file, the GM must be available at the
time of configuration, and therefore cannot simply be spun up as part of the
stack. Additionally, it enables any Heat user to utilize the grid resources.

Infoblox NIOS Configuration
---------------------------

No special configuration is necessary.


Using the Heat Resources
------------------------

*Infoblox::Grid::Member*

After installing the package, you should see the Infoblox::Grid::Member
resource available in the Orchestration > Resource Types section of the
OpenStack Horizon UI.

This resource represents a grid member configuration within the GM. It must
be created prior to the spin up of the Nova server associated with the grid
member.

An example template using this resources is in the doc/templates directory of
this package.

*Infoblox::Grid::NameServerGroupMember*

This resource represents the membership of a grid member within a name server
group. It does *not* represent the name server group itself. The name server
group must be pre-created and configured on the GM.

The creation of this resource will *add* the specified member to the named
group, while the deletion of this resource will remove it. Only the management
of grid secondary members is implemented.

The example templates include use of this resource as well. It must be created
only after the Infoblox::Grid::Member has already been created.

For test purposes when using the included templates, you can run the setup.sh
script to create a nios use and tenant, and setup test networks.

