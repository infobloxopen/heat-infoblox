===============================
heat-infoblox
===============================

.. image:: https://travis-ci.org/infobloxopen/heat-infoblox.svg?branch=stable%2Fkilo
    :target: https://travis-ci.org/infobloxopen/heat-infoblox

OpenStack Heat resources for integration with Infoblox appliances.

Features
--------

This package enables the configuration of Infoblox DDI appliances, as well
as the management of physical network resources via the Infoblox NetMRI
product.

With these resources you can:
 * Add and remove members from an Infoblox Grid
 * Add and remove grid members from a nameserver group
 * Configure Anycast loopback addresses on grid members [coming soon]
 * Configure OSPF and BGP protocols to advertise Anycast addresses [coming soon]
 * Execute aribtrary jobs on the NetMRI
 * Manage physical resources with a Heat resource that will execute different
   create and delete jobs on the NetMRI when a resource is created and deleted.

Installation
------------

You may install this module directly from PyPi.

OpenStack Configuration
-----------------------

You must update the ``plugin_dirs`` parameter in the ``heat.conf`` file
to include the resources from this module. Typically this would mean
adding ``/usr/local/lib/python2.7/dist-packages/heat_infoblox``.
Also you must add ``lock_path`` under ``oslo_concurrency`` stanza.
For security, the specified directory should only be writable by the user
running the heat process:
::

  plugin_dirs = /usr/local/lib/python2.7/dist-packages/heat_infoblox,/usr/lib64/heat,/usr/lib/heat
  [oslo_concurrency]
  # replace it with a directory writable by the user running the heat process
  lock_path = /home/user/directory_for_locks

The Heat engine must be restarted after installation and configuration of the
package.

Prior releases required configuration of connectivity parameters in the
``heat.conf`` file. This is no longer necessary, and those parameters are no
longer read. Instead, you include a ``connection`` map in the resource itself.

Infoblox Configuration
----------------------

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

*Infoblox::Grid::HaPair*

This resource create an HA pair GM, *not* for adding an HA pair to an existing
grid.

Your should use *Infoblox::Grid::Member* with "ha_pair" set to True to add
HA pair member into grid.

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

*Infoblox::NetMRI::Job*

This resource executes an arbitrary job in the NetMRI upon creation. It does
nothing upon deletion.

*Infoblox::NetMRI::ManagedResource*

This resource executes an arbitrary job in the NetMRI upon creation, and a
different job upon deletion.


Enabling In DevStack
--------------------

To enable use of Infoblox Heat resources in DevStack, add this repository as a
plugin:

::

  enable_plugin heat-infoblox https://github.com/infobloxopen/heat-infoblox.git

This will add the heat-infoblox module in development mode.

