# plugin.sh - DevStack plugin.sh dispatch script heat_infoblox

function install_heat_infoblox {
    echo
}

function init_heat_infoblox {
    echo
}

function configure_heat_infoblox {
    echo "Adding $HEAT_INFOBLOX_DIR/heat_infoblox to plugins_dir in $HEAT_CONF"
    echo >> $HEAT_CONF
    echo "# Added by heat-infoblox" >> $HEAT_CONF
    echo "[DEFAULT]" >> $HEAT_CONF
    echo "plugin_dirs=$HEAT_INFOBLOX_DIR/heat_infoblox,/usr/lib64/heat,/usr/lib/heat" >> $HEAT_CONF
}

# check for service enabled
if is_service_enabled heat-infoblox; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services for Infoblox Heat"
        #install_package cowsay

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing Infoblox Heat"
        install_heat_infoblox

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring Infoblox heat"
        configure_heat_infoblox

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the heat-infoblox service
        echo_summary "Initializing Infoblox Heat"
        init_heat_infoblox
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down heat_infoblox services
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        :
    fi
fi
