#!/bin/bash
###############################################################################
# SSH Tunnel Manager Script
# 
# This script reads tunnel configurations from tunnel.json and establishes
# SSH tunnels with TUN (network tunnel) interfaces. Each tunnel is managed
# in a separate screen session for reliability and easy monitoring.
#
# Features:
# - Automatic tunnel establishment via SSH
# - TUN interface creation for point-to-point VPN-like connections
# - Port forwarding (local and remote)
# - IPv4 and IPv6 support
# - Automatic reconnection on failure
# - Screen session management for each tunnel
###############################################################################

# Set secure PATH to prevent execution of untrusted binaries
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Get the directory where this script is located (works with symlinks)
CWD="$(dirname $(readlink -f $0))"

# Configuration file path (JSON format with tunnel definitions)
CONF="$CWD/tunnel.json"

# SSH private key path (must be readable and have proper permissions)
SSHKEY="$CWD/keys/id_rsa"

###############################################################################
# Function: create_remote_script
#
# Creates a script that will be executed on the remote server after SSH
# connection is established. This script:
# 1. Configures the TUN interface on the remote side
# 2. Sets up IP forwarding
# 3. Configures iptables NAT rules for network masquerading
# 4. Keeps the connection alive with a ping loop
#
# The script is created in /tmp/remote-${INDEX}.sh and will be copied
# to the remote server via SCP before the SSH tunnel is established.
###############################################################################
create_remote_script()
{
	touch /tmp/remote-${INDEX}.sh
	chmod +x /tmp/remote-${INDEX}.sh
	cat > /tmp/remote-${INDEX}.sh << EOF
#!/bin/bash
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# Wait for TUN interface to be fully created by SSH
sleep 2
# Assign IP address to the TUN interface on remote side
# Uses 10.1.1.x/30 subnet (point-to-point, 4 addresses per tunnel)
ip a a 10.1.1.$TUNREMOTE/30 dev tun${INDEX}
# Bring the TUN interface up
ip l s up dev tun${INDEX}
# Enable IP forwarding on the remote server
echo 1 > /proc/sys/net/ipv4/ip_forward
# Flush existing NAT rules
iptables -t nat -F
# Set up NAT masquerading for traffic from 10.10.0.0/16 network
# This allows clients in that network to access internet through the tunnel
iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -j MASQUERADE
# Alternative per-tunnel NAT rules (commented out, can be enabled if needed)
#iptables -t nat -A POSTROUTING -s 10.10.${INDEX}.0/24 -j MASQUERADE
#ip route add 10.10.${INDEX}.0/24 via 10.1.1.$TUNLOCAL
# Keep connection alive with continuous ping (prevents timeout)
ping 8.8.8.8
EOF
}

###############################################################################
# Function: create_local_script
#
# Creates a script that runs on the local machine to establish and maintain
# the SSH tunnel. This script:
# 1. Runs in an infinite loop to automatically reconnect on failure
# 2. Establishes SSH connection with TUN interface (-w flag)
# 3. Sets up port forwarding (-L flag)
# 4. Executes the remote script after connection
# 5. Logs connection attempts with timestamps
#
# The script is created in /tmp/local-${INDEX}.sh and will be executed
# in a screen session for background operation.
###############################################################################
create_local_script()
{
	touch /tmp/local-${INDEX}.sh
	chmod +x /tmp/local-${INDEX}.sh
	cat > /tmp/local-${INDEX}.sh << EOF
#!/bin/bash
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# Infinite loop to automatically reconnect if tunnel drops
while :; do
	# Log connection attempt with timestamp
	echo "\$(date +%F-%T) -- Starting SSH Tunnel ${INDEX}" | tee -a $LOG
	# Establish SSH connection with the following options:
	ssh -v \\
		-o "ServerAliveInterval 10"		\\  # Send keepalive every 10 seconds
		-o "ServerAliveCountMax 3"		\\  # Max 3 failed keepalives before disconnect
		-o "CheckHostIP no"			\\  # Don't check host IP in known_hosts
		-o "StrictHostKeyChecking no"		\\  # Don't prompt for unknown host keys
		-o "UpdateHostKeys yes" 		\\  # Update known_hosts automatically
		-o "VerifyHostKeyDNS no"		\\  # Don't verify host keys via DNS
		-w $INDEX:$INDEX			\\  # Create TUN interface (local:remote device number)
		-L $LBIND:$LPORT:$RBIND:$RPORT		\\  # Local port forwarding (bind:port -> remote_bind:remote_port)
		-i $SSHKEY -p $SSHPORT root@$SERVER	\\  # SSH key, port, and server address
		/tmp/remote-${INDEX}.sh			# Execute remote script after connection
	# Wait 1 second before attempting reconnection
	sleep 1
done
EOF
}

###############################################################################
# Function: init_ip_script
#
# Initializes the local IP configuration script that will configure all
# TUN interfaces on the local machine. This script is built incrementally
# as each tunnel configuration is processed, then executed once at the end.
#
# The script sets up IP addresses for all TUN interfaces in a coordinated
# manner to avoid conflicts.
###############################################################################
init_ip_script()
{
	# Remove existing script if present
	[ -e "/tmp/local-ip.sh" ] && rm /tmp/local-ip.sh
	# Initialize script with shebang and PATH
	echo "#!/bin/bash" > /tmp/local-ip.sh
	echo "PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"" >> /tmp/local-ip.sh
	# Wait for TUN interfaces to be created by SSH
	echo "sleep 2" >> /tmp/local-ip.sh
	# Initialize counter for IP address calculation
	C=0
}

###############################################################################
# Function: create_ip_script
#
# Appends IP configuration commands to the local IP script for a specific
# tunnel. Each tunnel gets a /30 subnet (4 addresses) from the 10.1.1.0/24
# range:
# - Tunnel 0: 10.1.1.1 (local) <-> 10.1.1.2 (remote)
# - Tunnel 1: 10.1.1.5 (local) <-> 10.1.1.6 (remote)
# - Tunnel 2: 10.1.1.9 (local) <-> 10.1.1.10 (remote)
# etc.
#
# The counter C is incremented after each tunnel to ensure unique IPs.
###############################################################################
create_ip_script()
{
	# Calculate local IP: (counter * 4) + 1 (e.g., 0*4+1=1, 1*4+1=5, 2*4+1=9)
	TUNLOCAL=$(echo "($C * 4 ) + 1" | bc)
	# Calculate remote IP: (counter * 4) + 2 (e.g., 0*4+2=2, 1*4+2=6, 2*4+2=10)
	TUNREMOTE=$(echo "($C * 4 ) + 2" | bc)
	# Ensure script exists and is executable
	touch /tmp/local-ip.sh
	chmod +x /tmp/local-ip.sh
	# Append IP configuration commands for this tunnel
	cat >> /tmp/local-ip.sh << EOF
# Configure IP address for TUN interface ${INDEX}
ip a a 10.1.1.$TUNLOCAL/30 dev tun${INDEX}
# Bring the TUN interface up
ip l s up dev tun${INDEX}
EOF
	# Increment counter for next tunnel
	(( C++ ))
}

###############################################################################
# Function: stop_session
#
# Stops a specific screen session by name. Used to clean up existing
# tunnel sessions before creating new ones.
#
# Parameters:
#   $1 - Screen session name to stop
###############################################################################
stop_session()
{
	local SESSION=$1
	# Force quit the screen session (X = detach, S = session name)
	screen -XS $SESSION quit
}

###############################################################################
# Function: stop_all_sessions
#
# Stops all screen sessions that match the 'ssh-' pattern. This is used
# when the script is run with the "stop" parameter to clean up all tunnels.
#
# Finds all active screen sessions with names starting with 'ssh-' and
# terminates them one by one.
###############################################################################
stop_all_sessions()
{
	local SESSION
	# List all screen sessions, filter for 'ssh-' pattern, extract session names
	screen -x | grep 'ssh-' | awk '{print$1}' | while read SESSION; do
		echo "killing $SESSION"
		stop_session $SESSION
	done
}

###############################################################################
# Function: init_ssh_config
#
# Initializes the SSH config file by removing any existing configuration.
# This ensures a clean slate for the new tunnel configurations.
#
# The SSH config file is located at /root/.ssh/config and will be populated
# with host entries for each tunnel server.
###############################################################################
init_ssh_config()
{
	SSHCONF=/root/.ssh/config
	# Remove existing config if present
	[ -e "$SSHCONF" ] && rm "$SSHCONF"
}

###############################################################################
# Function: update_ssh_config
#
# Adds a host entry to the SSH config file for easier SSH access.
# This allows using hostnames instead of IP addresses when connecting.
#
# Parameters:
#   $1 - Hostname to add to SSH config
#
# The entry includes:
# - Hostname (IP address or hostname)
# - User (root)
# - Port (SSH port from configuration)
# - IdentityFile (SSH private key path)
###############################################################################
update_ssh_config()
{
	local HOST=$1
	echo "host $HOST
		hostname $HOST
		user root
		port $SSHPORT
		IdentityFile $SSHKEY
	" >> $SSHCONF
}

###############################################################################
# Function: update_etc_hosts
#
# Updates /etc/hosts file to map IP addresses to hostnames.
# This allows using friendly hostnames instead of IP addresses.
#
# Parameters:
#   $1 - IP address to map
#   $2 - Hostname to assign to the IP
#
# The function:
# 1. Removes any existing entries for the IP address
# 2. Removes any existing entries for the hostname
# 3. Adds a new mapping entry
###############################################################################
update_etc_hosts()
{
	local IP="$1"
	local HOST="$2"
	# Remove existing entries for this IP address
	sed -i -e "/^$IP[[:space:]]/d" /etc/hosts
	# Remove existing entries for this hostname
	sed -i -e "/^[[:space:]]$HOST/d" /etc/hosts
	# Add new mapping (formatted with 40-character width for IP)
	printf "%-40s %s\n" $IP $HOST >> /etc/hosts
}

###############################################################################
# Main Execution Flow
###############################################################################

# Check if script was called with "stop" parameter
# If so, terminate all tunnel sessions and exit
if [ "$1" == "stop" ]; then
	stop_all_sessions
	exit
fi

# Validate JSON configuration file syntax
# jq will return non-zero exit code if JSON is malformed
jq '.' $CONF &> /dev/null
if [ "$?" != "0" ]; then
	echo "Error in json config file!"
	echo "For Error check run:"
	echo "    jq '.' $CONF"
	exit
fi

# Initialize helper scripts and configurations
init_ip_script    # Prepare script for local TUN interface IP configuration
init_ssh_config   # Clear existing SSH config file

# Count the number of tunnel configurations in the JSON file
N=$(jq length $CONF)

# Adjust count for zero-based array indexing (seq 0 to N-1)
(( N-- ))

# Process each tunnel configuration in the JSON file
for I in $(seq 0 $N); do

	# Display the current tunnel configuration for verification
	jq -r ".[$I]" $CONF
	
	# Extract configuration values from JSON
	HNAME="$(jq -r ".[$I].host_name" $CONF)"      # Hostname for /etc/hosts mapping
	INDEX="$(jq -r ".[$I].index" $CONF)"          # TUN interface number (must be unique)
	SSHPORT="$(jq -r ".[$I].ssh_port" $CONF)"     # SSH port on remote server
	IPV4="$(jq -r ".[$I].ipv4" $CONF)"            # IPv4 address of remote server
	LBIND="$(jq -r ".[$I].local_bind" $CONF)"     # Local bind address for port forwarding
	LPORT="$(jq -r ".[$I].local_port" $CONF)"     # Local port for forwarding
	RBIND="$(jq -r ".[$I].remote_bind" $CONF)"    # Remote bind address for forwarding
	RPORT="$(jq -r ".[$I].remote_port" $CONF)"   # Remote port for forwarding
	PREFERRED="$(jq -r ".[$I].preferred" $CONF)"  # Preferred IP version: "v4" or "v6"
	IPV6="$(jq -r ".[$I].ipv6" $CONF)"            # IPv6 address of remote server (optional)

	# Validate required configuration values
	# Skip this tunnel if any required field is missing or null
	if [ "$INDEX" == "" ] || [ "$INDEX" == "null" ]; then
		echo "Bypass: index can not be empty"
		continue
	elif [ "$SSHPORT" == "" ] || [ "$SSHPORT" == "null" ]; then
		echo "Bypass: ssh_port can not be empty"
		continue
	elif [ "$IPV4" == "" ] || [ "$IPV4" == "null" ]; then
		echo "Bypass: ipv4 can not be empty"
		continue
	elif [ "$LPORT" == "" ] || [ "$LPORT" == "null" ]; then
		echo "Bypass: local_port can not be empty"
		continue
	elif [ "$RPORT" == "" ] || [ "$RPORT" == "null" ]; then
		echo "Bypass: remote_port can not be empty"
		continue
	fi

	# Set default values for optional configuration fields
	[ "$LBIND" == "" ] || [ "$LBIND" == "null" ] && LBIND="0.0.0.0"      # Default: bind to all interfaces
	[ "$RBIND" == "" ] || [ "$RBIND" == "null" ] && RBIND="localhost"    # Default: bind to localhost on remote
	[ "$PREFERRED" == "" ] || [ "$PREFERRED" == "null" ] && PREFERRED="v4"  # Default: prefer IPv4
	LOG="/tmp/ssh-${INDEX}.log"  # Log file path for this tunnel

	# Update system files for easier hostname resolution
	# Only update if host_name is provided in configuration
	if [ "$HNAME" != "" ]; then
		# Add IPv4 entry if IPv4 address is provided
		if [ "$IPV4" != "" ]; then
			update_etc_hosts "$IPV4" "${HNAME}4"      # Add to /etc/hosts (e.g., "server4")
			update_ssh_config "${HNAME}4"              # Add to SSH config
		fi
		# Add IPv6 entry if IPv6 address is provided
		if [ "$IPV6" != "" ]; then
			update_etc_hosts "$IPV6" "${HNAME}6"       # Add to /etc/hosts (e.g., "server6")
			update_ssh_config "${HNAME}6"              # Add to SSH config
		fi
	fi

	# Choose which IP version to use for connection
	# Prefer IPv6 if explicitly requested and IPv6 address is available
	if [ "$PREFERRED" == "v6" ] && [ "$IPV6" != "" ]; then
		SERVER="$IPV6"
	else
		SERVER="$IPV4"  # Default to IPv4
	fi

	# Generate scripts for this tunnel
	create_ip_script      # Add IP config commands to local-ip.sh
	create_remote_script  # Create remote script to run on server
	create_local_script   # Create local script to establish tunnel

	# Copy remote script to the server via SCP
	# The script will be executed after SSH tunnel is established
	scp -P$SSHPORT -i $SSHKEY \
		/tmp/remote-${INDEX}.sh root@[$SERVER]:/tmp/ &> /dev/null

	# Stop any existing screen session for this tunnel (if it exists)
	# This prevents duplicate tunnels with the same index
	stop_session ssh-${INDEX} &> /dev/null

	# Start a new screen session in detached mode to run the tunnel script
	# Screen session name: ssh-${INDEX} (e.g., ssh-0, ssh-1, etc.)
	# The script will run in background and automatically reconnect on failure
	screen -dmS ssh-${INDEX} /tmp/local-${INDEX}.sh

done

# Configure IP addresses for all local TUN interfaces
# This is done after all tunnels are established to ensure interfaces exist
if [ -x /tmp/local-ip.sh ]; then
	echo "Local IP Setting ..."
	/tmp/local-ip.sh
fi

exit
