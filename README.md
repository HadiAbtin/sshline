# SSH Tunnel Manager

An automated SSH tunnel management system that establishes and maintains multiple SSH tunnels with TUN (network tunnel) interfaces. Each tunnel runs in a separate screen session for reliability and easy monitoring.

## Features

- **Automatic Tunnel Management**: Establishes SSH tunnels based on JSON configuration
- **TUN Interface Support**: Creates point-to-point VPN-like connections using TUN interfaces
- **Port Forwarding**: Supports both local and remote port forwarding
- **Dual Stack Support**: IPv4 and IPv6 connectivity
- **Auto-Reconnect**: Automatically reconnects on connection failure
- **Screen Session Management**: Each tunnel runs in a separate screen session for easy monitoring
- **Hostname Resolution**: Automatically updates `/etc/hosts` and SSH config for easy access

## Prerequisites

### Required Packages

- **bash**: Shell interpreter (usually pre-installed)
- **jq**: JSON processor for parsing configuration files
- **screen**: Terminal multiplexer for managing tunnel sessions
- **ssh/openssh-client**: SSH client for establishing connections
- **iproute2**: Network configuration tools (`ip` command)
- **iptables**: Firewall rules management (for NAT on remote side)
- **bc**: Basic calculator for IP address calculations

### Installation on Different Distributions

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y jq screen openssh-client iproute2 iptables bc
```

#### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL 7
sudo yum install -y jq screen openssh-clients iproute iptables bc

# CentOS/RHEL 8+ / Fedora
sudo dnf install -y jq screen openssh-clients iproute iptables bc
```

#### Arch Linux
```bash
sudo pacman -S jq screen openssh iproute2 iptables bc
```

### System Requirements

- **Operating System**: Linux (tested on Debian, Ubuntu, CentOS, RHEL, Fedora, Arch)
- **Permissions**: Root access required (for TUN interface creation and `/etc/hosts` modification)
- **Network**: SSH access to remote servers
- **SSH Keys**: Private SSH key must be placed in `keys/id_rsa` with proper permissions (600)

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd sshline
```

2. Create the SSH keys directory and place your private key:
```bash
mkdir -p keys
cp /path/to/your/private/key keys/id_rsa
chmod 600 keys/id_rsa
```

3. Configure your tunnels in `tunnel.json` (see Configuration section)

4. Make the script executable:
```bash
chmod +x tunnel.sh
```

## Configuration

### Tunnel Configuration File (`tunnel.json`)

The configuration file is a JSON array where each object represents a tunnel configuration.

#### Configuration Fields

**Required Fields:**
- `index` (string): TUN interface number (must be unique, e.g., "0", "1", "2")
- `ssh_port` (string): SSH port on the remote server (typically "22")
- `ipv4` (string): IPv4 address of the remote server
- `local_port` (string): Local port number for port forwarding
- `remote_port` (string): Remote port number for port forwarding

**Optional Fields:**
- `host_name` (string): Friendly hostname for `/etc/hosts` and SSH config mapping
- `local_bind` (string): Local bind address (default: "0.0.0.0" - all interfaces)
- `remote_bind` (string): Remote bind address (default: "localhost")
- `preferred` (string): IP version preference - "v4" or "v6" (default: "v4")
- `ipv6` (string): IPv6 address of the remote server (for IPv6 support)

#### Example Configuration

```json
[
    {
        "index": "0",
        "host_name": "webserver",
        "ssh_port": "22",
        "ipv4": "192.168.1.100",
        "local_bind": "0.0.0.0",
        "local_port": "8080",
        "remote_bind": "localhost",
        "remote_port": "80",
        "preferred": "v4",
        "ipv6": ""
    },
    {
        "index": "1",
        "host_name": "database",
        "ssh_port": "2222",
        "ipv4": "192.168.1.101",
        "local_bind": "127.0.0.1",
        "local_port": "3306",
        "remote_bind": "localhost",
        "remote_port": "3306",
        "preferred": "v4",
        "ipv6": "2001:db8::1"
    }
]
```

#### Field Descriptions

- **index**: The TUN interface number. Each tunnel must have a unique index. This determines the TUN interface name (tun0, tun1, etc.) and the IP address assignment in the 10.1.1.0/24 range.

- **host_name**: A friendly name for the server. If provided, the script will:
  - Add entries to `/etc/hosts` (e.g., `webserver4` for IPv4, `webserver6` for IPv6)
  - Create SSH config entries for easier access

- **ssh_port**: The SSH port on the remote server. Use "22" for standard SSH, or a custom port if your server uses a non-standard port.

- **ipv4**: The IPv4 address of the remote server. This is required for establishing the SSH connection.

- **ipv6**: Optional IPv6 address. If provided and `preferred` is set to "v6", the script will use IPv6 for the connection.

- **local_bind**: The local IP address to bind the port forward to. Use "0.0.0.0" to bind to all interfaces, or "127.0.0.1" to bind only to localhost.

- **local_port**: The local port number that will be forwarded. For example, if set to "8080", connections to `localhost:8080` will be forwarded to the remote server.

- **remote_bind**: The IP address on the remote server to bind to. Typically "localhost" to forward to services running on the remote server itself.

- **remote_port**: The port on the remote server to forward to. For example, "80" for HTTP, "3306" for MySQL, etc.

- **preferred**: IP version preference. Set to "v4" to prefer IPv4 (default) or "v6" to prefer IPv6 if both addresses are provided.

## Usage

### Starting Tunnels

Run the script as root to start all configured tunnels:

```bash
sudo ./tunnel.sh
```

The script will:
1. Validate the JSON configuration file
2. Create scripts for each tunnel
3. Establish SSH connections
4. Configure TUN interfaces
5. Start screen sessions for each tunnel

### Stopping Tunnels

To stop all tunnels:

```bash
sudo ./tunnel.sh stop
```

This will terminate all screen sessions running tunnels.

### Monitoring Tunnels

Each tunnel runs in a separate screen session. To monitor a specific tunnel:

```bash
# List all screen sessions
screen -ls

# Attach to a specific tunnel session (e.g., tunnel with index 0)
screen -r ssh-0

# Detach from screen session: Press Ctrl+A, then D
```

### Viewing Logs

Each tunnel creates a log file in `/tmp/`:

```bash
# View log for tunnel with index 0
tail -f /tmp/ssh-0.log

# View log for tunnel with index 1
tail -f /tmp/ssh-1.log
```

## How It Works

1. **Configuration Parsing**: The script reads `tunnel.json` and validates the JSON syntax using `jq`.

2. **Script Generation**: For each tunnel, the script generates:
   - A local script that establishes the SSH connection with TUN interface and port forwarding
   - A remote script that configures the TUN interface and network settings on the remote server

3. **Remote Script Deployment**: The remote script is copied to the server via SCP.

4. **Tunnel Establishment**: Each tunnel is started in a separate screen session with:
   - TUN interface creation (`-w` flag)
   - Port forwarding (`-L` flag)
   - Automatic reconnection on failure (infinite loop)

5. **Network Configuration**: 
   - Local TUN interfaces are configured with IP addresses from the 10.1.1.0/24 range
   - Remote TUN interfaces are configured with corresponding IP addresses
   - NAT rules are set up on the remote server for network masquerading

6. **Hostname Resolution**: If `host_name` is provided, entries are added to `/etc/hosts` and SSH config for easier access.

## Network Architecture

### IP Address Assignment

Each tunnel gets a `/30` subnet (4 addresses) from the `10.1.1.0/24` range:
- Tunnel 0: Local `10.1.1.1` ↔ Remote `10.1.1.2`
- Tunnel 1: Local `10.1.1.5` ↔ Remote `10.1.1.6`
- Tunnel 2: Local `10.1.1.9` ↔ Remote `10.1.1.10`
- And so on...

### TUN Interface

The TUN (network tunnel) interface creates a point-to-point connection between local and remote machines, similar to a VPN. This allows:
- Direct network communication between endpoints
- Routing traffic through the tunnel
- Network-level access (not just port forwarding)

## Troubleshooting

### Tunnel Not Connecting

1. **Check SSH Key Permissions**:
   ```bash
   ls -l keys/id_rsa
   # Should show: -rw------- (600)
   chmod 600 keys/id_rsa
   ```

2. **Verify SSH Access**:
   ```bash
   ssh -i keys/id_rsa -p <SSH_PORT> root@<SERVER_IP>
   ```

3. **Check Screen Sessions**:
   ```bash
   screen -ls
   screen -r ssh-<INDEX>
   ```

4. **View Logs**:
   ```bash
   tail -f /tmp/ssh-<INDEX>.log
   ```

### JSON Configuration Errors

Validate your JSON configuration:
```bash
jq '.' tunnel.json
```

### Permission Errors

The script requires root privileges for:
- Creating TUN interfaces
- Modifying `/etc/hosts`
- Configuring network interfaces

Run with `sudo`:
```bash
sudo ./tunnel.sh
```

### TUN Interface Not Available

Ensure your system supports TUN interfaces:
```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module if needed
modprobe tun
```

## Security Considerations

- **SSH Key Security**: Keep your private SSH keys secure. Never commit them to version control.
- **Root Access**: This script requires root privileges. Review the code before running.
- **Firewall Rules**: The remote script modifies iptables rules. Ensure this is acceptable for your environment.
- **Host Key Verification**: The script disables strict host key checking for convenience. Consider enabling it for production use.

## File Structure

```
sshline/
├── tunnel.sh              # Main script
├── tunnel.json            # Tunnel configuration (user-provided)
├── tunnel.json.example    # Example configuration
├── keys/                  # SSH keys directory (not in repo)
│   └── id_rsa            # Private SSH key (user-provided)
├── README.md             # This file
├── LICENSE               # Apache 2.0 License
└── .gitignore           # Git ignore rules
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
