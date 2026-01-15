# Installation Guide

This guide covers all installation methods and configuration options for NetGraph.

## Requirements

- **Python**: 3.10 or higher
- **AWS Credentials**: Valid AWS credentials with read-only EC2 permissions
- **MCP Client**: Claude Desktop, Claude Code CLI, Cursor, or another MCP-compatible client

## Installation Methods

### Method 1: pip (Recommended)

```bash
pip install aws-vpc-analyzer
```

### Method 2: uvx (For MCP users)

If you use `uv` for Python package management:

```bash
uvx aws-vpc-analyzer
```

### Method 3: From Source

For development or to get the latest changes:

```bash
git clone https://github.com/ayushgoel24/mcp-netgraph.git
cd mcp-netgraph
pip install -e .
```

### Method 4: With Development Dependencies

For contributing or running tests:

```bash
git clone https://github.com/ayushgoel24/mcp-netgraph.git
cd mcp-netgraph
pip install -e ".[dev]"
```

## Verify Installation

After installation, verify NetGraph is working:

```bash
# Check the command is available
aws-vpc-analyzer --help

# Or run as a module
python -m netgraph.server --help
```

## AWS Credentials Setup

NetGraph requires AWS credentials to access your VPC resources. It uses the standard AWS credential chain.

### Option 1: AWS CLI Profile (Recommended)

1. Install the AWS CLI if you haven't already:

   ```bash
   pip install awscli
   ```

2. Configure a profile:

   ```bash
   aws configure --profile my-profile
   ```

3. Verify the profile works:

   ```bash
   aws sts get-caller-identity --profile my-profile
   ```

### Option 2: Environment Variables

Set credentials directly:

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

### Option 3: IAM Role (EC2/Lambda)

If running on EC2 or Lambda, attach an IAM role with the required permissions. No additional configuration needed.

### Required IAM Permissions

See [IAM Policy Documentation](./iam-policy.md) for the complete policy.

Minimum permissions:

```
ec2:DescribeInstances
ec2:DescribeNetworkInterfaces
ec2:DescribeSubnets
ec2:DescribeSecurityGroups
ec2:DescribeNetworkAcls
ec2:DescribeRouteTables
ec2:DescribeInternetGateways
ec2:DescribeNatGateways
ec2:DescribeVpcs
ec2:DescribeVpcPeeringConnections
ec2:DescribeTransitGateways
ec2:DescribeTransitGatewayAttachments
ec2:GetManagedPrefixListEntries
```

## MCP Client Configuration

MCP (Model Context Protocol) allows AI assistants like Claude to use external tools. NetGraph runs as an MCP server that your AI client connects to via stdio transport.

### Configuration Fields Explained

| Field | Description |
|-------|-------------|
| `command` | The executable to run (`aws-vpc-analyzer` or `python`) |
| `args` | Command-line arguments (only needed when using `python -m`) |
| `env` | Environment variables passed to the server |

### Claude Desktop

1. **Locate your config file:**

   | OS | Path |
   |----|------|
   | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
   | Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
   | Linux | `~/.config/Claude/claude_desktop_config.json` |

2. **Create or edit the file** with one of these configurations:

   **Option A: Using the installed command (recommended)**
   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "aws-vpc-analyzer",
         "env": {
           "AWS_PROFILE": "my-profile",
           "AWS_REGION": "us-east-1"
         }
       }
     }
   }
   ```

   **Option B: Using Python module directly**
   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "python",
         "args": ["-m", "netgraph.server"],
         "env": {
           "AWS_PROFILE": "my-profile",
           "AWS_REGION": "us-east-1"
         }
       }
     }
   }
   ```

   **Option C: Using uvx (no installation required)**
   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "uvx",
         "args": ["aws-vpc-analyzer"],
         "env": {
           "AWS_PROFILE": "my-profile",
           "AWS_REGION": "us-east-1"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop** to load the new configuration.

4. **Verify it's working:** Start a new conversation and ask "What tools do you have for AWS VPC analysis?" Claude should mention the NetGraph tools.

### Claude Code (CLI)

1. **Choose your config location:**
   - `~/.claude.json` - Global config for all projects
   - `.mcp.json` - Project-specific config (in your project root)

2. **Add the configuration:**

   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "aws-vpc-analyzer",
         "env": {
           "AWS_PROFILE": "my-profile",
           "AWS_REGION": "us-east-1"
         }
       }
     }
   }
   ```

3. **Restart Claude Code** or start a new session.

### Cursor

1. **Open Cursor Settings** → **MCP** (or search for "MCP" in settings)

2. **Add server configuration:**

   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "aws-vpc-analyzer",
         "env": {
           "AWS_PROFILE": "my-profile",
           "AWS_REGION": "us-east-1"
         }
       }
     }
   }
   ```

3. **Restart Cursor** to apply changes.

### Other MCP Clients

For any MCP-compatible client, configure a server with:
- **Name:** `netgraph`
- **Command:** `aws-vpc-analyzer` (or `python -m netgraph.server`)
- **Transport:** stdio (default)
- **Environment variables:** `AWS_PROFILE`, `AWS_REGION` (see Configuration Options below)

## Configuration Options

Configure NetGraph behavior via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-1` | AWS region to query |
| `AWS_PROFILE` | (none) | AWS CLI profile name |
| `NETGRAPH_TTL` | `60` | Cache TTL in seconds |
| `NETGRAPH_ROLE_ARN` | (none) | IAM role ARN for cross-account access |
| `NETGRAPH_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |

Example with all options:

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "aws-vpc-analyzer",
      "env": {
        "AWS_PROFILE": "production",
        "AWS_REGION": "us-west-2",
        "NETGRAPH_TTL": "120",
        "NETGRAPH_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

## Cross-Account Access

To analyze VPCs in multiple AWS accounts:

1. **Create an IAM role in each target account** with:
   - Required EC2 read permissions
   - Trust relationship allowing your source account to assume the role

2. **Add sts:AssumeRole permission** to your source credentials

3. **Configure the role ARN**:

   ```json
   {
     "mcpServers": {
       "netgraph": {
         "command": "aws-vpc-analyzer",
         "env": {
           "AWS_PROFILE": "my-profile",
           "NETGRAPH_ROLE_ARN": "arn:aws:iam::123456789012:role/NetGraphRole"
         }
       }
     }
   }
   ```

## Troubleshooting

### "Command not found: aws-vpc-analyzer"

Ensure the installation directory is in your PATH:

```bash
# Find where pip installed it
pip show aws-vpc-analyzer | grep Location

# Add to PATH if needed (add to ~/.bashrc or ~/.zshrc)
export PATH="$PATH:$(python -m site --user-base)/bin"
```

### "Access Denied" errors

1. Verify your credentials are working:

   ```bash
   aws sts get-caller-identity --profile your-profile
   ```

2. Check your IAM permissions include all required EC2 describe actions

3. Verify the region is correct for your resources

### "No module named 'netgraph'"

The package may not be installed correctly:

```bash
pip uninstall aws-vpc-analyzer
pip install aws-vpc-analyzer
```

### MCP client doesn't see NetGraph tools

1. Restart your MCP client after configuration changes
2. Check the configuration file path is correct for your OS
3. Verify JSON syntax is valid
4. Check MCP client logs for error messages

### Cache issues / stale data

Force refresh data by using `force_refresh=true` in your queries, or wait for the TTL to expire (default: 60 seconds).

## Next Steps

- [IAM Policy Documentation](./iam-policy.md) - Copy-paste IAM policy
- [Example Prompts](./examples.md) - Usage examples and prompt templates
- [README](../README.md) - Tool reference and quick start
