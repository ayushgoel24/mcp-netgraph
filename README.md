# NetGraph

**MCP server for AWS VPC network path analysis and security auditing**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

NetGraph enables AI assistants to analyze AWS VPC network connectivity by modeling infrastructure as a graph. Ask questions like *"Can my web server reach the database on port 5432?"* and get deterministic answers with full path analysis.

## Why NetGraph?

**Without NetGraph**, debugging AWS network connectivity requires:
- Manually tracing Security Groups, NACLs, and route tables
- Checking stateful vs stateless rule semantics
- Verifying return path routing for NACLs
- Cross-referencing multiple AWS console pages

**With NetGraph**, your AI assistant can:
- Analyze complete network paths in seconds
- Identify exactly where traffic is blocked
- Find resources exposed to the public internet
- Discover resources by name or tags when you don't have IDs

## Quick Start

### Installation

```bash
pip install aws-vpc-analyzer
```

Or install from source:

```bash
git clone https://github.com/ayushgoel24/mcp-netgraph.git
cd mcp-netgraph
pip install -e .
```

For detailed setup instructions, see the [Installation Guide](docs/installation.md).

### Configure Your MCP Client

Add NetGraph to your MCP client configuration. Replace `your-profile` with your AWS CLI profile name.

<details>
<summary><b>Claude Desktop</b></summary>

**Config file location:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Add this configuration:**

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "aws-vpc-analyzer",
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

**Alternative using uvx (no pip install required):**

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "uvx",
      "args": ["aws-vpc-analyzer"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

</details>

<details>
<summary><b>Claude Code (CLI)</b></summary>

**Config file location:**
- Global: `~/.claude.json`
- Project-specific: `.mcp.json` in your project root

**Add this configuration:**

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "aws-vpc-analyzer",
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

Restart Claude Code or start a new session.

</details>

<details>
<summary><b>Cursor</b></summary>

Open **Settings** → **MCP** and add:

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "aws-vpc-analyzer",
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

Restart Cursor after saving.

</details>

For detailed setup instructions including troubleshooting, see the [Installation Guide](docs/installation.md).

### AWS Credentials

NetGraph uses your standard AWS credentials. Ensure you have:

1. **AWS CLI configured** with a profile, or
2. **Environment variables** set (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), or
3. **IAM role** attached (for EC2/Lambda environments)

Required IAM permissions: [See AWS Permissions](#aws-permissions) | [Full IAM Policy](docs/iam-policy.md)

## Tools

### `analyze_path`

Analyze network reachability between a source and destination with hop-by-hop evaluation of Security Groups, NACLs, and route tables.

```
Can instance i-0abc123 reach 10.0.2.50 on port 443?
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source_id` | string | Yes | EC2 instance ID (`i-xxx`) or ENI ID (`eni-xxx`) |
| `destination_ip` | string | Yes | IPv4 or IPv6 destination address |
| `port` | integer | Yes | Destination port (1-65535) |
| `protocol` | string | No | `tcp`, `udp`, `icmp`, or `-1` for all (default: `tcp`) |
| `force_refresh` | boolean | No | Bypass cache and fetch fresh data (default: `false`) |

**Returns:** Path status (`REACHABLE`, `BLOCKED`, or `UNKNOWN`), hop-by-hop details, and blocking reason if blocked.

---

### `find_public_exposure`

Scan a VPC to find resources exposed to the public internet on a specific port.

```
Show me all resources in vpc-12345678 exposed to SSH on port 22
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vpc_id` | string | Yes | VPC ID to scan (`vpc-xxx`) |
| `port` | integer | Yes | Port to check for exposure (1-65535) |
| `protocol` | string | No | `tcp`, `udp`, or `-1` for all (default: `tcp`) |
| `force_refresh` | boolean | No | Bypass cache (default: `false`) |

**Returns:** List of exposed resources with exposure paths, allowing Security Group rules, and remediation guidance.

---

### `find_resources`

Discover AWS resources by name pattern or tags. Useful when you know a resource by name but need its ID.

```
Find all production web servers in vpc-12345678
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vpc_id` | string | Yes | VPC ID to search (`vpc-xxx`) |
| `tags` | object | No | Tag key-value filters (e.g., `{"Environment": "prod"}`) |
| `resource_types` | array | No | Filter by type: `instance`, `eni`, `subnet`, `igw`, `nat`, `peering`, `tgw` |
| `name_pattern` | string | No | Glob pattern for Name tag (e.g., `web-*`, `*-prod-*`) |
| `max_results` | integer | No | Maximum results to return (default: 50, max: 50) |

**Returns:** Matching resources with IDs, names, IPs, subnets, and tags.

---

### `list_vpcs`

List and search VPCs in your account. Use this when you need a VPC ID but only know the name or tags.

```
What VPCs do I have? I'm looking for the production one.
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name_pattern` | string | No | Glob pattern for VPC Name tag (e.g., `prod-*`) |
| `tags` | object | No | Tag key-value filters (e.g., `{"Environment": "production"}`) |
| `cidr` | string | No | Filter by CIDR block (e.g., `10.0.0.0/16`) |

**Returns:** List of VPCs with IDs, names, CIDRs, state, and tags.

---

### `refresh_topology`

Pre-warm the cache by fetching all resources in specified VPCs. Optional optimization for faster subsequent queries.

```
Pre-load the topology for vpc-12345678
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vpc_ids` | array | Yes | List of VPC IDs to pre-warm (`["vpc-xxx", "vpc-yyy"]`) |

**Returns:** Node/edge counts, resources by type, and duration.

---

### `get_cache_stats`

Get cache performance statistics.

**Returns:** Cache hits, misses, hit rate, TTL, and entry counts.

## Configuration

Configure NetGraph via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-1` | AWS region to query |
| `AWS_PROFILE` | (none) | AWS CLI profile to use |
| `NETGRAPH_TTL` | `60` | Cache TTL in seconds |
| `NETGRAPH_ROLE_ARN` | (none) | IAM role ARN for cross-account access |
| `NETGRAPH_LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## Example Prompts

**Connectivity debugging:**
> Can my web server i-0abc123 reach the database at 10.0.3.50 on port 5432?

**Security audit:**
> Find all resources in vpc-prod12345 exposed to the internet on SSH port 22

**Resource discovery:**
> Find all instances tagged Environment=production in vpc-12345678

**VPC lookup:**
> List my VPCs - I need to find the one named "production"

**Pre-deployment validation:**
> Verify that i-gateway123 can reach 10.0.2.100 on port 8080

See [docs/examples.md](docs/examples.md) for more detailed examples.

## How It Works

NetGraph models your VPC as a directed graph:

- **Nodes:** EC2 instances, ENIs, subnets, Internet Gateways, NAT Gateways, VPC Peering connections
- **Edges:** Routing relationships with CIDR destinations and prefix lengths

When you ask about connectivity, NetGraph:

1. **Resolves** the source to its ENI and subnet
2. **Evaluates** Security Group egress rules (stateful - only checks outbound)
3. **Evaluates** NACL outbound rules (stateless - must also check return path)
4. **Traverses** the route table using Longest Prefix Match (LPM)
5. **Follows** the path through gateways until reaching the destination
6. **Evaluates** destination NACL inbound and Security Group ingress rules
7. **Verifies** return path routing to prevent asymmetric routing failures

## AWS Permissions

NetGraph requires read-only EC2 permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:GetManagedPrefixListEntries"
      ],
      "Resource": "*"
    }
  ]
}
```

For **cross-account analysis**, also add:
- `sts:AssumeRole` permission
- Trust relationship on target account roles
- Set `NETGRAPH_ROLE_ARN` environment variable

## Documentation

- [Installation Guide](docs/installation.md) - Detailed setup instructions
- [IAM Policy](docs/iam-policy.md) - Copy-paste IAM policies
- [Examples](docs/examples.md) - Detailed usage examples
- [Changelog](CHANGELOG.md) - Release notes and version history

## License

MIT

## Contributing

Contributions welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our development process and how to submit pull requests.
