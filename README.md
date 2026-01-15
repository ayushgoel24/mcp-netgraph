# NetGraph

**Model Context Protocol (MCP) server for AWS VPC network topology analysis**

NetGraph models AWS VPC infrastructure as a NetworkX directed graph, enabling deterministic reachability analysis and security auditing for AI agents. It evaluates Security Groups, NACLs, and route tables to answer questions like "Can instance A reach instance B on port 443?"

## Features

- **Lazy Graph-Based Topology** - Represent VPC resources (instances, ENIs, subnets, gateways) as NetworkX DiGraph nodes with routing relationships as directed edges
- **Accurate Rule Evaluation** - Handle stateful Security Groups vs stateless NACLs correctly, with Managed Prefix List support
- **Dual-Stack Networking** - Full IPv4 and IPv6 support throughout all evaluators
- **Cross-Account Traversal** - Support VPC peering analysis across AWS accounts via STS role assumption
- **LLM-Friendly Discovery** - Tag-based resource lookup to bridge natural language queries to AWS resource IDs

## Architecture

```mermaid
flowchart TB
    subgraph MCP["MCP Layer"]
        Server[MCP Server]
        Tools[Tool Handlers]
    end

    subgraph Core["Core Engine"]
        Graph[Graph Manager<br/>Read-Through Cache]
        PathAnalyzer[Path Analyzer]
        ExposureDetector[Exposure Detector]
        Discovery[Resource Discovery]
    end

    subgraph Evaluation["Rule Evaluation"]
        SGEvaluator[Security Group Evaluator]
        NACLEvaluator[NACL Evaluator]
        RouteEvaluator[Route Evaluator<br/>with LPM]
        CIDRMatcher[CIDR Matcher<br/>IPv4 + IPv6]
        PrefixResolver[Prefix List Resolver]
    end

    subgraph AWS["AWS Client Layer"]
        AWSClient[AWS Client Factory]
        EC2Client[EC2 Client]
        STSClient[STS Client]
        Cache[(Node Cache)]
    end

    Server --> Tools
    Tools --> Graph
    Tools --> PathAnalyzer
    Tools --> ExposureDetector
    Tools --> Discovery

    PathAnalyzer --> SGEvaluator
    PathAnalyzer --> NACLEvaluator
    PathAnalyzer --> RouteEvaluator

    SGEvaluator --> CIDRMatcher
    SGEvaluator --> PrefixResolver
    NACLEvaluator --> CIDRMatcher
    RouteEvaluator --> CIDRMatcher

    Graph --> AWSClient
    Graph --> Cache
    Discovery --> AWSClient
    PrefixResolver --> AWSClient
    AWSClient --> EC2Client
    AWSClient --> STSClient
```

## Data Flow

```mermaid
sequenceDiagram
    participant LLM as LLM/Client
    participant MCP as MCP Server
    participant PA as Path Analyzer
    participant GM as Graph Manager<br/>(Cache)
    participant AWS as AWS Client
    participant RE as Rule Evaluators

    LLM->>MCP: analyze_path(source, dest, port, proto)
    MCP->>PA: evaluate_path()

    PA->>GM: get_node(source_id)
    alt Cache Miss
        GM->>AWS: describe_instances(source_id)
        AWS-->>GM: Instance data
        GM->>GM: Cache node
    end
    GM-->>PA: Node with ENI, subnet refs

    PA->>GM: get_subnet(subnet_id)
    alt Cache Miss
        GM->>AWS: describe_subnets(subnet_id)
        AWS-->>GM: Subnet + route table
        GM->>GM: Cache node
    end
    GM-->>PA: Subnet with route table

    loop Each hop in path
        PA->>GM: get_next_hop(route_target)
        Note over GM: JIT fetch if not cached
        PA->>RE: evaluate_egress(sg, nacl, route)
        RE-->>PA: RuleResult(allowed/blocked/unknown, reason)
        alt Blocked or Unknown
            PA-->>MCP: PathResult(status, blocked_at)
        end
    end

    PA->>RE: evaluate_ingress(dest_sg, dest_nacl)
    RE-->>PA: RuleResult
    PA-->>MCP: PathResult(status=REACHABLE/BLOCKED/UNKNOWN)
    MCP-->>LLM: JSON response
```

## Installation

```bash
# Clone the repository
git clone https://github.com/ayushgoel/mcp-netgraph.git
cd mcp-netgraph

# Create and activate virtual environment (Python 3.10+)
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

## MCP Tools

### analyze_path

Analyze network reachability from source to destination with hop-by-hop evaluation.

```python
analyze_path(
    source_id="i-1234567890abcdef0",  # EC2 instance or ENI ID
    dest_ip="10.0.2.100",              # IPv4 or IPv6 destination
    port=443,
    protocol="tcp",
    force_refresh=False                # Bypass cache after AWS changes
)
```

**Returns:** `PathAnalysisResult` with status (REACHABLE, BLOCKED, UNKNOWN), full hop path, and blocking details if blocked.

### find_public_exposure

Find all resources exposed to the public internet on a specified port.

```python
find_public_exposure(
    port=22,                           # Port to check
    protocol="tcp",
    severity_filter="critical",        # Optional: "all", "high", "critical"
    vpc_ids=["vpc-123"]                # Optional: limit to specific VPCs
)
```

**Returns:** `PublicExposureResult` with exposed resources and remediation guidance.

### find_resources

Tag-based resource discovery for natural language queries.

```python
find_resources(
    name_pattern="web-*",              # Glob pattern for Name tag
    tags={"Environment": "prod"},      # Filter by tags
    resource_type="instance",          # instance, eni, subnet, security_group, vpc
    vpc_id="vpc-123",                  # Optional VPC filter
    limit=20
)
```

**Returns:** `ResourceDiscoveryResult` with matching resources including IDs, IPs, and tags.

### refresh_topology (Optional)

Pre-warm the graph cache with VPC topology for faster subsequent queries.

```python
refresh_topology(
    vpc_ids=["vpc-123", "vpc-456"],
    cross_account_roles={"123456789012": "arn:aws:iam::123456789012:role/NetGraphRole"}
)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Lazy Loading (JIT)** | Eager ingestion times out on accounts with 5000+ ENIs; fetch only what's needed during path traversal |
| **Explicit LPM Algorithm** | Route selection via Longest Prefix Match must be explicit and testable, not implicit |
| **PathStatus.UNKNOWN** | Distinguish "blocked by rule" from "couldn't determine due to permission failure" |
| **NACL Return Path Verification** | NACLs are stateless - must verify return traffic (ephemeral ports 1024-65535) can reach source |
| **Reverse Path Routing** | Destination subnet must have route back to source IP to prevent asymmetric routing failures |
| **Cache TTL (60s)** | Prevents stale cache from causing false negatives after user fixes rules in AWS Console |
| **Loop Detection** | Network graphs can be cyclic; visited_nodes set prevents infinite traversal |

## Graph Schema

```mermaid
erDiagram
    GRAPH_NODE {
        string id PK "Resource ID (i-xxx, eni-xxx, subnet-xxx)"
        string node_type "instance | eni | subnet | igw | nat | peering"
        string vpc_id "Parent VPC"
        string account_id "Owning AWS account"
        string region "AWS region"
        json attributes "Type-specific attributes"
        timestamp cached_at "When node was fetched"
    }

    GRAPH_EDGE {
        string source_id FK "Source node ID"
        string target_id FK "Target node ID"
        string edge_type "route | attachment | association"
        string route_table_id "Associated route table"
        string cidr_destination "Destination CIDR for route"
        int prefix_length "For LPM sorting"
    }

    SECURITY_GROUP {
        string sg_id PK
        string vpc_id FK
        list inbound_rules "Supports CIDR, prefix list, SG ref"
        list outbound_rules
    }

    NACL {
        string nacl_id PK
        string vpc_id FK
        list inbound_rules "Ordered by rule_number, IPv4+IPv6"
        list outbound_rules
    }

    GRAPH_NODE ||--o{ GRAPH_EDGE : "has_outbound"
    GRAPH_NODE ||--o{ SECURITY_GROUP : "attached_to"
    GRAPH_NODE ||--o{ NACL : "associated_with"
```

## Implementation Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Project foundation, exceptions, logging |
| Phase 2 | ✅ Complete | Pydantic data models (graph, AWS resources, results) |
| Phase 3 | ✅ Complete | Rule evaluators (SG, NACL, Route, CIDR) |
| Phase 4 | ✅ Complete | AWS client with pagination, retry, cross-account support |
| Phase 5 | ✅ Complete | Core engine: GraphManager with read-through cache |
| Phase 6A | ✅ Complete | PathAnalyzer with deterministic LPM traversal |
| Phase 6B | ✅ Complete | MCP tools and server integration |
| Phase 7 | ✅ Complete | Integration tests, performance tests, documentation |

## Development

```bash
# Run tests
pytest                              # All tests
pytest tests/unit/                  # Unit tests only
pytest -k "test_cidr"               # Tests matching pattern
pytest --cov                        # With coverage

# Type checking
mypy src/

# Linting
ruff check src/ tests/
ruff format src/ tests/
```

## Project Structure

```
src/netgraph/
├── server.py                # MCP server entry point
├── utils/logging.py         # Structured logging
├── models/
│   ├── errors.py            # Exception hierarchy
│   ├── graph.py             # NodeType, GraphNode, GraphEdge
│   ├── results.py           # PathStatus, PathAnalysisResult
│   └── aws_resources.py     # SGRule, NACLRule, Route, etc.
├── evaluators/
│   ├── cidr.py              # CIDRMatcher with LRU cache
│   ├── route.py             # RouteEvaluator with LPM
│   ├── nacl.py              # NACLEvaluator (stateless)
│   └── security_group.py    # SecurityGroupEvaluator (stateful)
├── aws/
│   ├── client.py            # AWSClient, AWSClientFactory
│   └── fetcher.py           # EC2Fetcher with auto-pagination
├── core/
│   ├── graph_manager.py     # Read-through cache, topology building
│   ├── path_analyzer.py     # Deterministic LPM traversal
│   ├── exposure_detector.py # Public internet exposure scanning
│   └── resource_discovery.py # Tag-based resource lookup
└── tools/                   # MCP tool implementations

tests/
├── unit/                    # Unit tests for all modules
├── integration/             # E2E scenario and MCP protocol tests
├── performance/             # Large VPC performance benchmarks
└── fixtures/                # VPC topology and prefix list fixtures

scripts/
└── verify_live.py           # Live AWS sandbox verification

docs/
└── examples.md              # Example Claude prompts
```

## AWS Permissions Required

The IAM principal running NetGraph needs these EC2 read permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeRouteTables",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeNatGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTransitGateways",
                "ec2:DescribeTransitGatewayAttachments",
                "ec2:GetManagedPrefixListEntries"
            ],
            "Resource": "*"
        }
    ]
}
```

For cross-account analysis, add `sts:AssumeRole` permission and configure trust relationships on target account roles.

## Live AWS Verification

Before deploying to production, verify NetGraph behavior against a real AWS account:

```bash
# Run all verification checks
AWS_PROFILE=dev-sandbox python scripts/verify_live.py

# Verbose output with details
AWS_PROFILE=dev-sandbox python scripts/verify_live.py --verbose

# Run a single check
AWS_PROFILE=dev-sandbox python scripts/verify_live.py --check pagination
```

The verification script validates:
- Error code formats match expectations
- Pagination returns complete data sets
- Prefix list resolution works correctly
- Response structures match what NetGraph expects
- Filter behavior is correct

This helps catch discrepancies between moto mocks and actual AWS behavior.

## Example Prompts

See [docs/examples.md](docs/examples.md) for example prompts to use with Claude, including:
- Debugging connection issues
- Security audits
- Pre-deployment validation
- Cross-VPC analysis
- Troubleshooting intermittent issues

## License

MIT
