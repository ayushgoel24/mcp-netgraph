# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2025-01-14

### Added

- **MCP Server** with stdio transport for Claude Desktop and other MCP clients
- **6 MCP Tools** for AWS VPC network analysis:
  - `analyze_path` - Evaluate network reachability with hop-by-hop path analysis
  - `find_public_exposure` - Scan VPCs for resources exposed to the internet
  - `find_resources` - Tag-based and name pattern resource discovery
  - `list_vpcs` - List and search VPCs by name, tags, or CIDR
  - `refresh_topology` - Pre-warm cache for faster subsequent queries
  - `get_cache_stats` - Monitor cache performance

- **Core Engine**:
  - `GraphManager` - Read-through cache with configurable TTL (default 60s)
  - `PathAnalyzer` - Deterministic LPM-based network path traversal
  - `ExposureDetector` - Internet exposure scanning with severity classification
  - `ResourceDiscovery` - Tag and pattern-based resource lookup

- **Rule Evaluators**:
  - `SecurityGroupEvaluator` - Stateful rule evaluation with prefix list support
  - `NACLEvaluator` - Stateless rule evaluation with return path verification
  - `RouteEvaluator` - Longest Prefix Match (LPM) route selection
  - `CIDRMatcher` - IPv4/IPv6 CIDR matching with LRU cache

- **AWS Client Layer**:
  - Auto-pagination on all `describe_*` API calls
  - Exponential backoff with jitter for rate limiting
  - Cross-account role assumption via STS
  - Proper error mapping to typed exceptions

- **Data Models** (Pydantic v2):
  - Graph models: `GraphNode`, `GraphEdge`, `NodeType`, `EdgeType`
  - AWS resources: `SecurityGroup`, `NetworkACL`, `RouteTable`, `SGRule`, `NACLRule`, `Route`
  - Results: `PathAnalysisResult`, `HopResult`, `RuleEvalResult`, `PathStatus`

- **Exception Hierarchy**:
  - `NetGraphError` base with `to_response()` for MCP-compatible JSON
  - `ValidationError`, `AWSAuthError`, `PermissionDeniedError`
  - `ResourceNotFoundError`, `CrossAccountAccessError`
  - `PrefixListResolutionError`, `CrossAccountSGResolutionError`
  - `AsymmetricRoutingError`

- **CI/CD**:
  - GitHub Actions workflow for testing, linting, and type checking
  - Automated PyPI publishing on version tags

### Security

- Read-only AWS permissions only (no write operations)
- No credential storage - uses standard AWS credential chain
- Cross-account access requires explicit IAM trust relationships

[Unreleased]: https://github.com/ayushgoel24/mcp-netgraph/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ayushgoel24/mcp-netgraph/releases/tag/v0.3.0 | [PyPI](https://pypi.org/project/aws-vpc-analyzer/0.3.0/)
