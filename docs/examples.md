# NetGraph Example Prompts

This document provides example prompts for using NetGraph with Claude. Examples are organized by use case and include expected outcomes to help you validate your setup.

## Table of Contents

- [Quick Start](#quick-start)
- [Discovery & Initialization](#discovery--initialization)
- [Connectivity Analysis](#connectivity-analysis)
- [Security & Governance](#security--governance)
- [Advanced Multi-Tool Workflows](#advanced-multi-tool-workflows)
- [Troubleshooting Scenarios](#troubleshooting-scenarios)
- [Tips for Effective Prompts](#tips-for-effective-prompts)
- [Quick Reference](#quick-reference)

---

## Quick Start

### Your First Query

```
What VPCs do I have in this AWS account?
```

**Tool Used:** `list_vpcs`

This is the simplest way to verify NetGraph is working. Claude will list all VPCs with their IDs, names, CIDRs, and tags.

### Basic Connectivity Check

```
Can instance i-0abc123def456 reach 10.0.3.50 on port 5432?
```

**Tool Used:** `analyze_path`

Claude traces the complete network path, evaluating Security Groups, NACLs, and route tables at each hop.

---

## Discovery & Initialization

These examples demonstrate resource discovery and cache management.

### Example 1: Environment Discovery

**Prompt:**
```
I just deployed the "netgraph-test" environment. Please discover the VPC ID
associated with it and then pre-warm the topology cache for that VPC.
```

**Tools Used:** `list_vpcs` → `refresh_topology`

**What This Tests:**
- Tag-based VPC discovery
- Tool chaining (using output from one tool as input to another)
- Cache pre-warming

**Sample Response:**
```
Found VPC vpc-0abc123 with Environment=netgraph-test tag.

Pre-warming topology cache...

Topology Refresh Complete:
- Nodes loaded: 47
- Edges created: 62
- Instances: 8
- Subnets: 6
- Security Groups: 12
- Route Tables: 4
- Duration: 2.3 seconds

The cache is now warm. Subsequent queries will be faster.
```

---

### Example 2: Tag-Based Resource Inventory

**Prompt:**
```
List all EC2 instances in the "netgraph-test" environment.
Group them by their "Role" tag.
```

**Tool Used:** `find_resources`

**What This Tests:**
- Tag filtering with `Environment` tag
- Resource enumeration
- LLM's ability to organize results by a secondary tag

**Sample Response:**
```
Found 8 instances in netgraph-test environment:

Web Tier (Role=web):
  - i-web001 (web-server-1) - 10.0.1.10 - subnet-public-1a
  - i-web002 (web-server-2) - 10.0.1.11 - subnet-public-1b

Application Tier (Role=application):
  - i-app001 (app-server-1) - 10.0.2.10 - subnet-private-1a
  - i-app002 (app-server-2) - 10.0.2.11 - subnet-private-1b

Database Tier (Role=database):
  - i-db001 (db-primary) - 10.0.3.10 - subnet-private-db-1a
  - i-db002 (db-replica) - 10.0.3.11 - subnet-private-db-1b

Isolated (Role=isolated):
  - i-iso001 (isolated-server) - 10.0.4.10 - subnet-isolated
  - i-iso002 (bastion-host) - 10.0.4.11 - subnet-isolated
```

---

### Example 3: Finding Resources by Name Pattern

**Prompt:**
```
Find all resources in vpc-prod12345 with names starting with "api-".
```

**Tool Used:** `find_resources` with `name_pattern`

**What This Tests:**
- Glob pattern matching on Name tags
- Mixed resource type discovery

---

## Connectivity Analysis

These examples test the core `analyze_path` functionality with specific pass/fail scenarios.

### Scenario A: Security Group Reference Resolution ✅

**Prompt:**
```
Check if the Web Server can connect to the Database Server on port 5432.
```

**Expected Result:** `REACHABLE`

**Why This Is Tricky:**
The Database Security Group doesn't whitelist an IP address—it whitelists the *source Security Group* (WebSecurityGroup). NetGraph's `SecurityGroupEvaluator` must correctly resolve SG-to-SG references.

**Sample Response:**
```
✅ REACHABLE

Path Analysis:
1. Source: i-web001 (eni-abc123) in subnet-public-1a
2. Security Group Egress: sg-web allows all outbound traffic
3. Source NACL Outbound: acl-public allows TCP/5432 to 10.0.3.0/24
4. Route: 10.0.3.0/24 via local (VPC internal)
5. Destination NACL Inbound: acl-private-db allows TCP/5432
6. Security Group Ingress: sg-database allows TCP/5432 from sg-web ✓
7. Return path verified via ephemeral ports

Traffic is allowed because sg-database references sg-web as a trusted source.
```

---

### Scenario B: Port Not Allowed ❌

**Prompt:**
```
Can the Web Server SSH (port 22) into the Database Server?
```

**Expected Result:** `BLOCKED` - Destination Security Group Deny

**Why This Is Tricky:**
Both instances are in the same VPC with valid routing, but the Database Security Group only allows ports 5432 (PostgreSQL) and 3306 (MySQL). SSH is explicitly not permitted.

**Sample Response:**
```
❌ BLOCKED at Security Group sg-database

Path Analysis:
1. Source: i-web001 in subnet-public-1a
2. Security Group Egress: sg-web allows all outbound ✓
3. Source NACL Outbound: Allowed ✓
4. Route: Local VPC route ✓
5. Destination NACL Inbound: Allowed ✓
6. Security Group Ingress: sg-database DENIES TCP/22 ✗

Reason: sg-database only allows:
  - TCP/5432 from sg-web (PostgreSQL)
  - TCP/3306 from sg-app (MySQL)

SSH (port 22) is not in the allowed rules.

Remediation: If SSH access is required, add an inbound rule to sg-database
allowing TCP/22 from sg-web or a bastion security group.
```

---

### Scenario C: NAT Gateway Traversal ✅

**Prompt:**
```
Analyze the path from the App Server to 8.8.8.8 on port 443.
```

**Expected Result:** `REACHABLE`

**Why This Is Tricky:**
The App Server is in a private subnet with no direct internet access. Traffic must traverse: Instance → Private Route Table → NAT Gateway → Public Route Table → Internet Gateway. NetGraph must correctly follow this multi-hop path.

**Sample Response:**
```
✅ REACHABLE (via NAT Gateway)

Path Analysis:
1. Source: i-app001 (10.0.2.10) in subnet-private-1a
2. Security Group Egress: sg-app allows TCP/443 to 0.0.0.0/0 ✓
3. Source NACL Outbound: acl-private allows all outbound ✓
4. Route: 0.0.0.0/0 → nat-0abc123 (NAT Gateway)
5. NAT Gateway: nat-0abc123 in subnet-public-1a
6. NAT performs source address translation
7. Public Route: 0.0.0.0/0 → igw-main (Internet Gateway)
8. Traffic exits VPC to internet

Note: NetGraph verified the path to the VPC boundary.
External internet routing beyond the IGW cannot be verified.
```

---

### Scenario D: Missing Route (Isolated Subnet) ❌

**Prompt:**
```
Can the Isolated Server reach the internet at 1.1.1.1?
```

**Expected Result:** `BLOCKED` - No matching route

**Why This Is Tricky:**
The Isolated Server is in a subnet with a route table that has no default route (0.0.0.0/0). This is a common pattern for highly secured workloads that should never initiate outbound connections.

**Sample Response:**
```
❌ BLOCKED at Route Table rtb-isolated

Path Analysis:
1. Source: i-iso001 (10.0.4.10) in subnet-isolated
2. Security Group Egress: sg-isolated allows all outbound ✓
3. Source NACL Outbound: acl-isolated allows all outbound ✓
4. Route Lookup: No route to 1.1.1.1 ✗

Route Table rtb-isolated contains:
  - 10.0.0.0/16 → local
  - (no default route)

Reason: subnet-isolated intentionally has no internet route.
This is a security feature for isolated workloads.

If internet access is required:
1. Add NAT Gateway route: 0.0.0.0/0 → nat-gateway-id
2. Or move the instance to a subnet with internet access
```

---

### Scenario E: Cross-Subnet Same VPC ✅

**Prompt:**
```
Verify that the application tier can connect to the database tier on port 3306.
```

**Expected Result:** `REACHABLE`

**Sample Response:**
```
✅ REACHABLE

Path: i-app001 (10.0.2.10) → i-db001 (10.0.3.10) on TCP/3306

All checks passed:
- SG egress: sg-app allows TCP/3306 to 10.0.3.0/24 ✓
- NACL outbound: acl-private allows ✓
- Route: local (same VPC) ✓
- NACL inbound: acl-private-db allows TCP/3306 ✓
- SG ingress: sg-database allows TCP/3306 from sg-app ✓
- Return path: Ephemeral ports allowed ✓
```

---

### Scenario F: VPC Peering Connectivity ✅

**Prompt:**
```
Can the monitoring server i-monitor001 in vpc-tools reach the
application server at 172.16.2.50 in vpc-production?
```

**Expected Result:** `REACHABLE` (if peering is configured correctly)

**Why This Is Tricky:**
Cross-VPC connectivity requires:
1. VPC Peering connection in "active" state
2. Route table entries in both VPCs pointing to the peering connection
3. Security Groups allowing cross-VPC CIDR ranges
4. NACLs permitting the traffic

**Sample Response:**
```
✅ REACHABLE via VPC Peering

Path Analysis:
1. Source: i-monitor001 (10.0.1.10) in vpc-tools
2. SG egress: Allows all to 172.16.0.0/16 ✓
3. Route: 172.16.0.0/16 → pcx-peer12345 (VPC Peering)
4. Peering Connection: pcx-peer12345 (active) ✓
5. Peer VPC Route: 10.0.0.0/16 → pcx-peer12345 (return path) ✓
6. Destination: 172.16.2.50 in vpc-production
7. Destination SG: Allows TCP from 10.0.0.0/16 ✓

Bidirectional routing confirmed.
```

---

## Security & Governance

These examples focus on security auditing and compliance checks.

### Scenario G: Finding Public Exposure ("Shadow IT")

**Prompt:**
```
Scan the netgraph-test VPC for any resources exposed to the
public internet on port 22 (SSH).
```

**Tool Used:** `find_public_exposure`

**What This Tests:**
Complete exposure analysis including: Internet Gateway → Route Table → Subnet → NACL → Security Group chain.

**Expected Result:** Only resources in public subnets with open SG rules should appear.

**Sample Response:**
```
Public Exposure Scan Results for vpc-netgraph-test on TCP/22:

⚠️ CRITICAL: 1 resource exposed

1. i-web001 (web-server-1)
   - Private IP: 10.0.1.10
   - Public IP: 54.123.45.67
   - Subnet: subnet-public-1a
   - Exposure Path: eni-abc123 → subnet-public-1a → igw-main
   - Allowing Rule: sgr-0abc123 in sg-web
     └─ Allows: TCP/22 from 0.0.0.0/0 (DANGEROUS)
   - Severity: CRITICAL

Remediation:
1. Restrict SSH access to known IP ranges (e.g., office CIDR)
2. Consider using AWS Systems Manager Session Manager instead
3. Implement a bastion host pattern

Resources NOT exposed (in private subnets):
- i-app001, i-app002 (no IGW route)
- i-db001, i-db002 (no IGW route)
- i-iso001 (no internet route at all)
```

---

### Scenario H: NACL Explicit Deny ❌

**Prompt:**
```
Check connectivity from the Web Server to the Isolated Server on port 80.
```

**Expected Result:** `BLOCKED` - Destination NACL Inbound Deny

**Why This Is Tricky:**
The Isolated Server is protected by a restrictive NACL with explicit DENY rules. Even if Security Groups would allow the traffic, the NACL blocks it first (NACLs are evaluated before SGs for inbound traffic).

**Sample Response:**
```
❌ BLOCKED at NACL acl-isolated (inbound)

Path Analysis:
1. Source: i-web001 in subnet-public-1a
2. Security Group Egress: sg-web allows ✓
3. Source NACL Outbound: acl-public allows ✓
4. Route: 10.0.4.0/24 via local ✓
5. Destination NACL Inbound: acl-isolated DENIES ✗

NACL acl-isolated rules:
  Rule 50: DENY TCP 0-65535 from 0.0.0.0/0  ← MATCHED
  Rule 100: ALLOW TCP 22 from 10.0.5.0/24 (bastion only)
  Rule *: DENY all (implicit)

Reason: The isolated subnet's NACL explicitly denies all inbound
traffic except SSH from the bastion subnet.

This is intentional security isolation. If connectivity is required,
the NACL rules must be modified by your network administrator.
```

---

### Scenario I: Database Port Audit

**Prompt:**
```
Audit vpc-prod12345 for any resources exposed to the public internet
on database ports: 3306 (MySQL), 5432 (PostgreSQL), 1433 (SQL Server),
27017 (MongoDB), and 6379 (Redis).
```

**Tools Used:** Multiple `find_public_exposure` calls

**Sample Response:**
```
Database Port Security Audit for vpc-prod12345:

┌─────────────────┬────────┬──────────────────────────────┐
│ Port            │ Status │ Finding                      │
├─────────────────┼────────┼──────────────────────────────┤
│ 3306 (MySQL)    │ ✓ SAFE │ No public exposure           │
│ 5432 (Postgres) │ ✓ SAFE │ No public exposure           │
│ 1433 (SQL Srv)  │ ✓ SAFE │ No public exposure           │
│ 27017 (MongoDB) │ ✓ SAFE │ No public exposure           │
│ 6379 (Redis)    │ ⚠️ RISK │ 1 resource exposed          │
└─────────────────┴────────┴──────────────────────────────┘

FINDING: Redis exposure detected

Instance: i-cache001 (redis-cache)
- Public IP: 54.200.100.50
- Allowing rule: sg-cache allows TCP/6379 from 0.0.0.0/0

IMMEDIATE ACTIONS REQUIRED:
1. Remove public IP or move to private subnet
2. Restrict sg-cache to application tier security group only
3. Enable Redis AUTH if not already configured
```

---

## Advanced Multi-Tool Workflows

These examples demonstrate sophisticated prompts that require chaining multiple tools.

### Workflow 1: Diagnose & Explain

**Prompt:**
```
I'm troubleshooting the "netgraph-test" stack. Find the instance with
the role "isolated", check if it can reach the database on port 5432,
and if not, explain exactly which security control is blocking it.
```

**Tool Chain:**
1. `find_resources(tags={"Role": "isolated"})` → Gets isolated instance ID
2. `find_resources(tags={"Role": "database"})` → Gets database instance IP
3. `analyze_path(source=isolated_id, dest=db_ip, port=5432)` → Analyzes connectivity

**Sample Response:**
```
Investigation Results:

Step 1: Found isolated instance
- i-iso001 (isolated-server) at 10.0.4.10

Step 2: Found database instance
- i-db001 (db-primary) at 10.0.3.10

Step 3: Path Analysis
❌ BLOCKED at NACL acl-isolated (outbound)

Root Cause Analysis:
The isolated subnet's NACL (acl-isolated) blocks outbound traffic
to the database subnet:

  Rule 50: DENY TCP 0-65535 to 10.0.3.0/24  ← BLOCKS DB ACCESS
  Rule 100: ALLOW TCP 443 to 0.0.0.0/0 (HTTPS only)
  Rule *: DENY all

The isolated server can only make HTTPS requests. Database
connectivity is explicitly blocked by network policy.

This appears to be intentional isolation. If database access
is required, consult your network security team about modifying
acl-isolated or relocating the workload.
```

---

### Workflow 2: Ops Health Check

**Prompt:**
```
Check the health of my graph cache. If the hit rate is below 70%,
refresh the topology for the netgraph-test VPC.
```

**Tool Chain:**
1. `get_cache_stats()` → Check current cache health
2. (Conditional) `list_vpcs(tags={"Environment": "netgraph-test"})` → Get VPC ID
3. (Conditional) `refresh_topology(vpc_ids=[...])` → Refresh if needed

**Sample Response:**
```
Cache Health Check:

Current Statistics:
- Cache entries: 12
- Hits: 45
- Misses: 38
- Hit rate: 54.2% ⚠️ (below 70% threshold)
- TTL: 60 seconds

Hit rate is low. Refreshing topology...

Found VPC: vpc-0abc123 (netgraph-test)

Topology Refresh Complete:
- Nodes loaded: 47
- Edges created: 62
- Duration: 2.1 seconds

New cache statistics:
- Cache entries: 47
- Hit rate will improve on subsequent queries
```

---

### Workflow 3: Pre-Deployment Checklist

**Prompt:**
```
I'm deploying a new microservice to the app tier. Verify that:
1. It can reach the database on port 5432
2. It can reach Redis cache on port 6379
3. It can reach external API at api.stripe.com on port 443
4. The web tier can reach it on port 8080

Use the app server i-app001 as a reference point.
```

**Tool Chain:** Multiple `analyze_path` calls

**Sample Response:**
```
Pre-Deployment Network Validation:

┌────────────────────────────────────────┬────────────┬─────────────────┐
│ Connectivity Requirement               │ Status     │ Notes           │
├────────────────────────────────────────┼────────────┼─────────────────┤
│ App → Database (5432)                  │ ✅ PASS    │ SG-to-SG ref    │
│ App → Redis (6379)                     │ ✅ PASS    │ Same subnet     │
│ App → api.stripe.com (443)             │ ✅ PASS    │ Via NAT Gateway │
│ Web → App (8080)                       │ ✅ PASS    │ Cross-subnet OK │
└────────────────────────────────────────┴────────────┴─────────────────┘

All connectivity requirements validated! ✓

Details:
1. Database: Traffic allowed via sg-database referencing sg-app
2. Redis: Local subnet routing, sg-cache allows from sg-app
3. External API: Routes through nat-0abc123, exits via igw-main
4. Inbound from Web: sg-app allows TCP/8080 from sg-web

Your microservice deployment should have full network connectivity.
```

---

### Workflow 4: Security Incident Response

**Prompt:**
```
Security alert: We detected suspicious outbound traffic from the
database tier. Verify what external connectivity the database
servers have and identify any unexpected exposure.
```

**Tool Chain:**
1. `find_resources(tags={"Role": "database"})` → Find all DB instances
2. `analyze_path` to common external destinations (8.8.8.8, etc.)
3. `find_public_exposure` on database ports

**Sample Response:**
```
Database Tier Security Assessment:

Database Instances Found:
- i-db001 (db-primary) - 10.0.3.10
- i-db002 (db-replica) - 10.0.3.11

Outbound Connectivity Analysis:

1. Internet Access (8.8.8.8:443):
   ❌ BLOCKED - No route to internet
   Database subnet has no NAT Gateway route ✓ (EXPECTED)

2. Internal Network (10.0.0.0/16):
   ✅ ALLOWED - Can reach other internal subnets
   This is normal for database replication and app connectivity

Public Exposure Check:
- Port 5432: Not exposed ✓
- Port 3306: Not exposed ✓

Assessment: Database tier is properly isolated.
- No internet egress capability
- No public ingress exposure

The suspicious traffic alert may be:
1. False positive (internal traffic misclassified)
2. Originating from a different resource
3. DNS resolution traffic (if allowed)

Recommend checking VPC Flow Logs for the specific traffic pattern.
```

---

## Troubleshooting Scenarios

### Intermittent Connection Failures (NACL Return Path)

**Prompt:**
```
Users report intermittent TCP timeouts from web tier to app tier.
Web server is i-web001, app server is at 10.0.2.50 port 8080.
Could there be a NACL issue with return traffic?
```

**What This Tests:** NACL stateless behavior and ephemeral port handling

**Sample Response:**
```
Analysis reveals a NACL return path issue!

Forward Path: ✅ ALLOWED
- SG egress: sg-web allows TCP/8080 ✓
- NACL outbound: acl-public allows ✓
- Route: Local VPC ✓
- NACL inbound: acl-private allows TCP/8080 ✓
- SG ingress: sg-app allows TCP/8080 from sg-web ✓

Return Path: ❌ PARTIALLY BLOCKED
- App subnet NACL outbound check...
- acl-private Rule 100: Allow TCP 8080 only
- acl-private Rule *: Deny all

PROBLEM FOUND: Ephemeral ports blocked!

NACLs are STATELESS. Return traffic uses ephemeral ports
(1024-65535), but acl-private only allows port 8080 outbound.

This causes intermittent failures because:
- Connections using source port 8080 succeed (rare)
- Connections using other source ports fail (common)

Fix: Add to acl-private outbound rules:
  Rule 110: Allow TCP 1024-65535 to 10.0.1.0/24

This allows return traffic on ephemeral ports to the web subnet.
```

---

### Asymmetric Routing Detection

**Prompt:**
```
We have VPC peering between vpc-app and vpc-shared-services.
Traffic from vpc-app reaches vpc-shared-services, but responses
seem to be dropped. Check for asymmetric routing.
```

**What This Tests:** Bidirectional route verification

**Sample Response:**
```
Asymmetric Routing Analysis:

Forward Path (vpc-app → vpc-shared-services):
✅ Route exists: 172.16.0.0/16 → pcx-peer123

Return Path (vpc-shared-services → vpc-app):
❌ NO ROUTE FOUND

vpc-shared-services route table rtb-shared:
- 172.16.0.0/16 → local
- 0.0.0.0/0 → igw-shared
- (missing: 10.0.0.0/16 → pcx-peer123)

PROBLEM: Asymmetric routing detected!

Traffic reaches vpc-shared-services, but responses cannot
return because there's no route back to vpc-app's CIDR.

Fix: Add route to rtb-shared in vpc-shared-services:
  Destination: 10.0.0.0/16
  Target: pcx-peer123
```

---

## Tips for Effective Prompts

### Be Specific with Resource Identifiers

| Instead of... | Use... |
|---------------|--------|
| "Check if web can reach database" | "Can i-web001 reach 10.0.3.50 on port 5432?" |
| "Find my servers" | "Find instances in vpc-abc123 with Role=web tag" |
| "Is anything exposed?" | "Find resources in vpc-abc123 exposed on port 22" |

### Always Specify Ports and Protocols

```
❌ "Can server A connect to server B?"
✅ "Can server A connect to server B on TCP port 443?"
```

### Mention Your Suspicions

```
❌ "Why can't my app connect?"
✅ "Why can't i-app001 connect to 10.0.2.50:8080? I suspect NACL issues."
```

### Request Fresh Data After Changes

```
"I just updated sg-web. Re-analyze the path from i-web001 to
10.0.3.50:5432 with force_refresh=true"
```

### Use Tags for Discovery

```
"Find all instances with Environment=production and Team=platform"
```

---

## Quick Reference

| Use Case | Prompt Template |
|----------|-----------------|
| List VPCs | `"List my VPCs"` or `"Find VPC with tag Environment=prod"` |
| Connectivity check | `"Can {instance_id} reach {ip} on port {port}?"` |
| Security audit | `"Find resources in {vpc_id} exposed on port {port}"` |
| Resource discovery | `"Find instances in {vpc_id} with {tag}={value}"` |
| Pre-deployment | `"Verify {source} can reach {dest} on port {port}"` |
| Troubleshooting | `"Why can't {source} reach {dest}:{port}? Check NACLs"` |
| Cache refresh | `"Refresh topology for {vpc_id}"` or use `force_refresh=true` |
| Multi-port audit | `"Scan {vpc_id} for exposure on ports 22, 3306, 5432"` |
| Cross-VPC check | `"Can {instance} in {vpc1} reach {ip} in {vpc2}?"` |

---

## Tool Reference

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `list_vpcs` | Find VPCs by name/tags | `name_pattern`, `tags`, `cidr` |
| `find_resources` | Discover resources | `vpc_id`, `tags`, `resource_types`, `name_pattern` |
| `analyze_path` | Check connectivity | `source_id`, `destination_ip`, `port`, `protocol` |
| `find_public_exposure` | Security scanning | `vpc_id`, `port`, `protocol` |
| `refresh_topology` | Pre-warm cache | `vpc_ids` |
| `get_cache_stats` | Monitor performance | (none) |
