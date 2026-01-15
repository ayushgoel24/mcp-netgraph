# IAM Policy for NetGraph

This document provides IAM policies for NetGraph. All policies are **read-only** - NetGraph never modifies your AWS resources.

## Quick Start Policy

Copy and paste this policy for basic usage:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetGraphReadOnly",
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

## Creating the Policy

### Via AWS Console

1. Go to **IAM** > **Policies** > **Create policy**
2. Select the **JSON** tab
3. Paste the policy above
4. Click **Next**
5. Name it `NetGraphReadOnly`
6. Click **Create policy**
7. Attach to your IAM user or role

### Via AWS CLI

```bash
# Create the policy
aws iam create-policy \
  --policy-name NetGraphReadOnly \
  --policy-document file://netgraph-policy.json

# Attach to a user
aws iam attach-user-policy \
  --user-name YOUR_USER \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/NetGraphReadOnly

# Or attach to a role
aws iam attach-role-policy \
  --role-name YOUR_ROLE \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/NetGraphReadOnly
```

### Via CloudFormation

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: IAM policy for NetGraph MCP server

Resources:
  NetGraphPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: NetGraphReadOnly
      Description: Read-only EC2 permissions for NetGraph VPC analysis
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: NetGraphReadOnly
            Effect: Allow
            Action:
              - ec2:DescribeInstances
              - ec2:DescribeNetworkInterfaces
              - ec2:DescribeSubnets
              - ec2:DescribeSecurityGroups
              - ec2:DescribeNetworkAcls
              - ec2:DescribeRouteTables
              - ec2:DescribeInternetGateways
              - ec2:DescribeNatGateways
              - ec2:DescribeVpcs
              - ec2:DescribeVpcPeeringConnections
              - ec2:DescribeTransitGateways
              - ec2:DescribeTransitGatewayAttachments
              - ec2:GetManagedPrefixListEntries
            Resource: '*'

Outputs:
  PolicyArn:
    Description: ARN of the NetGraph policy
    Value: !Ref NetGraphPolicy
```

### Via Terraform

```hcl
resource "aws_iam_policy" "netgraph" {
  name        = "NetGraphReadOnly"
  description = "Read-only EC2 permissions for NetGraph VPC analysis"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "NetGraphReadOnly"
        Effect = "Allow"
        Action = [
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
          "ec2:GetManagedPrefixListEntries",
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach to an existing role
resource "aws_iam_role_policy_attachment" "netgraph" {
  role       = aws_iam_role.your_role.name
  policy_arn = aws_iam_policy.netgraph.arn
}
```

## Cross-Account Access

To analyze VPCs in multiple AWS accounts, you need additional setup.

### 1. Create Role in Target Account

In each target account, create an IAM role with:

**Trust Policy** (allows your source account to assume the role):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "netgraph-cross-account"
        }
      }
    }
  ]
}
```

**Permission Policy**: Use the same NetGraph read-only policy from above.

### 2. Add AssumeRole Permission to Source Account

Add this to your source account credentials:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetGraphAssumeRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::TARGET_ACCOUNT_1:role/NetGraphRole",
        "arn:aws:iam::TARGET_ACCOUNT_2:role/NetGraphRole"
      ]
    }
  ]
}
```

### 3. Configure NetGraph

Set the `NETGRAPH_ROLE_ARN` environment variable:

```json
{
  "mcpServers": {
    "netgraph": {
      "command": "mcp-netgraph",
      "env": {
        "AWS_PROFILE": "my-profile",
        "NETGRAPH_ROLE_ARN": "arn:aws:iam::TARGET_ACCOUNT:role/NetGraphRole"
      }
    }
  }
}
```

## Permission Explanations

| Permission | Purpose |
|------------|---------|
| `DescribeInstances` | Get EC2 instance details, IPs, and security groups |
| `DescribeNetworkInterfaces` | Get ENI details for network path tracing |
| `DescribeSubnets` | Get subnet CIDRs and route table associations |
| `DescribeSecurityGroups` | Evaluate security group rules |
| `DescribeNetworkAcls` | Evaluate NACL rules (stateless, requires return path check) |
| `DescribeRouteTables` | Determine next hop via Longest Prefix Match |
| `DescribeInternetGateways` | Identify public internet access points |
| `DescribeNatGateways` | Trace NAT gateway paths for private subnets |
| `DescribeVpcs` | List and search VPCs |
| `DescribeVpcPeeringConnections` | Trace cross-VPC paths |
| `DescribeTransitGateways` | Identify TGW routing (limited support) |
| `DescribeTransitGatewayAttachments` | Get TGW attachment details |
| `GetManagedPrefixListEntries` | Resolve managed prefix lists in security group rules |

## Restricting by VPC (Optional)

If you want to limit NetGraph to specific VPCs, you can use resource-level conditions. Note that not all EC2 describe actions support resource-level permissions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetGraphRestrictedVPC",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:Vpc": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678"
        }
      }
    },
    {
      "Sid": "NetGraphGlobalDescribe",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
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

## Security Best Practices

1. **Use IAM roles over access keys** when possible
2. **Scope to specific regions** if you don't need global access
3. **Enable CloudTrail** to audit NetGraph API calls
4. **Use separate credentials** for production vs development VPCs
5. **Rotate credentials regularly** if using access keys
6. **Use AWS Organizations SCPs** to enforce boundaries in multi-account setups

## Troubleshooting

### "Access Denied" Errors

1. Verify the policy is attached:
   ```bash
   aws iam list-attached-user-policies --user-name YOUR_USER
   ```

2. Test a specific permission:
   ```bash
   aws ec2 describe-vpcs --profile your-profile
   ```

3. Check for deny policies that might override allows

### "UnauthorizedOperation" Errors

This usually means you're missing a specific permission. Check the error message for which action is denied and add it to your policy.

### Cross-Account "Access Denied"

1. Verify the trust policy in the target account role
2. Verify the source account has `sts:AssumeRole` permission
3. Check the external ID matches (if configured)
4. Verify the role ARN is correct
