# Common AWS APIs for Reconnaissance Activity

This reference lists AWS API calls frequently observed in reconnaissance scans, where an actor queries services and resources to map an environment. ReconRaptor will search for the use of these APIs and their frequencies to detect recon scans in CloudTrail logs. It focuses on **information-gathering** actions, not on APIs used for later-stage attacks (e.g., key changes, data modification).

---

## EC2 & Compute Reconnaissance
- `DescribeInstances` – Lists EC2 instances and configurations.
- `DescribeSecurityGroups` – Reveals security group rules and open ports.
- `DescribeVpcs` – Shows VPC configurations and network topology.
- `DescribeRegions` – Discovers available AWS regions.
- `DescribeAvailabilityZones` – Maps infrastructure layout.
- `DescribeImages` – Lists available AMIs and configurations.
- `DescribeKeyPairs` – Shows SSH key pairs for access.
- `DescribeVolumes` – Lists EBS volumes and their attachments.
- `DescribeSnapshots` – Shows EBS snapshots and permissions.
- `DescribeNetworkInterfaces` – Reveals network interface configurations.
- `DescribeRouteTables` – Shows routing configurations.
- `DescribeInternetGateways` – Lists internet gateways.
- `DescribeNetworkAcls` – Shows network ACL configurations.
- `DescribeSubnets` – Lists subnet configurations.
- `DescribeAddresses` – Shows Elastic IP addresses.
- `DescribeLoadBalancers` – Lists load balancer configurations.
- `DescribeAutoScalingGroups` – Shows scaling group configurations.

## S3 & Storage Reconnaissance
- `ListBuckets` – Lists all S3 buckets in the account.
- `ListObjects` – Enumerates contents of a bucket.
- `ListObjectsV2` – Modern version of `ListObjects`.
- `GetBucketPolicy` – Reveals bucket access policies.
- `GetBucketPublicAccessBlock` – Shows public access settings.
- `GetBucketVersioning` – Shows versioning configuration.
- `GetBucketEncryption` – Shows encryption settings.
- `GetBucketLocation` – Shows bucket region.
- `GetBucketTagging` – Shows bucket tags.
- `GetBucketAcl` – Shows access control list.
- `GetBucketCors` – Shows CORS configuration.
- `GetBucketLifecycle` – Shows lifecycle policies.
- `GetBucketReplication` – Shows replication configuration.

## IAM & Identity Reconnaissance
- `ListUsers` – Lists IAM users.
- `ListRoles` – Lists IAM roles.
- `ListGroups` – Lists IAM groups.
- `ListPolicies` – Lists IAM policies.
- `ListAttachedUserPolicies` – Shows policies attached to a user.
- `ListAttachedRolePolicies` – Shows policies attached to a role.
- `ListAttachedGroupPolicies` – Shows policies attached to a group.
- `GetUser` – Gets details of a user.
- `GetRole` – Gets details of a role.
- `GetGroup` – Gets details of a group.
- `GetPolicy` – Gets details of a policy.
- `GetPolicyVersion` – Gets policy document content.
- `ListAccessKeys` – Shows access keys for users.
- `ListMFADevices` – Lists MFA devices.
- `ListServiceSpecificCredentials` – Lists service-specific credentials.

## Database & Data Reconnaissance
- `DescribeDBInstances` – Lists RDS instances.
- `DescribeDBClusters` – Lists RDS clusters.
- `DescribeDBSnapshots` – Shows RDS snapshots.
- `DescribeDBSubnetGroups` – Shows RDS subnet groups.
- `DescribeDBParameterGroups` – Shows RDS parameter groups.
- `DescribeDBEngineVersions` – Shows available RDS engine versions.
- `ListTables` – Lists DynamoDB tables.
- `DescribeTable` – Shows DynamoDB table schema.
- `ListFunctions` – Lists Lambda functions.
- `GetFunction` – Gets Lambda function details.
- `ListEventSourceMappings` – Shows Lambda event sources.

## Network & Security Reconnaissance
- `DescribeVpcPeeringConnections` – Lists VPC peering connections.
- `DescribeVpcEndpoints` – Lists VPC endpoints.
- `DescribeTransitGateways` – Lists transit gateways.
- `DescribeDirectConnectGateways` – Lists Direct Connect gateways.
- `DescribeVpnConnections` – Lists VPN connections.
- `DescribeCustomerGateways` – Lists customer gateways.
- `DescribeVpnGateways` – Lists VPN gateways.

## Monitoring & Logging Reconnaissance
- `DescribeLogGroups` – Lists CloudWatch log groups.
- `DescribeLogStreams` – Lists CloudWatch log streams.
- `DescribeAlarms` – Lists CloudWatch alarms.
- `DescribeMetrics` – Lists CloudWatch metrics.
- `ListTrails` – Lists CloudTrail trails.
- `GetTrail` – Gets CloudTrail configuration.
- `GetEventSelectors` – Shows CloudTrail event selectors.

## Other Services Reconnaissance
- `ListTopics` – Lists SNS topics.
- `ListSubscriptions` – Lists SNS subscriptions.
- `ListQueues` – Lists SQS queues.
- `GetQueueAttributes` – Gets SQS queue attributes.
- `ListDistributions` – Lists CloudFront distributions.
- `GetDistribution` – Gets CloudFront distribution details.
- `ListHostedZones` – Lists Route 53 hosted zones.
- `ListResourceRecordSets` – Lists DNS records in Route 53.
- `ListKeys` – Lists KMS keys.
- `DescribeKey` – Gets KMS key details.
- `ListSecrets` – Lists AWS Secrets Manager secrets.
- `DescribeSecret` – Gets AWS Secrets Manager secret details.

## Configuration & Compliance Reconnaissance
- `ListConfigurationRecorders` – Lists AWS Config recorders.
- `ListConfigRules` – Lists AWS Config rules.
- `ListConfigRuleEvaluationResults` – Shows Config compliance results.
- `ListDetectors` – Lists GuardDuty detectors.
- `GetDetector` – Gets GuardDuty detector details.
- `ListFindings` – Lists GuardDuty findings.

---

*Note:* This list is not exhaustive. Reconnaissance can involve other AWS APIs, depending on the target environment and attacker objectives.

