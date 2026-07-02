# Deploy The IDS On AWS

This project must run on an EC2 instance because Scapy requires raw-packet
access. The deployed detector observes traffic entering and leaving that EC2
instance. It cannot capture traffic from your home WiFi or another network
unless that traffic is mirrored or forwarded to EC2.

## Recommended Architecture

- Ubuntu EC2 instance using host networking for Scapy
- Streamlit dashboard on TCP port `8501`
- PostgreSQL container bound only to `127.0.0.1:5432`
- Encrypted EBS volume for PostgreSQL data
- AWS Systems Manager Session Manager for shell access

Automatic blocking is disabled by default. Enable it only after validating the
rules because the container has `NET_ADMIN` capability.

## CloudFormation Deployment

Push this project to a public Git repository, find your current public IP, and
deploy the template:

From Windows PowerShell, the helper automatically detects your public IP:

```powershell
.\deploy\aws\deploy.ps1 `
  -GitRepository "https://github.com/YOUR_USER/YOUR_REPOSITORY.git" `
  -VpcId "vpc-xxxxxxxx" `
  -PublicSubnetId "subnet-xxxxxxxx"
```

Or run the AWS CLI command directly:

```bash
aws cloudformation deploy \
  --stack-name network-intrusion-detection \
  --template-file deploy/aws/cloudformation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitRepository=https://github.com/YOUR_USER/YOUR_REPOSITORY.git \
    GitBranch=main \
    AllowedDashboardCidr=YOUR_PUBLIC_IP/32 \
    VpcId=vpc-xxxxxxxx \
    PublicSubnetId=subnet-xxxxxxxx
```

Use a public subnet that assigns public IPv4 addresses and routes outbound
traffic through an internet gateway.

Get the dashboard URL:

```bash
aws cloudformation describe-stacks \
  --stack-name network-intrusion-detection \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" \
  --output text
```

The initial Docker build can take several minutes. Check it through Session
Manager:

```bash
aws ssm start-session --target INSTANCE_ID
cd /opt/network-intrusion-detection
sudo docker compose --env-file .env.aws -f docker-compose.aws.yml ps
sudo docker compose --env-file .env.aws -f docker-compose.aws.yml logs -f dashboard
```

## Deploy To An Existing Ubuntu EC2 Instance

Clone the project, then run:

```bash
cd network-intrusion-detection
sudo bash deploy/aws/install_ec2.sh
```

The installer generates `.env.aws`, starts PostgreSQL, builds the dashboard,
and configures both containers to restart automatically.

## Production Hardening

- Restrict `AllowedDashboardCidr` to trusted `/32` addresses.
- Put an HTTPS reverse proxy or authenticated load balancer in front of port
  `8501` before sharing the dashboard.
- Store API and alert credentials in AWS Secrets Manager or SSM Parameter Store.
- Back up the `postgres_data` Docker volume or move PostgreSQL to Amazon RDS.
- Use VPC Traffic Mirroring when monitoring traffic from other EC2 instances.
