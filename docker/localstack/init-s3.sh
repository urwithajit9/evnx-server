# docker/localstack/init-s3.sh
#!/bin/bash
# Creates the evnx-vaults-dev S3 bucket in LocalStack on startup
awslocal s3 mb s3://evnx-vaults-dev
echo "✓ S3 bucket evnx-vaults-dev created"