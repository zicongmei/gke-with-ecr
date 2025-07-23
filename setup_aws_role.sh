#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

AWS_ROLE_NAME="gke-role-1"
GCP_SERVICE_ACCOUNT_EMAIL="565326050482-compute@developer.gserviceaccount.com"

OIDC_PROVIDER_URL="https://accounts.google.com"
OIDC_CLIENT_ID="sts.amazonaws.com"
GOOGLE_ROOT_CA_THUMBPRINT="08e4f16a75f048d0a0d3f7f14b64f20f01968848"

echo "Starting AWS IAM Role and OIDC Provider configuration for GCP Service Account..."
echo "AWS Role Name: ${AWS_ROLE_NAME}"
echo "GCP Service Account Email: ${GCP_SERVICE_ACCOUNT_EMAIL}"
echo "OIDC Provider URL: ${OIDC_PROVIDER_URL}"

# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Error: Could not retrieve AWS Account ID. Please ensure AWS CLI is configured and authenticated."
    exit 1
fi
echo "Retrieved AWS Account ID: ${AWS_ACCOUNT_ID}"

# Define the AWS OIDC Provider ARN based on the AWS Account ID and OIDC URL
# The OIDC provider ARN format is arn:aws:iam::ACCOUNT_ID:oidc-provider/URL_HOSTNAME
AWS_OIDC_PROVIDER_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER_URL#https://}"

# 1. Create the AWS IAM Role
echo "Checking if AWS IAM Role '${AWS_ROLE_NAME}' already exists..."
if aws iam get-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
    echo "IAM Role '${AWS_ROLE_NAME}' already exists. Skipping creation."
    # Even if it exists, we might want to ensure its trust policy is correct.
    # For this script, we assume if it exists, it's configured or will be manually updated.
    # If the trust policy needs updating, you would use `aws iam update-assume-role-policy`.
else
    echo "IAM Role '${AWS_ROLE_NAME}' does not exist. Creating..."

    # Define the Trust Policy for the IAM Role
    # This policy allows the OIDC provider to assume the role, with conditions
    # ensuring the request comes from the specific GCP Service Account.
    TRUST_POLICY_JSON=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "${AWS_OIDC_PROVIDER_ARN}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER_URL#https://}:aud": "${OIDC_CLIENT_ID}",
          "${OIDC_PROVIDER_URL#https://}:sub": "${GCP_SERVICE_ACCOUNT_EMAIL}"
        }
      }
    }
  ]
}
EOF
)
    echo "Generated Trust Policy for role:"
    # Using jq for pretty printing if available, otherwise raw output
    if command -v jq &>/dev/null; then
        echo "${TRUST_POLICY_JSON}" | jq .
    else
        echo "${TRUST_POLICY_JSON}"
    fi

    # Create the role with the defined trust policy
    if ! aws iam create-role \
        --role-name "${AWS_ROLE_NAME}" \
        --assume-role-policy-document "${TRUST_POLICY_JSON}" \
        --description "IAM Role for GCP Service Account (${GCP_SERVICE_ACCOUNT_EMAIL}) to assume via OIDC" &>/dev/null; then
        echo "Error: Failed to create IAM Role '${AWS_ROLE_NAME}'."
        exit 1
    fi
    echo "IAM Role '${AWS_ROLE_NAME}' created successfully."
fi

# 2. Create an AWS OIDC Provider
echo "Checking if AWS OIDC Provider for '${OIDC_PROVIDER_URL}' already exists..."
# List OIDC providers and check if one with our URL exists
if aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?Url=='${OIDC_PROVIDER_URL}'].Arn" --output text | grep -q "${OIDC_PROVIDER_URL}"; then
    echo "OIDC Provider for '${OIDC_PROVIDER_URL}' already exists. Skipping creation."
else
    echo "OIDC Provider for '${OIDC_PROVIDER_URL}' does not exist. Creating..."
    # Create the OIDC provider with Google's OIDC URL, sts.amazonaws.com as client ID, and the root CA thumbprint
    if ! aws iam create-open-id-connect-provider \
        --url "${OIDC_PROVIDER_URL}" \
        --client-id-list "${OIDC_CLIENT_ID}" \
        --thumbprint-list "${GOOGLE_ROOT_CA_THUMBPRINT}" &>/dev/null; then
        echo "Error: Failed to create OIDC Provider for '${OIDC_PROVIDER_URL}'."
        exit 1
    fi
    echo "OIDC Provider for '${OIDC_PROVIDER_URL}' created successfully."
fi

echo "AWS IAM Role and OIDC Provider setup complete!"
echo "------------------------------------------------------------"
echo "Next Steps:"
echo "1. Attach necessary permission policies to the role '${AWS_ROLE_NAME}'."
echo "   Example: To grant ECR read-only access:"
echo "   aws iam attach-role-policy --role-name ${AWS_ROLE_NAME} --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
echo "2. In your GCP environment (e.g., GKE Workload Identity or a compute instance),"
echo "   configure your service account to use this AWS role ARN for federated authentication."
echo ""

# Optional: Output the Role ARN for convenience
AWS_ROLE_ARN=$(aws iam get-role --role-name "${AWS_ROLE_NAME}" --query Role.Arn --output text 2>/dev/null)
if [ -n "$AWS_ROLE_ARN" ]; then
    echo "AWS Role ARN for ${AWS_ROLE_NAME}: ${AWS_ROLE_ARN}"
fi
echo "AWS OIDC Provider ARN: ${AWS_OIDC_PROVIDER_ARN}"