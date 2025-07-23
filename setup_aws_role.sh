#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

AWS_ROLE_NAME_PREFIX="gke-role" # Use a prefix as the name might not be fixed but derived from ARN

GCP_PROJECT_ID=$(gcloud config get-value project)
GCP_PROJECT_NUMBER=$(gcloud projects describe ${GCP_PROJECT_ID} --format="value(projectNumber)")
GCP_SERVICE_ACCOUNT_EMAIL="${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

OIDC_PROVIDER_URL="https://accounts.google.com" # Changed to accounts.google.com
OIDC_CLIENT_ID="sts.amazonaws.com"
GOOGLE_ROOT_CA_THUMBPRINT="08e4f16a75f048d0a0d3f7f14b64f20f01968848" # Updated for accounts.google.com

# Define the status directory and file
STATUS_DIR=".status"
STATUS_FILE="${STATUS_DIR}/aws_role_info.txt"

echo "Starting AWS IAM Role and OIDC Provider configuration for GCP Service Account..."
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

# Derive a unique role name based on project ID and a timestamp or fixed suffix
# Using a fixed name for simplicity as per original, but good to be aware.
AWS_ROLE_NAME="${AWS_ROLE_NAME_PREFIX}-1" # Keeping original role name for consistency with existing script logic

# 1. Create the AWS IAM Role
echo "Checking if AWS IAM Role '${AWS_ROLE_NAME}' already exists..."
if aws iam get-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
    echo "IAM Role '${AWS_ROLE_NAME}' already exists. Skipping creation."
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

# Add ECR Pull permissions to the role
ECR_READ_POLICY_ARN="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
ECR_READ_POLICY_NAME="AmazonECRContainerRegistryReadOnly" # Corrected policy name for clarity based on ARN

echo "Attempting to attach ECR read-only policy '${ECR_READ_POLICY_NAME}' to role '${AWS_ROLE_NAME}'..."

# Check if the policy is already attached
if aws iam list-attached-role-policies --role-name "${AWS_ROLE_NAME}" --query "AttachedPolicies[?PolicyName=='${ECR_READ_POLICY_NAME}']" --output text | grep -q "${ECR_READ_POLICY_NAME}"; then
    echo "Policy '${ECR_READ_POLICY_NAME}' is already attached to role '${AWS_ROLE_NAME}'. Skipping attachment."
else
    if ! aws iam attach-role-policy \
        --role-name "${AWS_ROLE_NAME}" \
        --policy-arn "${ECR_READ_POLICY_ARN}" &>/dev/null; then
        echo "Error: Failed to attach policy '${ECR_READ_POLICY_NAME}' to role '${AWS_ROLE_NAME}'."
        exit 1
    fi
    echo "Policy '${ECR_READ_POLICY_NAME}' attached successfully to role '${AWS_ROLE_NAME}'."
fi

# Optional: Output the Role ARN for convenience
AWS_ROLE_ARN=$(aws iam get-role --role-name "${AWS_ROLE_NAME}" --query Role.Arn --output text 2>/dev/null)
if [ -z "$AWS_ROLE_ARN" ]; then
    echo "Error: Could not retrieve AWS Role ARN for ${AWS_ROLE_NAME}."
    exit 1
fi

echo "AWS Role ARN for ${AWS_ROLE_NAME}: ${AWS_ROLE_ARN}"
echo "AWS OIDC Provider ARN: ${AWS_OIDC_PROVIDER_ARN}"

# Create .status directory and write ARNs
mkdir -p "${STATUS_DIR}"
echo "Writing AWS role and OIDC provider ARNs to ${STATUS_FILE}..."
echo "AWS_ROLE_ARN=${AWS_ROLE_ARN}" > "${STATUS_FILE}"
echo "AWS_OIDC_PROVIDER_ARN=${AWS_OIDC_PROVIDER_ARN}" >> "${STATUS_FILE}"
echo "Information saved to ${STATUS_FILE}."

echo "Next Steps:"
echo "1. In your GCP environment (e.g., GKE Workload Identity or a compute instance),"
echo "   configure your service account to use this AWS role ARN for federated authentication."
echo ""