#!/bin/bash
set -euo pipefail

# Argument check
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <GCS_PATH_TO_BINARY> <AWS_ROLE_ARN>"
    echo "  <GCS_PATH_TO_BINARY> should be the gs:// path to the 'ecr-credential-provider' binary."
    echo "  <AWS_ROLE_ARN> should be the AWS IAM Role ARN for ECR access."
    exit 1
fi

GCS_BINARY_PATH="$1"
AWS_ROLE_ARN="$2"

# Define installation paths
BINARY_INSTALL_DIR="/opt/kubernetes/node/bin"
BINARY_INSTALL_NAME="gke-image-puller" # The name for the installed binary
KUBELET_CONFIG_DIR="/etc/kubernetes/gke-ecr-credential-provider"
KUBELET_CONFIG_FILE="${KUBELET_CONFIG_DIR}/config.yaml"
KUBELET_SERVICE="kubelet" # Common service name for kubelet

echo "Starting installation of GKE ECR Credential Provider..."
echo "  GCS Binary Path: ${GCS_BINARY_PATH}"
echo "  AWS Role ARN: ${AWS_ROLE_ARN}"

# 1. Ensure gsutil is available
if ! command -v gsutil &> /dev/null; then
    echo "Error: gsutil command not found."
    echo "Please ensure Google Cloud SDK is installed and gsutil is in your PATH."
    exit 1
fi

# 2. Create target directory for the binary
echo "Creating binary installation directory: ${BINARY_INSTALL_DIR}"
sudo mkdir -p "${BINARY_INSTALL_DIR}"

# 3. Download the binary from GCS
echo "Downloading binary from ${GCS_BINARY_PATH} to ${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}..."
sudo gsutil cp "${GCS_BINARY_PATH}" "${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}"
sudo chmod +x "${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}"
echo "Binary downloaded and made executable."

# 4. Create the kubelet credential provider config file
echo "Creating kubelet credential provider config directory: ${KUBELET_CONFIG_DIR}"
sudo mkdir -p "${KUBELET_CONFIG_DIR}"

echo "Writing kubelet credential provider config file: ${KUBELET_CONFIG_FILE}"
cat <<EOF | sudo tee "${KUBELET_CONFIG_FILE}" > /dev/null
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  - name: gke-image-puller
    matchImages:
      - "public.ecr.aws"
      - "*.dkr.ecr.*.amazonaws.com"
      - "*.dkr.ecr.*.amazonaws.com.cn"
      - "*.dkr.ecr-fips.*.amazonaws.com"
      - "*.dkr.ecr.us-iso-east-1.c2s.ic.gov"
      - "*.dkr.ecr.us-isob-east-1.sc2s.sgov.gov"
      - "container.cloud.google.com"
      - "gcr.io"
      - "*.gcr.io"
      - "*.pkg.dev"
    args:
      - --aws-role-arn=${AWS_ROLE_ARN}
    defaultCacheDuration: "0s"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
EOF
echo "Kubelet config file created."

# 5. Restart kubelet service
echo "Attempting to restart kubelet service..."
if systemctl is-active --quiet "${KUBELET_SERVICE}"; then
    sudo systemctl daemon-reload # Reload systemd units, typically good practice
    sudo systemctl restart "${KUBELET_SERVICE}"
    echo "Kubelet service restarted successfully."
    echo "Please verify the installation by checking 'sudo systemctl status ${KUBELET_SERVICE}'"
    echo "and looking for 'gke-image-puller' entries in kubelet logs (e.g., 'journalctl -u ${KUBELET_SERVICE}')."
    echo "Ensure that kubelet is configured to use a credential provider config file, e.g., via"
    echo "the '--credential-provider-config=${KUBELET_CONFIG_FILE}' flag in its startup arguments."
else
    echo "Warning: Kubelet service '${KUBELET_SERVICE}' not found or not active."
    echo "Please start/restart kubelet manually and ensure it's configured to use the config file at ${KUBELET_CONFIG_FILE}."
    exit 1
fi

echo "GKE ECR Credential Provider installation script finished."