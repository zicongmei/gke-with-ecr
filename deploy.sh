#!/bin/bash
set -euo pipefail

STATUS_DIR=".status"
PUBLISH_STATUS_FILE="${STATUS_DIR}/publish_info.txt"
AWS_ROLE_STATUS_FILE="${STATUS_DIR}/aws_role_info.txt"

echo "Reading deployment information from ${STATUS_DIR}..."

# Read GCS_PATH
if [ ! -f "${PUBLISH_STATUS_FILE}" ]; then
    echo "Error: Publish status file '${PUBLISH_STATUS_FILE}' not found."
    echo "Please run 'make publish GCS_PATH=...' first."
    exit 1
fi
# Source the file and validate the variable
# The file is expected to contain "GCS_BINARY_PATH=gs://..."
source "${PUBLISH_STATUS_FILE}"
if [ -z "${GCS_BINARY_PATH}" ]; then
    echo "Error: GCS_BINARY_PATH not found in ${PUBLISH_STATUS_FILE}."
    exit 1
fi
GCS_PATH="${GCS_BINARY_PATH}" # Assign to the variable name used later in the script

# Read AWS_ROLE_ARN
if [ ! -f "${AWS_ROLE_STATUS_FILE}" ]; then
    echo "Error: AWS role status file '${AWS_ROLE_STATUS_FILE}' not found."
    echo "Please run 'setup_aws_role.sh' first."
    exit 1
fi
# Source the file and validate the variable
# The file is expected to contain "AWS_ROLE_ARN=arn:aws:..."
source "${AWS_ROLE_STATUS_FILE}"
if [ -z "${AWS_ROLE_ARN}" ]; then
    echo "Error: AWS_ROLE_ARN not found in ${AWS_ROLE_STATUS_FILE}."
    exit 1
fi


DAEMONSET_NAME="gke-ecr-image-puller-installer"
NAMESPACE="kube-system" # Or any other system namespace like default if preferred

echo "Deploying GKE ECR Image Puller DaemonSet..."
echo "  GCS Binary Path: ${GCS_PATH}"
echo "  AWS Role ARN: ${AWS_ROLE_ARN}"

# The script below is an adapted version of install.sh to run within
# a privileged initContainer that mounts the host's root filesystem at /host.
# It removes 'sudo' and prefixes host-specific paths with '/host'.
INSTALL_SCRIPT_CONTENT=$(cat <<'EOF_INSTALL_SCRIPT'
#!/bin/bash
set -euo pipefail

# These are passed as environment variables to the initContainer
# GCS_BINARY_PATH_ENV and AWS_ROLE_ARN_ENV

# Define installation paths relative to the /host mount point
HOST_ROOT="/host" # The mount point for the host's root filesystem

BINARY_INSTALL_DIR="${HOST_ROOT}/home/kubernetes/bin"
BINARY_INSTALL_NAME="gke-ecr-image-puller"
KUBELET_CONFIG_DIR="${HOST_ROOT}/etc/kubernetes/gke-ecr-credential-provider"
KUBELET_CONFIG_FILE="${HOST_ROOT}/etc/srv/kubernetes/cri_auth_config.yaml"
KUBELET_SERVICE="kubelet" # Common service name for kubelet on GKE nodes

echo "Starting installation of GKE ECR Credential Provider on host via initContainer..."
echo "  GCS Binary Path: ${GCS_BINARY_PATH_ENV}"
echo "  AWS Role ARN: ${AWS_ROLE_ARN_ENV}"

# 1. Ensure gsutil is available (the 'google/cloud-sdk' image should provide it)
if ! command -v gsutil &> /dev/null; then
    echo "Error: gsutil command not found in initContainer. Ensure 'google/cloud-sdk' image is correct."
    exit 1
fi

# 2. Create target directory for the binary on the host
echo "Creating binary installation directory: ${BINARY_INSTALL_DIR}"
mkdir -p "${BINARY_INSTALL_DIR}"

# 3. Download the binary from GCS to the host
echo "Downloading binary from ${GCS_BINARY_PATH_ENV} to ${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}..."
gsutil cp "${GCS_BINARY_PATH_ENV}" "${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}"
chmod +x "${BINARY_INSTALL_DIR}/${BINARY_INSTALL_NAME}"
echo "Binary downloaded and made executable."

# 4. Create the kubelet credential provider config file on the host
echo "Creating kubelet credential provider config directory: ${KUBELET_CONFIG_DIR}"
mkdir -p "${KUBELET_CONFIG_DIR}"

echo "Inserting kubelet credential provider config file: ${KUBELET_CONFIG_FILE}"
cp "${KUBELET_CONFIG_FILE}" "${KUBELET_CONFIG_FILE}".bak
cat <<EOF_CONFIG > "${KUBELET_CONFIG_FILE}"
kind: CredentialProviderConfig
apiVersion: kubelet.config.k8s.io/v1
providers:
  - name: gke-ecr-image-puller
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
      - --aws-role-arn=${AWS_ROLE_ARN_ENV}
    defaultCacheDuration: "0s"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
  - name: auth-provider-gcp
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    matchImages:
    - "container.cloud.google.com"
    - "gcr.io"
    - "*.gcr.io"
    - "*.pkg.dev"
    args:
    - get-credentials
    - --v=3
    defaultCacheDuration: 1m
EOF_CONFIG
echo "Kubelet config file created."

# 5. Restart kubelet service on the host
echo "Attempting to restart kubelet service on the host..."
# Use chroot to execute systemctl on the host system.
# This assumes the host has a systemd setup accessible via /host/usr/bin/systemctl.
if chroot "${HOST_ROOT}" systemctl is-active --quiet "${KUBELET_SERVICE}"; then
    echo "Host kubelet service is active. Proceeding with restart."
    chroot "${HOST_ROOT}" systemctl daemon-reload
    chroot "${HOST_ROOT}" systemctl restart "${KUBELET_SERVICE}"
    echo "Host Kubelet service restarted successfully."
    echo "Please verify the installation by checking 'sudo systemctl status ${KUBELET_SERVICE}' on the host"
    echo "and looking for 'gke-image-puller' entries in kubelet logs."
    echo "Ensure that kubelet is configured to use a credential provider config file, e.g., via"
    echo "the '--credential-provider-config=${KUBELET_CONFIG_FILE}' flag in its startup arguments."
else
    echo "Warning: Host Kubelet service '${KUBELET_SERVICE}' not found or not active."
    echo "Installation completed, but restart might need manual intervention."
    # Fail the initContainer if kubelet restart fails, so the pod can be retried or marked as failed.
    exit 1
fi

echo "GKE ECR Credential Provider installation script finished on host."
EOF_INSTALL_SCRIPT
)

# Base64 encode the script content to embed it safely in the YAML
ENCODED_SCRIPT=$(echo "${INSTALL_SCRIPT_CONTENT}" | base64 -w 0)

# Create the DaemonSet YAML and apply it using kubectl
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ${DAEMONSET_NAME}
  namespace: ${NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${DAEMONSET_NAME}
  template:
    metadata:
      labels:
        app: ${DAEMONSET_NAME}
    spec:
      hostPID: true # Required for systemctl interaction via chroot
      hostIPC: true # Good practice for privileged daemonsets, though not strictly required for this script
      hostNetwork: true # To allow network access for gsutil to download binary
      # nodeSelector:
      #   kubernetes.io/os: linux
      #   cloud.google.com/gke-nodepool: default-pool # Optional: Target specific nodepool if needed
      tolerations:
      - operator: Exists # Tolerates all taints, important for GKE nodes (e.g., control-plane, critical add-ons)
      volumes:
        - name: host-root
          hostPath:
            path: / # Mount the host's root filesystem
        - name: systemd-run
          hostPath:
            path: /run # For systemd related runtime files, typically needed by systemctl
      initContainers:
        - name: gke-image-puller-installer
          image: google/cloud-sdk:latest # Image with gsutil, bash, chroot, and systemctl-compatible binaries
          securityContext:
            privileged: true # Required for host filesystem access and systemctl restart
          env:
            - name: GCS_BINARY_PATH_ENV
              value: "${GCS_PATH}"
            - name: AWS_ROLE_ARN_ENV
              value: "${AWS_ROLE_ARN}"
          command: ["bash", "-c"]
          args:
            - |
              echo "${ENCODED_SCRIPT}" | base64 -d > /tmp/install-script.sh
              chmod +x /tmp/install-script.sh
              /tmp/install-script.sh
          volumeMounts:
            - name: host-root
              mountPath: /host # Mount host's root at /host inside the container
            - name: systemd-run
              mountPath: /run # Mount host's /run at /run inside the container
      containers:
        # A lightweight container to keep the DaemonSet pod running after the initContainer completes.
        # The initContainer performs the one-time installation.
        - name: pause
          image: registry.k8s.io/pause:3.9 # Use a lightweight pause container
          command: ["/bin/sh"]
          args: ["-c", "sleep infinity"] # Keep the container running indefinitely
  updateStrategy:
    type: RollingUpdate # Standard update strategy for DaemonSets
    rollingUpdate:
      maxUnavailable: 1
EOF

echo "DaemonSet '${DAEMONSET_NAME}' applied to namespace '${NAMESPACE}'."
echo "Check its status with: kubectl -n ${NAMESPACE} get ds ${DAEMONSET_NAME}"
echo "Check pod logs for installation progress: kubectl -n ${NAMESPACE} logs -f -l app=${DAEMONSET_NAME} -c gke-image-puller-installer"