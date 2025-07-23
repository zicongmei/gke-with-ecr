# Define variables
BINARY_NAME := ecr-credential-provider
BUILD_DIR := bin
STATUS_DIR := .status
STATUS_FILE_PUBLISH := $(STATUS_DIR)/publish_info.txt
STATUS_FILE_AWS := $(STATUS_DIR)/aws_role_info.txt

# Default target
.PHONY: all
all: build

# make build: builds the binary for Linux AMD64
.PHONY: build
build: $(BUILD_DIR)/$(BINARY_NAME)

# Create the build directory if it doesn't exist
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile the Go application
$(BUILD_DIR)/$(BINARY_NAME): $(BUILD_DIR)
	@echo "Building $(BINARY_NAME)..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Binary built at $(BUILD_DIR)/$(BINARY_NAME)"

# make publish: publishes the binary to a GCS path and records the path
# Usage: make publish GCS_PATH=gs://your-bucket/path/
.PHONY: publish
publish: build $(STATUS_DIR)
	@if [ -z "$(GCS_PATH)" ]; then \
		echo "Error: GCS_PATH environment variable or make argument is not set."; \
		echo "Usage: make publish GCS_PATH=gs://your-bucket/path/to/upload"; \
		exit 1; \
	fi
	@TIMESTAMP=$$(date +%Y%m%d%H%M%S); \
	UPLOAD_NAME="$(BINARY_NAME)-$${TIMESTAMP}"; \
	FINAL_GCS_PATH="$(GCS_PATH)/$${UPLOAD_NAME}"; \
	echo "Publishing $(BINARY_NAME) to $${FINAL_GCS_PATH}..." ; \
	gsutil cp $(BUILD_DIR)/$(BINARY_NAME) $${FINAL_GCS_PATH} ; \
	echo "Successfully published $(BINARY_NAME) to $${FINAL_GCS_PATH}" ; \
	echo "GCS_BINARY_PATH=$${FINAL_GCS_PATH}" > "$(STATUS_FILE_PUBLISH)" ; \
	echo "Published GCS path recorded in $(STATUS_FILE_PUBLISH)"

# make deploy: deploys the GKE ECR image puller using information from .status dir
.PHONY: deploy
deploy: $(STATUS_DIR)
	@echo "Running deploy.sh using information from $(STATUS_DIR)..."
	./deploy.sh

# make undeploy: removes the GKE ECR image puller DaemonSet
.PHONY: undeploy
undeploy:
	@echo "Running undeploy.sh..."
	./undeploy.sh

# Clean target: removes built files and status directory
.PHONY: clean
clean:
	@echo "Cleaning build directory and status files..."
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned."

# Ensure .status directory exists before writing to it
$(STATUS_DIR):
	@mkdir -p $(STATUS_DIR)