/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/base64"
	"encoding/json" // Added for parsing JWT claims
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const ecrPublicRegion string = "us-east-1"
const ecrPublicHost string = "public.ecr.aws"

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr[\.\-]ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(?:\.cn)?|on\.(?:aws|amazonwebservices\.com\.cn)|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type ECRPublic interface {
	GetAuthorizationToken(ctx context.Context, params *ecrpublic.GetAuthorizationTokenInput, optFns ...func(*ecrpublic.Options)) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

// STS abstracts the calls we make to aws-sdk for testing purposes
type STS interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type ecrPlugin struct {
	ecr        ECR
	ecrPublic  ECRPublic
	sts        STS
	awsRoleARN string // Added field for the AWS IAM Role ARN provided as a command-line argument
}

func defaultECRProvider(ctx context.Context, region string) (ECR, error) {
	klog.Infof("Attempting to load AWS default config for ECR in region: %q", region)
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
	} else {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		klog.Errorf("Failed to load AWS config: %v", err)
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	klog.Infof("Successfully loaded AWS config. Creating ECR client.")
	return ecr.NewFromConfig(cfg), nil
}

func publicECRProvider(ctx context.Context) (ECRPublic, error) {
	klog.Infof("Attempting to load AWS default config for ECR Public in region: %q", ecrPublicRegion)
	// ECR public registries are only in one region and only accessible from regions
	// in the "aws" partition.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(ecrPublicRegion),
	)
	if err != nil {
		klog.Errorf("Failed to load AWS config for ECR Public: %v", err)
		return nil, fmt.Errorf("failed to load AWS config for ECR Public: %w", err)
	}

	klog.Infof("Successfully loaded AWS config. Creating ECR Public client.")
	return ecrpublic.NewFromConfig(cfg), nil
}

func stsProvider(ctx context.Context, region string) (STS, error) {
	klog.Infof("Attempting to load AWS default config for STS in region: %q", region)
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
	} else {
		klog.Warningf("No region found in the image reference for STS client, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		klog.Errorf("Failed to load AWS config for STS: %v", err)
		return nil, fmt.Errorf("failed to load AWS config for STS: %w", err)
	}
	klog.Infof("Successfully loaded AWS config. Creating STS client.")
	return sts.NewFromConfig(cfg), nil
}

type credsData struct {
	authToken *string
	expiresAt *time.Time
}

func (e *ecrPlugin) getPublicCredsData(ctx context.Context, optFns ...func(*ecrpublic.Options)) (*credsData, error) {
	klog.Infof("Getting creds for public registry (%s)", ecrPublicHost)
	var err error

	if e.ecrPublic == nil {
		klog.Infof("ECR Public client not initialized. Initializing now.")
		e.ecrPublic, err = publicECRProvider(ctx)
		if err != nil {
			klog.Errorf("Failed to initialize ECR Public client: %v", err)
			return nil, err
		}
	}

	klog.Infof("Calling ECR Public GetAuthorizationToken API.")
	output, err := e.ecrPublic.GetAuthorizationToken(ctx, &ecrpublic.GetAuthorizationTokenInput{}, optFns...)
	if err != nil {
		klog.Errorf("ECR Public GetAuthorizationToken API call failed: %v", err)
		return nil, fmt.Errorf("ECR Public GetAuthorizationToken API call failed: %w", err)
	}

	if output == nil {
		klog.Errorf("Response output from ECR Public was nil.")
		return nil, errors.New("response output from ECR Public was nil")
	}

	if output.AuthorizationData == nil {
		klog.Errorf("Authorization data from ECR Public was empty.")
		return nil, errors.New("authorization data from ECR Public was empty")
	}

	klog.Infof("Successfully retrieved authorization data for public registry. Token expires at: %v", output.AuthorizationData.ExpiresAt)
	return &credsData{
		authToken: output.AuthorizationData.AuthorizationToken,
		expiresAt: output.AuthorizationData.ExpiresAt,
	}, nil
}

func (e *ecrPlugin) getPrivateCredsData(ctx context.Context, imageHost string, image string, optFns ...func(*ecr.Options)) (*credsData, error) {
	klog.Infof("Getting creds for private image %s (host: %s)", image, imageHost)
	var err error

	if e.ecr == nil {
		region := parseRegionFromECRPrivateHost(imageHost)
		klog.Infof("ECR private client not initialized. Initializing now for region: %q.", region)
		e.ecr, err = defaultECRProvider(ctx, region)
		if err != nil {
			klog.Errorf("Failed to initialize ECR private client for region %q: %v", region, err)
			return nil, err
		}
	}

	klog.Infof("Calling ECR private GetAuthorizationToken API for host %s.", imageHost)
	output, err := e.ecr.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{}, optFns...)
	if err != nil {
		klog.Errorf("ECR private GetAuthorizationToken API call failed for host %s: %v", imageHost, err)
		return nil, fmt.Errorf("ECR private GetAuthorizationToken API call failed for host %s: %w", imageHost, err)
	}
	if output == nil {
		klog.Errorf("Response output from ECR private was nil for host %s.", imageHost)
		return nil, errors.New("response output from ECR private was nil")
	}
	if len(output.AuthorizationData) == 0 {
		klog.Errorf("Authorization data from ECR private was empty for host %s.", imageHost)
		return nil, errors.New("authorization data from ECR private was empty")
	}
	klog.Infof("Successfully retrieved authorization data for private registry %s. Token expires at: %v", imageHost, output.AuthorizationData[0].ExpiresAt)
	return &credsData{
		authToken: output.AuthorizationData[0].AuthorizationToken,
		expiresAt: output.AuthorizationData[0].ExpiresAt,
	}, nil
}

// getGCPIdentityToken fetches a GCP Service Account identity token from the GCP metadata server.
func getGCPIdentityToken(ctx context.Context, audience string) (string, error) {
	metadataURL := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s&format=full&licenses=FALSE", url.QueryEscape(audience))
	klog.Infof("Attempting to fetch GCP identity token from metadata server for audience: %s", audience)
	klog.V(4).Infof("GCP metadata server URL: %s", metadataURL)

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		klog.Errorf("Failed to create request to GCP metadata server for audience %s: %v", audience, err)
		return "", fmt.Errorf("failed to create request to GCP metadata server: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second} // Add a timeout to prevent hanging
	klog.Infof("Making HTTP GET request to GCP metadata server.")
	resp, err := client.Do(req)
	if err != nil {
		klog.Errorf("Failed to make request to GCP metadata server for audience %s: %v", audience, err)
		return "", fmt.Errorf("failed to make request to GCP metadata server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for error context, ignore error reading body
		klog.Errorf("Received non-200 status code from GCP metadata server: %d, body: %s", resp.StatusCode, string(bodyBytes))
		return "", fmt.Errorf("received non-200 status code from GCP metadata server: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("Failed to read response body from GCP metadata server for audience %s: %v", audience, err)
		return "", fmt.Errorf("failed to read response body from GCP metadata server: %w", err)
	}

	klog.Infof("Successfully fetched GCP identity token: %s", tokenBytes)
	return string(tokenBytes), nil
}

// buildCredentialsProvider constructs an AWS credentials provider that assumes an IAM role
// using a GCP Service Account identity token obtained from the GKE metadata server.
func (e *ecrPlugin) buildCredentialsProvider(ctx context.Context, imageHost string) (aws.CredentialsProvider, error) {
	klog.Infof("Building AWS credentials provider for federated authentication using AWS IAM Role ARN: %s", e.awsRoleARN)
	var err error

	// The AWS IAM Role ARN is now provided directly as a command-line argument to the plugin.
	arn := e.awsRoleARN
	if arn == "" {
		klog.Errorf("AWS IAM role ARN is empty. It is required for federated authentication.")
		// This case should ideally be caught by the command-line flag parser (cobra),
		// but this serves as a safeguard.
		return nil, errors.New("AWS IAM role ARN is required for federated authentication and was not provided.")
	}

	if e.sts == nil {
		region := "" // STS client can be initialized without a specific region, SDK will use default or env
		if imageHost != ecrPublicHost {
			region = parseRegionFromECRPrivateHost(imageHost)
			klog.Infof("Derived region %q from image host %q for STS client.", region, imageHost)
		}
		klog.Infof("STS client not initialized. Initializing now for region: %q.", region)
		e.sts, err = stsProvider(ctx, region)
	}
	if err != nil {
		klog.Errorf("Failed to create STS client: %v", err)
		return nil, fmt.Errorf("failed to create STS client: %w", err)
	}

	return aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		klog.Infof("Initiating credential fetch within AWS CredentialsProviderFunc.")
		// Fetch the GCP Service Account identity token from the GKE metadata server.
		// The audience for this token is "sts.amazonaws.com" for OIDC federation.
		gcpIdentityToken, err := getGCPIdentityToken(ctx, "sts.amazonaws.com")
		if err != nil {
			klog.Errorf("Failed to get GCP identity token from metadata server: %v", err)
			return aws.Credentials{}, fmt.Errorf("failed to get GCP identity token from metadata server: %w", err)
		}
		// Removed for security: klog.Infof("Got GCP token: %s", gcpIdentityToken)
		klog.Infof("Successfully obtained GCP identity token. Attempting to assume AWS IAM role %s.", arn)

		// Extract 'sub' claim from GCP identity token for RoleSessionName
		var roleSessionName string = "gke-ecr-credential-provider" // Default fallback session name
		tokenParts := strings.Split(gcpIdentityToken, ".")
		if len(tokenParts) == 3 {
			// JWT payload is the second part (index 1) and is Base64Url encoded
			payload, decodeErr := base64.RawURLEncoding.DecodeString(tokenParts[1])
			if decodeErr != nil {
				klog.Errorf("Failed to base64url decode JWT payload for 'sub' extraction: %v", decodeErr)
			} else {
				var claims struct {
					Sub string `json:"sub"`
				}
				unmarshalErr := json.Unmarshal(payload, &claims)
				if unmarshalErr != nil {
					klog.Errorf("Failed to unmarshal JWT payload for 'sub' extraction: %v", unmarshalErr)
				} else if claims.Sub != "" {
					roleSessionName = claims.Sub
					klog.Infof("Extracted 'sub' from GCP token for RoleSessionName: %s", roleSessionName)
				} else {
					klog.Warningf("'sub' claim not found or empty in GCP token payload. Using default RoleSessionName: %s", roleSessionName)
				}
			}
		} else {
			klog.Warningf("GCP token does not appear to be a valid JWT (expected 3 parts separated by '.', got %d). Using default RoleSessionName: %s", len(tokenParts), roleSessionName)
		}

		// Use the fetched GCP identity token to assume the specified AWS IAM role.
		assumeOutput, err := e.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(arn),
			RoleSessionName:  aws.String(roleSessionName),  // Use the extracted 'sub' or fallback
			WebIdentityToken: aws.String(gcpIdentityToken), // The GCP identity token
		})
		if err != nil {
			klog.Errorf("Failed to assume AWS IAM role '%s' with GCP identity token: %v", arn, err)
			return aws.Credentials{}, fmt.Errorf("failed to assume AWS IAM role '%s' with GCP identity token: %w", arn, err)
		}

		klog.Infof("Successfully assumed AWS IAM role %s. Credentials obtained, AccessKeyID: %s", arn, *assumeOutput.Credentials.AccessKeyId)
		return aws.Credentials{
			AccessKeyID:     *assumeOutput.Credentials.AccessKeyId,
			SecretAccessKey: *assumeOutput.Credentials.SecretAccessKey,
			SessionToken:    *assumeOutput.Credentials.SessionToken,
			CanExpire:       true,
			Expires:         *assumeOutput.Credentials.Expiration,
		}, nil
	}), nil
}

func (e *ecrPlugin) GetCredentials(ctx context.Context, request *v1.CredentialProviderRequest, args []string) (*v1.CredentialProviderResponse, error) {
	klog.Infof("GetCredentials called for image: %s, with args: %v", request.Image, args)
	var creds *credsData
	var err error

	if request.Image == "" {
		klog.Errorf("Image in plugin request was empty.")
		return nil, errors.New("image in plugin request was empty")
	}

	imageHost, err := parseHostFromImageReference(request.Image)
	if err != nil {
		klog.Errorf("Failed to parse host from image reference %q: %v", request.Image, err)
		return nil, fmt.Errorf("failed to parse host from image reference %q: %w", request.Image, err)
	}
	klog.Infof("Parsed image host: %s", imageHost)

	var credentialsProvider aws.CredentialsProvider = nil

	roleARNToUse := e.awsRoleARN

	if roleARNToUse != "" {
		klog.Infof("AWS IAM role ARN '%s' provided via command-line argument. Attempting to build AWS credentials provider using GCP metadata server for federated authentication.", roleARNToUse)
		credentialsProvider, err = e.buildCredentialsProvider(ctx, imageHost)
		if err != nil {
			klog.Errorf("Failed to build AWS credentials provider for ECR using GCP token: %v", err)
			return nil, fmt.Errorf("failed to build AWS credentials provider for ECR using GCP token: %w", err)
		}
		klog.Infof("Successfully built AWS credentials provider using federated authentication.")
	} else {
		// If no AWS IAM Role ARN is provided via command-line argument,
		// the AWS SDK's default credential chain will be used. This includes
		// environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN),
		// shared credential files (~/.aws/credentials), and EC2 instance profiles (if on EC2).
		klog.Info("No AWS IAM role ARN provided via command-line argument. AWS SDK will use its default credential resolution chain (e.g., EC2 instance profile, env vars, shared config).")
		// `credentialsProvider` remains nil here, so the ECR/ECRPublic clients will be
		// initialized with `config.LoadDefaultConfig` which implies default AWS SDK credential lookup.
	}

	if imageHost == ecrPublicHost {
		klog.Infof("Image host %q matches ECR Public host. Fetching public registry credentials.", imageHost)
		var optFns = []func(*ecrpublic.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *ecrpublic.Options) {
				o.Credentials = credentialsProvider
				klog.Infof("Applying custom AWS credentials provider to ECR Public client options.")
			})
		}
		creds, err = e.getPublicCredsData(ctx, optFns...)
	} else {
		klog.Infof("Image host %q does not match ECR Public host. Fetching private registry credentials.", imageHost)
		var optFns = []func(*ecr.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *ecr.Options) {
				o.Credentials = credentialsProvider
				klog.Infof("Applying custom AWS credentials provider to ECR private client options.")
			})
		}
		creds, err = e.getPrivateCredsData(ctx, imageHost, request.Image, optFns...)
	}

	if err != nil {
		klog.Errorf("Failed to get ECR authorization data: %v", err)
		return nil, fmt.Errorf("error running credential provider plugin: operation error ECR: GetAuthorizationToken, get identity: %w", err)
	}

	if creds.authToken == nil {
		klog.Errorf("Authorization token in response was nil.")
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.ToString(creds.authToken))
	if err != nil {
		klog.Errorf("Failed to base64 decode authorization token: %v", err)
		return nil, fmt.Errorf("failed to base64 decode authorization token: %w", err)
	}
	klog.Infof("Successfully base64 decoded authorization token.")

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		klog.Errorf("Error parsing username and password from authorization token: expected 2 parts, got %d. Decoded: %q", len(parts), string(decodedToken))
		return nil, errors.New("error parsing username and password from authorization token")
	}
	klog.Infof("Successfully parsed username and password from token. Username: %s", parts[0])

	cacheDuration := getCacheDuration(creds.expiresAt)
	klog.Infof("Calculated cache duration for credentials: %v", cacheDuration)

	response := &v1.CredentialProviderResponse{
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: cacheDuration,
		Auth: map[string]v1.AuthConfig{
			imageHost: {
				Username: parts[0],
				Password: parts[1],
			},
		},
	}
	klog.Infof("Returning CredentialProviderResponse for image host %s.", imageHost)
	return response, nil

}

// getCacheDuration calculates the credentials cache duration based on the ExpiresAt time from the authorization data
func getCacheDuration(expiresAt *time.Time) *metav1.Duration {
	var cacheDuration *metav1.Duration
	if expiresAt == nil {
		klog.Warningf("expiresAt time was nil, setting cache duration to 0.")
		// explicitly set cache duration to 0 if expiresAt was nil so that
		// kubelet does not cache it in-memory
		cacheDuration = &metav1.Duration{Duration: 0}
	} else {
		// halving duration in order to compensate for the time loss between
		// the token creation and passing it all the way to kubelet.
		duration := time.Second * time.Duration((expiresAt.Unix()-time.Now().Unix())/2)
		if duration > 0 {
			klog.Infof("Token expires at %v. Calculated effective cache duration: %v", *expiresAt, duration)
			cacheDuration = &metav1.Duration{Duration: duration}
		} else {
			// If duration is 0 or negative (token already expired or very short life),
			// set cache duration to 0 to force immediate re-fetch.
			klog.Warningf("Calculated cache duration was %v (expires at %v, now %v), setting to 0 to force re-fetch.", duration, *expiresAt, time.Now())
			cacheDuration = &metav1.Duration{Duration: 0}
		}
	}
	return cacheDuration
}

// parseHostFromImageReference parses the hostname from an image reference
func parseHostFromImageReference(image string) (string, error) {
	// a URL needs a scheme to be parsed correctly
	if !strings.Contains(image, "://") {
		image = "https://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		klog.Errorf("Error parsing image reference %s: %v", image, err)
		return "", fmt.Errorf("error parsing image reference %s: %v", image, err)
	}
	klog.V(4).Infof("Successfully parsed host %q from image reference %q.", parsed.Hostname(), image)
	return parsed.Hostname(), nil
}

func parseRegionFromECRPrivateHost(host string) string {
	splitHost := ecrPrivateHostPattern.FindStringSubmatch(host)
	if len(splitHost) != 5 {
		klog.Warningf("Could not parse region from ECR private host %q. Pattern match failed.", host)
		return ""
	}
	region := splitHost[3]
	klog.V(4).Infof("Parsed region %q from ECR private host %q.", region, host)
	return region
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	klog.Infof("ECR Credential Provider Plugin starting.")

	// Use cobra command to parse arguments and run the plugin
	rootCmd := newCredentialProviderCommand()
	if err := rootCmd.Execute(); err != nil {
		klog.Errorf("Error executing root command: %v", err)
		os.Exit(1)
	}
	klog.Infof("ECR Credential Provider Plugin finished.")
}

var gitVersion string

func newCredentialProviderCommand() *cobra.Command {
	var awsRoleARN string // Variable to store the AWS Role ARN from the command-line flag

	cmd := &cobra.Command{
		Use:     "ecr-credential-provider",
		Short:   "ECR credential provider for kubelet",
		Version: gitVersion,
		Run: func(cmd *cobra.Command, args []string) {
			klog.Infof("Command execution started. AWS IAM Role ARN provided: %q", awsRoleARN)
			// Initialize the plugin with the AWS Role ARN obtained from the command-line flag
			p := NewCredentialProvider(&ecrPlugin{awsRoleARN: awsRoleARN})
			if err := p.Run(context.TODO()); err != nil {
				// This error message is visible in kubelet logs if the plugin fails early
				// as a top-level error message.
				klog.Errorf("Error running credential provider plugin: %v", err)
				os.Exit(1)
			}
		},
	}

	// Add a persistent flag to accept the AWS IAM Role ARN
	cmd.Flags().StringVar(&awsRoleARN, "aws-role-arn", "", "AWS IAM Role ARN to assume for ECR access when using GCP federated authentication. This flag is required.")
	// Mark the flag as required
	cmd.MarkPersistentFlagRequired("aws-role-arn")
	klog.V(4).Infof("Cobra command created with 'aws-role-arn' flag.")

	return cmd
}