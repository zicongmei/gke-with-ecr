package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/klog/v2"
	"k8s.io/kubelet/pkg/apis/credentialprovider/install"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	install.Install(scheme)
}

// CredentialProvider is an interface implemented by the kubelet credential provider plugin to fetch
// the username/password based on the provided image name.
type CredentialProvider interface {
	GetCredentials(ctx context.Context, request *v1.CredentialProviderRequest, args []string) (response *v1.CredentialProviderResponse, err error)
}

// ExecPlugin implements the exec-based plugin for fetching credentials that is invoked by the kubelet.
type ExecPlugin struct {
	plugin CredentialProvider
}

// NewCredentialProvider returns an instance of execPlugin that fetches
// credentials based on the provided plugin implementing the CredentialProvider interface.
func NewCredentialProvider(plugin CredentialProvider) *ExecPlugin {
	return &ExecPlugin{plugin}
}

// Run executes the credential provider plugin. Required information for the plugin request (in
// the form of v1.CredentialProviderRequest) is provided via stdin from the kubelet.
// The CredentialProviderResponse, containing the username/password required for pulling
// the provided image, will be sent back to the kubelet via stdout.
func (e *ExecPlugin) Run(ctx context.Context) error {
	klog.Infof("ExecPlugin Run method invoked.")
	return e.runPlugin(ctx, os.Stdin, os.Stdout, os.Args[1:])
}

func (e *ExecPlugin) runPlugin(ctx context.Context, r io.Reader, w io.Writer, args []string) error {
	klog.Infof("Reading CredentialProviderRequest from stdin.")
	data, err := io.ReadAll(r)
	if err != nil {
		klog.Errorf("Failed to read input from stdin: %v", err)
		return fmt.Errorf("failed to read input from stdin: %w", err)
	}
	klog.V(4).Infof("Successfully read %d bytes from stdin.", len(data))

	gvk, err := json.DefaultMetaFactory.Interpret(data)
	if err != nil {
		klog.Errorf("Failed to interpret GVK from input data: %v", err)
		return fmt.Errorf("failed to interpret GVK from input data: %w", err)
	}
	klog.V(4).Infof("Interpreted GVK: %s", gvk.String())

	if gvk.GroupVersion() != v1.SchemeGroupVersion {
		klog.Errorf("Unsupported group version: %s (expected %s)", gvk.GroupVersion(), v1.SchemeGroupVersion)
		return fmt.Errorf("group version %s is not supported", gvk.GroupVersion())
	}

	request, err := decodeRequest(data)
	if err != nil {
		klog.Errorf("Failed to decode CredentialProviderRequest: %v", err)
		return fmt.Errorf("failed to decode CredentialProviderRequest: %w", err)
	}
	klog.Infof("Successfully decoded CredentialProviderRequest for image: %s", request.Image)

	response, err := e.plugin.GetCredentials(ctx, request, args)
	if err != nil {
		klog.Errorf("Plugin GetCredentials failed for image %s: %v", request.Image, err)
		return fmt.Errorf("plugin GetCredentials failed: %w", err)
	}
	klog.Infof("Successfully obtained credentials from plugin for image: %s", request.Image)

	if response == nil {
		klog.Errorf("CredentialProviderResponse from plugin was nil.")
		return errors.New("CredentialProviderResponse from plugin was nil")
	}

	encodedResponse, err := encodeResponse(response)
	if err != nil {
		klog.Errorf("Failed to encode CredentialProviderResponse: %v", err)
		return fmt.Errorf("failed to encode response: %w", err)
	}
	klog.Infof("Successfully encoded CredentialProviderResponse (length: %d bytes).", len(encodedResponse))

	writer := bufio.NewWriter(w)
	defer writer.Flush()
	if _, err := writer.Write(encodedResponse); err != nil {
		klog.Errorf("Failed to write encoded response to stdout: %v", err)
		return fmt.Errorf("failed to write encoded response to stdout: %w", err)
	}
	klog.Infof("Successfully wrote response to stdout.")

	return nil
}

func decodeRequest(data []byte) (*v1.CredentialProviderRequest, error) {
	obj, gvk, err := codecs.UniversalDecoder(v1.SchemeGroupVersion).Decode(data, nil, nil)
	if err != nil {
		klog.Errorf("Codecs universal decoder failed to decode request data: %v", err)
		return nil, err
	}
	klog.V(4).Infof("Decoded object GVK: %s", gvk.String())

	if gvk.Kind != "CredentialProviderRequest" {
		klog.Errorf("Decoded kind was %q, expected CredentialProviderRequest", gvk.Kind)
		return nil, fmt.Errorf("kind was %q, expected CredentialProviderRequest", gvk.Kind)
	}

	if gvk.Group != v1.GroupName {
		klog.Errorf("Decoded group was %q, expected %s", gvk.Group, v1.GroupName)
		return nil, fmt.Errorf("group was %q, expected %s", gvk.Group, v1.GroupName)
	}

	request, ok := obj.(*v1.CredentialProviderRequest)
	if !ok {
		klog.Errorf("Unable to convert decoded object of type %T to *CredentialProviderRequest", obj)
		return nil, fmt.Errorf("unable to convert %T to *CredentialProviderRequest", obj)
	}
	klog.V(4).Infof("Successfully cast decoded object to *CredentialProviderRequest.")

	return request, nil
}

func encodeResponse(response *v1.CredentialProviderResponse) ([]byte, error) {
	mediaType := "application/json"
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		klog.Errorf("Unsupported media type %q for encoding response.", mediaType)
		return nil, fmt.Errorf("unsupported media type %q", mediaType)
	}
	klog.V(4).Infof("Found serializer info for media type %q.", mediaType)

	encoder := codecs.EncoderForVersion(info.Serializer, v1.SchemeGroupVersion)
	data, err := runtime.Encode(encoder, response)
	if err != nil {
		klog.Errorf("Failed to encode response using encoder: %v", err)
		return nil, fmt.Errorf("failed to encode response: %v", err)
	}
	klog.V(4).Infof("Successfully encoded response object.")

	return data, nil
}