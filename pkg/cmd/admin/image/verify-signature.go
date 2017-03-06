package image

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/containers/image/docker/policyconfiguration"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/signature"
	sigtypes "github.com/containers/image/types"
	"github.com/openshift/origin/pkg/client"
	"github.com/openshift/origin/pkg/cmd/templates"
	"github.com/openshift/origin/pkg/cmd/util/clientcmd"
	imageapi "github.com/openshift/origin/pkg/image/api"

	"github.com/spf13/cobra"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
)

var (
	verifyImageSignatureLongDesc = templates.LongDesc(`
	Verifies the imported image signature using the local public key.

	This command verifies if the signature attached to an image is trusted by
	using the provided public GPG key.
	Trusted image means that the image signature was signed by a valid GPG key and the image identity
	provided by the signature content matches with the image.
	By default, this command will not record a signature condition back to the Image object but only
	print the verification status to the console.

	To record a new condition, you have to pass the "--confirm" flag.
	`)

	verifyImageSignatureExample = templates.Examples(`
	# Verify the image signature using the local GNUPG keychan and record the status as a condition to image
	%[1]s sha256:c841e9b64e4579bd56c794bdd7c36e1c257110fd2404bebbb8b613e4935228c4 --expected-identity=registry.local:5000/foo/bar:v1
	`)
)

type VerifyImageSignatureOptions struct {
	InputImage        string
	ExpectedIdentity  string
	PublicKeyFilename string
	PublicKey         []byte
	Confirm           bool
	Remove            bool
	CurrentUser       string

	Client client.Interface
	Out    io.Writer
	ErrOut io.Writer
}

func NewCmdVerifyImageSignature(name, fullName string, f *clientcmd.Factory, out, errOut io.Writer) *cobra.Command {
	opts := &VerifyImageSignatureOptions{ErrOut: errOut, Out: out}
	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s IMAGE [--confirm]", name),
		Short:   "Verify that the given IMAGE signature is trusted",
		Long:    verifyImageSignatureLongDesc,
		Example: fmt.Sprintf(verifyImageSignatureExample, name),
		Run: func(cmd *cobra.Command, args []string) {
			kcmdutil.CheckErr(opts.Complete(f, cmd, args, out))
			kcmdutil.CheckErr(opts.Run())
		},
	}

	cmd.Flags().BoolVar(&opts.Confirm, "confirm", opts.Confirm, "If true, the result of the verification will be recorded to an image object.")
	cmd.Flags().BoolVar(&opts.Remove, "remove", opts.Remove, "If set, all signature verifications will be removed from the given image.")
	cmd.Flags().StringVar(&opts.PublicKeyFilename, "public-key", opts.PublicKeyFilename, "A path to a public GPG key to be used for verification.")
	cmd.Flags().StringVar(&opts.ExpectedIdentity, "expected-identity", opts.ExpectedIdentity, "An expected image docker reference to verify.")
	return cmd
}

func (o *VerifyImageSignatureOptions) Complete(f *clientcmd.Factory, cmd *cobra.Command, args []string, out io.Writer) error {
	if len(args) != 1 {
		return kcmdutil.UsageError(cmd, "exactly one image must be specified")
	}
	o.InputImage = args[0]
	if len(o.ExpectedIdentity) == 0 {
		return kcmdutil.UsageError(cmd, "the --expected-identity must be specified")
	}
	var err error

	// If --public-key is provided only this key will be used for verification and the
	// .gnupg/pubring.gpg will be ignored.
	if len(o.PublicKeyFilename) > 0 {
		if o.Remove {
			return kcmdutil.UsageError(cmd, "cannot use public key when removing verification status")
		}
		if o.PublicKey, err = ioutil.ReadFile(o.PublicKeyFilename); err != nil {
			return err
		}
	}
	if o.Client, _, err = f.Clients(); err != nil {
		return err
	}
	// Only make this API call when we are sure we will be writing validation.
	if o.Confirm && !o.Remove {
		if me, err := o.Client.Users().Get("~"); err != nil {
			return err
		} else {
			o.CurrentUser = me.Name
		}
	}

	return nil
}

// verifySignature verifies the image signature and returns the identity when the signature
// is valid.
func (o *VerifyImageSignatureOptions) verifySignature(pc *signature.PolicyContext, img *imageapi.Image, sigBlob []byte) (string, error) {
	// Pretend that this is the only signature of img, and see what the policy says.
	memoryImage, err := newUnparsedImage(o.ExpectedIdentity, img, sigBlob)
	if err != nil {
		return "", fmt.Errorf("error setting up signature verification: %v", err)
	}
	allowed, err := pc.IsRunningImageAllowed(memoryImage)
	if !allowed && err == nil {
		return "", errors.New("internal error: signature rejected but no error set")
	}
	if err != nil {
		return "", fmt.Errorf("signsture rejected: %v", err)
	}

	// Because s.Content was the only signature used above, we now know that s.Content is acceptable, so untrustedInfo is good enough.
	// And we really only want untrustedInfo.UntrustedShortKeyIdentifier, which does not depend on any context.
	untrustedInfo, err := signature.GetUntrustedSignatureInformationWithoutVerifying(sigBlob)
	if err != nil {
		return "", fmt.Errorf("error getting signing key identity: %v", err) // Note that this is also treated as an unverified signature. It really shouldn’t happen anyway.
	}
	return untrustedInfo.UntrustedShortKeyIdentifier, nil
}

// clearSignatureVerificationStatus removes the current image signature from the Image object by
// erasing all signature fields that were previously set (when image signature was
// previously verified).
func (o *VerifyImageSignatureOptions) clearSignatureVerificationStatus(s *imageapi.ImageSignature) {
	s.Conditions = []imageapi.SignatureCondition{}
	s.IssuedBy = nil
}

// fakeDockerTransport is containers/image/docker.Transport, except that it only provides identity information.
var fakeDockerTransport = dockerTransport{}

type dockerTransport struct{}

func (t dockerTransport) Name() string {
	return "docker"
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an ImageReference.
func (t dockerTransport) ParseReference(reference string) (sigtypes.ImageReference, error) {
	return parseDockerReference(reference)
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a signature.PolicyTransportScopes keys
// (i.e. a valid PolicyConfigurationIdentity() or PolicyConfigurationNamespaces() return value).
// It is acceptable to allow an invalid value which will never be matched, it can "only" cause user confusion.
// scope passed to this function will not be "", that value is always allowed.
func (t dockerTransport) ValidatePolicyConfigurationScope(scope string) error {
	// FIXME? We could be verifying the various character set and length restrictions
	// from docker/distribution/reference.regexp.go, but other than that there
	// are few semantically invalid strings.
	return nil
}

// fakeDockerReference is containers/image/docker.Reference, except that only provides identity information.
type fakeDockerReference struct{ ref reference.Named }

// parseReference converts a string, which should not start with the ImageTransport.Name prefix, into an Docker ImageReference.
func parseDockerReference(refString string) (sigtypes.ImageReference, error) {
	if !strings.HasPrefix(refString, "//") {
		return nil, fmt.Errorf("docker: image reference %s does not start with //", refString)
	}
	ref, err := reference.ParseNormalizedNamed(strings.TrimPrefix(refString, "//"))
	if err != nil {
		return nil, err
	}
	ref = reference.TagNameOnly(ref)

	if reference.IsNameOnly(ref) {
		return nil, fmt.Errorf("Docker reference %s has neither a tag nor a digest", reference.FamiliarString(ref))
	}
	// A github.com/distribution/reference value can have a tag and a digest at the same time!
	// The docker/distribution API does not really support that (we can’t ask for an image with a specific
	// tag and digest), so fail.  This MAY be accepted in the future.
	// (Even if it were supported, the semantics of policy namespaces are unclear - should we drop
	// the tag or the digest first?)
	_, isTagged := ref.(reference.NamedTagged)
	_, isDigested := ref.(reference.Canonical)
	if isTagged && isDigested {
		return nil, fmt.Errorf("Docker references with both a tag and digest are currently not supported")
	}
	return fakeDockerReference{
		ref: ref,
	}, nil
}

func (ref fakeDockerReference) Transport() sigtypes.ImageTransport {
	return fakeDockerTransport
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent reference.
// NOTE: The returned string is not promised to be equal to the original input to ParseReference;
// e.g. default attribute values omitted by the user may be filled in in the return value, or vice versa.
// WARNING: Do not use the return value in the UI to describe an image, it does not contain the Transport().Name() prefix.
func (ref fakeDockerReference) StringWithinTransport() string {
	return "//" + reference.FamiliarString(ref.ref)
}

// DockerReference returns a Docker reference associated with this reference
// (fully explicit, i.e. !reference.IsNameOnly, but reflecting user intent,
// not e.g. after redirect or alias processing), or nil if unknown/not applicable.
func (ref fakeDockerReference) DockerReference() reference.Named {
	return ref.ref
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for policy lookup.
// This MUST reflect user intent, not e.g. after processing of third-party redirects or aliases;
// The value SHOULD be fully explicit about its semantics, with no hidden defaults, AND canonical
// (i.e. various references with exactly the same semantics should return the same configuration identity)
// It is fine for the return value to be equal to StringWithinTransport(), and it is desirable but
// not required/guaranteed that it will be a valid input to Transport().ParseReference().
// Returns "" if configuration identities for these references are not supported.
func (ref fakeDockerReference) PolicyConfigurationIdentity() string {
	res, err := policyconfiguration.DockerReferenceIdentity(ref.ref)
	if res == "" || err != nil { // Coverage: Should never happen, NewReference above should refuse values which could cause a failure.
		panic(fmt.Sprintf("Internal inconsistency: policyconfiguration.DockerReferenceIdentity returned %#v, %v", res, err))
	}
	return res
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set.  The list will be processed
// in order, terminating on first match, and an implicit "" is always checked at the end.
// It is STRONGLY recommended for the first element, if any, to be a prefix of PolicyConfigurationIdentity(),
// and each following element to be a prefix of the element preceding it.
func (ref fakeDockerReference) PolicyConfigurationNamespaces() []string {
	return policyconfiguration.DockerReferenceNamespaces(ref.ref)
}

func (ref fakeDockerReference) NewImage(ctx *sigtypes.SystemContext) (sigtypes.Image, error) {
	panic("Unimplemented")
}
func (ref fakeDockerReference) NewImageSource(ctx *sigtypes.SystemContext, requestedManifestMIMETypes []string) (sigtypes.ImageSource, error) {
	panic("Unimplemented")
}
func (ref fakeDockerReference) NewImageDestination(ctx *sigtypes.SystemContext) (sigtypes.ImageDestination, error) {
	panic("Unimplemented")
}
func (ref fakeDockerReference) DeleteImage(ctx *sigtypes.SystemContext) error {
	panic("Unimplemented")
}

// unparsedImage implements sigtypes.UnparsedImage, to allow evaluating the signature policy
// against an image without having to make it pullable by containers/image
type unparsedImage struct {
	ref       sigtypes.ImageReference
	manifest  []byte
	signature []byte
}

func newUnparsedImage(expectedIdentity string, img *imageapi.Image, signature []byte) (sigtypes.UnparsedImage, error) {
	ref, err := parseDockerReference("//" + expectedIdentity)
	if err != nil {
		return nil, fmt.Errorf("Invalid --expected-identity: %v", err)
	}
	return &unparsedImage{ref: ref, manifest: []byte(img.DockerImageManifest), signature: signature}, nil
}

// Reference returns the reference used to set up this source, _as specified by the user_
// (not as the image itself, or its underlying storage, claims).  This can be used e.g. to determine which public keys are trusted for this image.
func (ui *unparsedImage) Reference() sigtypes.ImageReference {
	return ui.ref
}

// Close removes resources associated with an initialized UnparsedImage, if any.
func (ui *unparsedImage) Close() error {
	return nil
}

// Manifest is like ImageSource.GetManifest, but the result is cached; it is OK to call this however often you need.
func (ui *unparsedImage) Manifest() ([]byte, string, error) {
	return ui.manifest, "", nil
}

// Signatures is like ImageSource.GetSignatures, but the result is cached; it is OK to call this however often you need.
func (ui *unparsedImage) Signatures() ([][]byte, error) {
	return [][]byte{ui.signature}, nil
}

func (o *VerifyImageSignatureOptions) Run() error {
	img, err := o.Client.Images().Get(o.InputImage)
	if err != nil {
		return err
	}
	if len(img.Signatures) == 0 {
		return fmt.Errorf("%s does not have any signature", img.Name)
	}

	policy, err := signature.DefaultPolicy(nil)
	if err != nil {
		return fmt.Errorf("Error reading signature verification policy: %v", err)
	}
	pc, err := signature.NewPolicyContext(policy)
	if err != nil {
		return fmt.Errorf("Error preparing for signature verification: %v", err)
	}
	defer pc.Destroy()

	for i, s := range img.Signatures {
		// If --remove is specified, just erase the existing signature verification for all
		// signatures.
		// TODO: This should probably need to handle removal of a single signature.
		if o.Remove {
			o.clearSignatureVerificationStatus(&img.Signatures[i])
			continue
		}

		// Verify the signature against the policy
		signedBy, err := o.verifySignature(pc, img, s.Content)
		if err != nil {
			fmt.Fprintf(o.ErrOut, "error verifying %s signature %d: %v\n", o.InputImage, i, err)
			o.clearSignatureVerificationStatus(&img.Signatures[i])
			continue
		}
		fmt.Fprintf(o.Out, "%s signature %d is verified (signed by key: %q)\n", o.InputImage, i, signedBy)

		now := unversioned.Now()
		newConditions := []imageapi.SignatureCondition{
			{
				Type:               imageapi.SignatureTrusted,
				Status:             kapi.ConditionTrue,
				LastProbeTime:      now,
				LastTransitionTime: now,
				Reason:             "verified manually",
				Message:            fmt.Sprintf("verified by user %s", o.CurrentUser),
			},
			// FIXME: This condition is required to be set for validation.
			{
				Type:               imageapi.SignatureForImage,
				Status:             kapi.ConditionTrue,
				LastProbeTime:      now,
				LastTransitionTime: now,
			},
		}
		img.Signatures[i].Conditions = newConditions
		img.Signatures[i].IssuedBy = &imageapi.SignatureIssuer{}
		// TODO: This should not be just a key id but a human-readable identity.
		img.Signatures[i].IssuedBy.CommonName = signedBy
	}

	if o.Confirm {
		_, err := o.Client.Images().Update(img)
		return err
	}
	fmt.Fprintf(o.Out, "(add --confirm to record signature verification status to server)\n")
	return nil
}
