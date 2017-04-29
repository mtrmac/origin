package image

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/containers/image/docker"
	"github.com/containers/image/image"
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
	DockerToken       string

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
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return err
	}
	if clientConfig.BearerToken == "" {
		return errors.New("you must use a client config with a token")
	}
	o.DockerToken = clientConfig.BearerToken

	if len(args) != 1 {
		return kcmdutil.UsageError(cmd, "exactly one image must be specified")
	}
	o.InputImage = args[0]
	if len(o.ExpectedIdentity) == 0 {
		return kcmdutil.UsageError(cmd, "the --expected-identity must be specified")
	}

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
	memoryImage, err := o.newUnparsedImage(img, sigBlob)
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

// unparsedImage wraps a sigtypes.UnparsedImage, overriding it so that
// we are verifying only a single signature.
type unparsedImage struct {
	sigtypes.UnparsedImage
	signature []byte
}

// Signatures is like ImageSource.GetSignatures, but the result is cached; it is OK to call this however often you need.
func (ui *unparsedImage) Signatures() ([][]byte, error) {
	return [][]byte{ui.signature}, nil
}

func (o *VerifyImageSignatureOptions) newUnparsedImage(img *imageapi.Image, signature []byte) (sigtypes.UnparsedImage, error) {
	ref, err := docker.ParseReference("//" + img.DockerImageReference)
	if err != nil {
		return nil, fmt.Errorf("Invalid dockerImageReference %s for %s: %v", img.DockerImageReference, o.InputImage, err)
	}
	src, err := ref.NewImageSource(&sigtypes.SystemContext{
		DockerAuthConfig: &sigtypes.DockerAuthConfig{
			Username: "unused",
			Password: o.DockerToken,
		}}, nil)
	if err != nil {
		return nil, fmt.Errorf("Error initializing image %s: %v", o.InputImage, err)
	}
	return &unparsedImage{UnparsedImage: image.UnparsedFromSource(src), signature: signature}, nil
}

func (o *VerifyImageSignatureOptions) Run() error {
	img, err := o.Client.Images().Get(o.InputImage)
	if err != nil {
		return err
	}
	if len(img.Signatures) == 0 {
		return fmt.Errorf("%s does not have any signature", img.Name)
	}

	prm, err := signature.NewPRMExactReference(o.ExpectedIdentity)
	if err != nil {
		return fmt.Errorf("Error setting up signature verification policy reference matcher: %v", err)
	}
	pr, err := signature.NewPRSignedByKeyPath(signature.SBKeyTypeGPGKeys, o.PublicKeyFilename, prm)
	if err != nil {
		return fmt.Errorf("Error setting up signature verification policy: %v", err)
	}
	policy := &signature.Policy{Default: []signature.PolicyRequirement{pr}}
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
