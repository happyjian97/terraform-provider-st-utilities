package utilities

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	_ datasource.DataSource = &chacha20EncryptDataSource{}
)

func NewChacha20EncryptDataSource() datasource.DataSource {
	return &chacha20EncryptDataSource{}
}

type chacha20EncryptDataSource struct{}

type chacha20EncryptDataSourceModel struct {
	EncryptKey           types.String `tfsdk:"encrypt_key"`
	StringValue          types.String `tfsdk:"string_value"`
	EncryptedStringValue types.String `tfsdk:"encrypted_string_value"`
}

func (d *chacha20EncryptDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_chacha20_encrypt"
}

func (d *chacha20EncryptDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"encrypt_key": schema.StringAttribute{
				Description: "Key that used for chacha20 Encryption. Must be between 16 and 32 characters long.",
				Required:    true,
				Sensitive:   true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(16, 32),
				},
			},
			"string_value": schema.StringAttribute{
				Description: "The value to be encrypted with chacha20. This can be either a JSON string (which will be minified and trimmed before encryption) or a plain string (which will be trimmed before encryption).",
				Required:    true,
			},
			"encrypted_string_value": schema.StringAttribute{
				Description: "Output of encryted string value.",
				Computed:    true,
			},
		},
	}
}

func (d *chacha20EncryptDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var plan, state chacha20EncryptDataSourceModel

	diags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state = plan

	encrypted, err := encryptChaCha20(plan.EncryptKey.ValueString(), plan.StringValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("[Error] Failed to encrypt value", err.Error())
		return
	}
	state.EncryptedStringValue = types.StringValue(encrypted)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// encryptChaCha20 prepares the input and encrypts it with XChaCha20-Poly1305
// AEAD. The input may be either a JSON string or a plain string: if it parses
// as valid JSON it is minified (compacted) and trimmed; otherwise it is treated
// as a plain string and merely trimmed. The 32-byte key is derived from the
// provided key via SHA-256, and a deterministic 24-byte nonce is derived from
// the resulting plaintext via SHA-256. Using a deterministic nonce keeps
// Terraform plans stable (the same input always yields the same ciphertext).
// The Poly1305 auth tag appended by Seal provides integrity — any tampering
// with the ciphertext is detected on decryption (aead.Open). It returns the
// base64-encoded ciphertext (plaintext + 16-byte auth tag).
func encryptChaCha20(key, input string) (string, error) {
	// Determine the plaintext to encrypt. If the input is valid JSON, minify
	// (compact) and trim it; otherwise treat it as a plain string and just
	// trim it. This makes the data source compatible with both JSON and
	// plain-string inputs.
	plaintext := strings.TrimSpace(input)

	var jsonValue interface{}
	if err := json.Unmarshal([]byte(input), &jsonValue); err == nil {
		// Input is valid JSON — re-marshal to compact/minified form.
		minifiedBytes, err := json.Marshal(jsonValue)
		if err != nil {
			return "", fmt.Errorf("failed to minify JSON: %w", err)
		}
		plaintext = strings.TrimSpace(string(minifiedBytes))
	}

	// Derive the 32-byte key from the user-provided key using SHA-256 so
	// any-length key satisfies chacha20poly1305.KeySize (32).
	keyHash := sha256.Sum256([]byte(key))

	// Derive a deterministic 24-byte nonce from the plaintext so that the same
	// input always produces the same ciphertext. The XChaCha20 variant uses a
	// 24-byte nonce (NonceSizeX), which is large enough that random nonces
	// would also be safe; we keep it deterministic for Terraform plan
	// stability. Equal plaintexts will yield equal ciphertexts, which is
	// acceptable for this utility.
	nonceHash := sha256.Sum256([]byte(plaintext))

	aead, err := chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		return "", fmt.Errorf("failed to create xchacha20-poly1305 aead: %w", err)
	}

	// Seal encrypts the plaintext and appends a 16-byte Poly1305 auth tag.
	ciphertext := aead.Seal(nil, nonceHash[:chacha20poly1305.NonceSizeX], []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
