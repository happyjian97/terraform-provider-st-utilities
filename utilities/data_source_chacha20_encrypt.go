package utilities

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
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
	SecretKey                   types.String `tfsdk:"secret_key"`
	StringValue                 types.String `tfsdk:"string_value"`
	AdditionalAuthenticatedData types.String `tfsdk:"additional_authenticated_data"`
	EncryptedStringValue        types.String `tfsdk:"encrypted_string_value"`
}

func (d *chacha20EncryptDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_chacha20_encrypt"
}

func (d *chacha20EncryptDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"secret_key": schema.StringAttribute{
				Description: "Hex-encoded 32-byte (256-bit) key used for XChaCha20-Poly1305 encryption. Must be exactly 64 hexadecimal characters (e.g. 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef).",
				Required:    true,
				Sensitive:   true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-fA-F]{64}$`), "must be exactly 64 hexadecimal characters (32 bytes)"),
				},
			},
			"string_value": schema.StringAttribute{
				Description: "The value to be encrypted with chacha20. This can be either a JSON string (which will be minified and trimmed before encryption) or a plain string (which will be trimmed before encryption).",
				Required:    true,
			},
			"additional_authenticated_data": schema.StringAttribute{
				Description: "Optional additional data to authenticate but not encrypt. The same value must be provided when decrypting. If the AAD is tampered with, decryption will fail.",
				Optional:    true,
			},
			"encrypted_string_value": schema.StringAttribute{
				Description: "JSON object containing hex-encoded nonce (24B), base64-encoded ciphertext (includes auth tag), and base64-encoded additional authenticated data (AAD).",
				Computed:    true,
				Sensitive:   true,
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

	aad := plan.AdditionalAuthenticatedData.ValueString()
	encrypted, err := encryptChaCha20(plan.SecretKey.ValueString(), plan.StringValue.ValueString(), aad)
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

// chacha20EncryptOutput is the JSON structure returned by encryptChaCha20.
type chacha20EncryptOutput struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// encryptChaCha20 prepares the input and encrypts it with XChaCha20-Poly1305
// AEAD. The input may be either a JSON string or a plain string: if it parses
// as valid JSON it is minified (compacted) and trimmed; otherwise it is treated
// as a plain string and merely trimmed. The 32-byte key is derived from the
// provided key (a 64-character hex string representing 32 bytes). A random 24-byte nonce is generated for each
// encryption. The optional AAD (additional authenticated data) is authenticated
// but not encrypted -- the same AAD must be provided to decrypt. The Poly1305
// auth tag provides integrity. It returns a JSON
// string with three separate fields:
//
//	{"nonce":"<hex>","ciphertext":"<base64>","tag":"<base64>"}
//
// where ciphertext includes the 16-byte Poly1305 auth tag (needed for
// decryption), and tag is the base64-encoded additional authenticated data.
func encryptChaCha20(key, input, aad string) (string, error) {
	// Determine the plaintext to encrypt. If the input is valid JSON, minify
	// (compact) and trim it; otherwise treat it as a plain string and just
	// trim it. This makes the data source compatible with both JSON and
	// plain-string inputs.
	plaintext := strings.TrimSpace(input)

	var jsonValue interface{}
	if err := json.Unmarshal([]byte(input), &jsonValue); err == nil {
		minifiedBytes, err := json.Marshal(jsonValue)
		if err != nil {
			return "", fmt.Errorf("failed to minify JSON: %w", err)
		}
		plaintext = strings.TrimSpace(string(minifiedBytes))
	}

	// Decode the hex-encoded 32-byte key.
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid hex key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create xchacha20-poly1305 aead: %w", err)
	}

	// Generate a random 24-byte nonce (XChaCha20 nonce size).
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal encrypts the plaintext and appends a 16-byte Poly1305 auth tag.
	// AAD (if provided) is authenticated but not encrypted. The auth tag is
	// part of the ciphertext (needed for decryption).
	sealed := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))

	output := chacha20EncryptOutput{
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		Tag:        string(aad),
	}

	outputJSON, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("failed to marshal output json: %w", err)
	}

	return string(outputJSON), nil
}
