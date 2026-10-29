package utilities

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ provider.Provider = &utilitiesProvider{}
)

func New() provider.Provider {
	return &utilitiesProvider{}
}

type utilitiesProvider struct{}

func (p *utilitiesProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "st-utilities"
}

func (p *utilitiesProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *utilitiesProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

func (p *utilitiesProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewChacha20EncryptDataSource,
		NewModuleTemplateDataSource,
	}
}

func (p *utilitiesProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}
