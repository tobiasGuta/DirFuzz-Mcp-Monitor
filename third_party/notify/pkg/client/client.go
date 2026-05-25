package client

import (
	"github.com/projectdiscovery/notify/pkg/providers"
	"github.com/projectdiscovery/notify/pkg/types"
)

type Client = providers.Client

func New(providerOptions *providers.ProviderOptions, options *types.Options) (*Client, error) {
	return providers.New(providerOptions, options)
}
