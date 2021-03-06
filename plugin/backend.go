package lmsecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	lm "github.com/logicmonitor/lm-sdk-go"
)

const (
	userAgentBase = "LogicMonitor Vault Secrets/"
)

// BackendLM implementation
type BackendLM struct {
	*framework.Backend

	rolesLock sync.Mutex
}

// Factory for the backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend definition
func Backend() *BackendLM {
	var b BackendLM

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: framework.PathAppend(
			pathsRoles(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathAPITokens(&b),
			},
		),
		Secrets: []*framework.Secret{
			apiTokens(&b),
		},

		BackendType: logical.TypeLogical,
	}

	return &b
}

func newLMClient(ctx context.Context, s logical.Storage) (context.Context, *lm.APIClient, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}

	config := lm.NewConfiguration()
	config.BasePath = "https://" + cfg.AccountDomain + "/santaba/rest"
	config.UserAgent = userAgentBase

	api := lm.NewAPIClient(config)
	ctx = context.WithValue(ctx, lm.ContextAPIKey, cfg.APIKey)
	return ctx, api, nil
}

const backendHelp = `
The LogicMonitor secrets backend dynamically generates LogicMonitor
account API tokens. The service API tokens have a configurable
lease set and are automatically revoked at the end of the lease.

After mounting this backend, credentials to generate API tokens must
be configured with the "config/" endpoints and policies must be
written using the "roles/" endpoints before any keys can be generated.
`
