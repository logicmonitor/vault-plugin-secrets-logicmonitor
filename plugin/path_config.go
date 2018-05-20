package lmsecrets

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	lm "github.com/logicmonitor/lm-sdk-go"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"account_domain": {
				Type:        framework.TypeString,
				Description: `LogicMonitor account domain. Example: vault.logicmonitor.com`,
			},
			"access_id": {
				Type:        framework.TypeString,
				Description: `LogicMonitor API token Access ID with permissions to create new user accounts and set account roles`,
			},
			"access_key": {
				Type:        framework.TypeString,
				Description: `LogicMonitor API token Access Key with permissions to create new user accounts and set account roles`,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease for generated keys. If <= 0, will use system default.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum time a service account key is valid for. If <= 0, will use system default.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	var key string
	if cfg.APIKey.Key == "" {
		key = "n/a"
	} else {
		key = "<sensitive>"
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account_domain": string(cfg.AccountDomain),
			"ttl":            int64(cfg.TTL / time.Second),
			"max_ttl":        int64(cfg.MaxTTL / time.Second),
			"access_key":     key,
			"access_id":      string(cfg.APIKey.ID),
		},
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	AccountDomain, ok := data.GetOk("account_domain")
	if ok {
		match, err := regexp.MatchString(".logicmonitor.com$", AccountDomain.(string))
		if !match {
			return logical.ErrorResponse("invalid account url: must be a .logicmonitor.com address"), nil
		}
		addrs, err := net.LookupHost(AccountDomain.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid account url: %v", err)), nil
		}
		if len(addrs) < 1 {
			return logical.ErrorResponse("invalid account url: no addresses found"), nil
		}
		cfg.AccountDomain = strings.Replace(AccountDomain.(string), "https://", "", 1)
		cfg.AccountDomain = strings.Replace(AccountDomain.(string), "http://", "", 1)
	}

	accessID, ok := data.GetOk("access_id")
	if ok {
		cfg.APIKey.ID = accessID.(string)
	}

	accessKey, ok := data.GetOk("access_key")
	if ok {
		cfg.APIKey.Key = accessKey.(string)
	}

	// Update token TTL.
	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		cfg.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	// Update token Max TTL.
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if ok {
		cfg.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

type config struct {
	AccountDomain string
	APIKey        lm.APIKey

	TTL    time.Duration
	MaxTTL time.Duration
}

func getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	var cfg config
	cfgRaw, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if cfgRaw == nil {
		return nil, nil
	}

	if err := cfgRaw.DecodeJSON(&cfg); err != nil {
		return nil, err
	}

	return &cfg, err
}

const pathConfigHelpSyn = `
Configure the LogicMonitor backend.
`

const pathConfigHelpDesc = `
The LogicMonitor backend requires credentials for managing service accounts and
keys. This endpoint is used to configure those credentials as well as default
values for the backend in general.
`