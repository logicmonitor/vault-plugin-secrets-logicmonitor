package lmsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	lm "github.com/logicmonitor/lm-sdk-go"
	"github.com/logicmonitor/vault-plugin-secrets-logicmonitor/utilities"
)

const (
	APITokens = "api_tokens"
)

func apiTokens(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: APITokens,
		Fields: map[string]*framework.FieldSchema{
			"access_id": {
				Type:        framework.TypeString,
				Description: "LogicMonitor API Token Access ID",
			},
			"access_key": {
				Type:        framework.TypeString,
				Description: "LogicMonitor API Token Access Key",
			},
		},
		Renew:  b.tokenRenew,
		Revoke: b.tokenRevoke,
	}
}

func pathAPITokens(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("tokens/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role.",
			},
		},
		ExistenceCheck: b.pathRolesExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathAPITokensReadUpdate,
			logical.UpdateOperation: b.pathAPITokensReadUpdate,
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

func (b *backend) pathAPITokensReadUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	role, err := getRoles(roleName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}

	return b.getAPITokens(ctx, req.Storage, role)
}

func (b *backend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Access tokens do not expire so just respond with the stored info
	secretD := map[string]interface{}{
		"access_id":  req.Secret.InternalData["access_id"].(string),
		"access_key": req.Secret.InternalData["access_key"].(string),
	}
	resp := b.Secret(APITokens).Response(secretD, req.Secret.InternalData)
	return resp, nil
}

func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ctx, client, err := newLMClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	tokenIDRaw, ok := req.Secret.InternalData["token_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("secret is missing token internal data for token_id")
	}

	userIDRaw, ok := req.Secret.InternalData["user_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("secret is missing token internal data for user_id")
	}

	userID := int32(userIDRaw)
	tokenID := int32(tokenIDRaw)

	restResponse, apiResponse, err := client.DeleteApiTokenById(ctx, userID, tokenID)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return nil, fmt.Errorf("Failed to delete api token %v from user %v: %v", tokenID, userID, _err)
	}
	return nil, err
}

func (b *backend) getAPITokens(ctx context.Context, s logical.Storage, r *Role) (*logical.Response, error) {
	ctx, client, err := newLMClient(ctx, s)
	if err != nil {
		return nil, err
	}

	token := lm.ApiToken{
		Note: "Managed by Vault",
	}

	restResponse, apiResponse, err := client.AddApiTokenByAdminId(ctx, r.ServiceAccountID, token)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return nil, fmt.Errorf("Failed to create API tokens for user %d: %v", r.ServiceAccountID, _err)
	}
	token = *restResponse.Data

	secretD := map[string]interface{}{
		"access_id":  token.AccessId,
		"access_key": token.AccessKey,
	}
	internalD := map[string]interface{}{
		"access_id":  token.AccessId,
		"access_key": token.AccessKey,
		"token_id":   token.Id,
		"role":       r.Name,
		"user_id":    r.ServiceAccountID,
	}
	resp := b.Secret(APITokens).Response(secretD, internalD)
	return resp, err
}

const pathTokenHelpSyn = `Generate a set of LogicMonitor API access tokens.`

const pathTokenHelpDesc = `
This path will generate a new set LogicMonitor API access tokens. These tokens
will have permissions scoped to the configured LogicMonitor roles. The API
tokens will be revoked when the lease expires.

`
