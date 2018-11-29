package lmsecrets

import (
	"context"
	"fmt"

	lmclient "github.com/logicmonitor/lm-sdk-go/client"
	"github.com/logicmonitor/lm-sdk-go/client/lm"
	"github.com/logicmonitor/lm-sdk-go/models"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/logicmonitor/vault-plugin-secrets-logicmonitor/utilities"
)

const (
	// APITokens identifies the key used to store API token values
	APITokens = "api_tokens"
)

func apiTokens(b *BackendLM) *framework.Secret {
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

func pathAPITokens(b *BackendLM) *framework.Path {
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

func (b *BackendLM) pathAPITokensReadUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	role, err := getRoles(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}

	ctx, client, err := newLMClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return b.getAPITokens(ctx, client, role)
}

func (b *BackendLM) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Access tokens do not expire so just respond with the stored info
	secretD := map[string]interface{}{
		"access_id":  req.Secret.InternalData["access_id"].(string),
		"access_key": req.Secret.InternalData["access_key"].(string),
	}
	resp := b.Secret(APITokens).Response(secretD, req.Secret.InternalData)
	return resp, nil
}

func (b *BackendLM) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, client, err := newLMClient(ctx, req.Storage)
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

	params := lm.NewDeleteAPITokenByIDParams()
	params.SetAdminID(int32(userIDRaw))
	params.SetApitokenID(int32(tokenIDRaw))
	_, err = client.LM.DeleteAPITokenByID(params)
	if err != nil {
		return nil, fmt.Errorf("Failed to delete api token %v from user %v: %v", params.ApitokenID, params.AdminID, err)
	}
	return nil, err
}

func (b *BackendLM) getAPITokens(ctx context.Context, client *lmclient.LMSdkGo, r *Role) (*logical.Response, error) {
	params := lm.NewGetAPITokenListByAdminIDParams()
	params.SetAdminID(r.ServiceAccountID)
	params.SetOffset(utilities.LiteralInt32Pointer(int32(0)))
	params.SetSize(utilities.LiteralInt32Pointer(int32(-1)))

	token := &models.APIToken{
		Note: fmt.Sprintf("Managed by Vault. Temporary token for Vault role %s", r.Name),
	}

	addParams := lm.NewAddAPITokenByAdminIDParams()
	addParams.SetAdminID(r.ServiceAccountID)
	addParams.SetBody(token)

	response, err := client.LM.AddAPITokenByAdminID(addParams)
	if err != nil {
		return nil, fmt.Errorf("Failed to create API tokens for user %d: %v", r.ServiceAccountID, err)
	}
	token = response.Payload

	secretD := map[string]interface{}{
		"access_id":  token.AccessID,
		"access_key": token.AccessKey,
	}
	internalD := map[string]interface{}{
		"access_id":  token.AccessID,
		"access_key": token.AccessKey,
		"token_id":   token.ID,
		"role":       r.Name,
		"user_id":    r.ServiceAccountID,
	}
	resp := b.Secret(APITokens).Response(secretD, internalD)
	return resp, err
}

// nolint: gosec
const pathTokenHelpSyn = `Generate a set of LogicMonitor API access tokens.`

const pathTokenHelpDesc = `
This path will generate a new set LogicMonitor API access tokens. These tokens
will have permissions scoped to the configured LogicMonitor roles. The API
tokens will be revoked when the lease expires.

`
