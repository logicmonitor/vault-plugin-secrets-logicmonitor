package lmsecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	lm "github.com/logicmonitor/lm-sdk-go"
)

const (
	rolesStoragePrefix = "roles"
)

func pathsRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("roles/%s", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Required. Name of the role.",
				},
				"roles": {
					Type:        framework.TypeString,
					Description: "Required. Comma-separated list of LogicMonitor account roles to bind to this role.",
				},
			},
			ExistenceCheck: b.pathRolesExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.DeleteOperation: b.pathRolesDelete,
				logical.ReadOperation:   b.pathRolesRead,
				logical.CreateOperation: b.pathRolesCreateUpdate,
				logical.UpdateOperation: b.pathRolesCreateUpdate,
			},
			HelpSynopsis:    pathRolesHelpSyn,
			HelpDescription: pathRolesHelpDesc,
		},
		// Paths for listing roles
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRolesList,
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRolesList,
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
	}
}

func (b *backend) pathRolesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return false, errors.New("role name is required")
	}

	role, err := getRoles(ctx, nameRaw.(string), req.Storage)
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := getRoles(ctx, nameRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"role":  role.Name,
		"roles": role.Roles,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	warnings := make([]string, 0)
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	roleName := nameRaw.(string)

	role, err := getRoles(ctx, roleName, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to get role %s: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, nil
	}

	b.rolesLock.Lock()
	defer b.rolesLock.Unlock()

	ctx, client, err := newLMClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	err = b.deleteLMUser(ctx, client, role.ServiceAccountID)
	if err != nil {
		warnings = append(warnings, err.Error())
	}

	if err := role.delete(ctx, req.Storage); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRolesCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	warnings := make([]string, 0)
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("role name is required"), nil
	}
	name := nameRaw.(string)

	role, err := getRoles(ctx, name, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		role = &Role{
			Name: name,
		}
	}

	ctx, client, err := newLMClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	roleIDs, roles, err := b.parseRoleIDs(ctx, client, d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	role.Roles = roles
	role.RoleIDs = roleIDs

	lmUser, err := role.buildLMUser()
	if err != nil {
		return nil, err
	}

	lmUser, err = b.createUpdateLMUser(ctx, client, lmUser)
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	role.ServiceAccountID = lmUser.Id
	role.ServiceAccountName = lmUser.Username

	if err := role.save(ctx, req.Storage); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func getRoles(ctx context.Context, name string, s logical.Storage) (*Role, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	rs := &Role{}
	if err := entry.DecodeJSON(rs); err != nil {
		return nil, err
	}
	return rs, nil
}

func (b *backend) parseRoleIDs(ctx context.Context, client *lm.DefaultApiService, d *framework.FieldData) ([]int32, string, error) {
	// Role Bindings
	roles, _ := d.GetOk("roles")
	if roles == "" {
		return nil, "", fmt.Errorf("roles are required")
	}

	roleNames := strings.Split(roles.(string), ",")
	if roles == "" || len(roleNames) < 1 {
		return nil, "", fmt.Errorf("given empty roles string")
	}

	roleIDs, err := b.getLMRoleIds(ctx, client, roleNames)
	return roleIDs, roles.(string), err
}

const pathRolesHelpSyn = `Read/write sets of LogicMonitor account roles to be given to generated credentials.`
const pathListRolesHelpSyn = `List existing roles.`

const pathRolesHelpDesc = `
This path allows you create roles, which bind to sets of LogicMonitor
accounts roles. Secrets are generated under a role and will have the
given set of roles on resources.

The specified roles must already exist in your LogicMonitor account.
For more information on managing LogicMonitor roles, see:
https://www.logicmonitor.com/support/rest-api-developers-guide/roles/
`
const pathListRolesHelpDesc = `List roles by role name`
