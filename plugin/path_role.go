package lmsecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	rolesStoragePrefix = "roles"
	roleType           = "role"
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

	role, err := getRoles(nameRaw.(string), ctx, req.Storage)
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

	role, err := getRoles(nameRaw.(string), ctx, req.Storage)
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

	role, err := getRoles(roleName, ctx, req.Storage)
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

	role, err := getRoles(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		role = &Role{
			Name: name,
		}
	}

	isCreate := req.Operation == logical.CreateOperation

	// Role Bindings
	roles, newRoles := d.GetOk("roles")
	roleNames := strings.Split(roles.(string), ",")
	if roles == "" || len(roleNames) < 1 {
		return logical.ErrorResponse("given empty roles string"), nil
	}

	if isCreate && newRoles == false {
		return logical.ErrorResponse("roles are required for new role"), nil
	}

	ctx, client, err := newLMClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	role.Roles = roles.(string)
	rolesInt, err := b.getLMRoleIds(ctx, client, roleNames)
	if err != nil {
		return nil, err
	}
	role.RolesInt = rolesInt

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

func getRoles(name string, ctx context.Context, s logical.Storage) (*Role, error) {
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
