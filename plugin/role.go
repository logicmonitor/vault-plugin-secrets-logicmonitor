package lmsecrets

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/antihax/optional"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
	lm "github.com/logicmonitor/lm-sdk-go"
	"github.com/logicmonitor/vault-plugin-secrets-logicmonitor/utilities"
)

const (
	defaultEmail          = "vault@logicmonitor.com"
	roleAccountNoteTmpl   = "Managed by Vault. Role account for LM secrets backend role %q"
	roleAccountNamePrefix = "vault_"
	roleAccountNameSuffix = "_role"
)

// Role struct for storing data about the secret role
type Role struct {
	Name               string
	Roles              string
	RoleIDs            []int32
	ServiceAccountName string
	ServiceAccountID   int32
}

func (r *Role) validate() error {
	var err *multierror.Error
	if r.Name == "" {
		err = multierror.Append(err, errors.New("role name is empty"))
	}

	if len(r.Roles) == 0 {
		err = multierror.Append(err, fmt.Errorf("role bindings cannot be empty"))
	}

	if r.ServiceAccountName == "" {
		err = multierror.Append(err, errors.New("service account name is empty"))
	}

	if r.ServiceAccountID < 1 {
		err = multierror.Append(err, errors.New("service account id is empty"))
	}

	return err.ErrorOrNil()
}

func (r *Role) delete(ctx context.Context, s logical.Storage) error {
	err := s.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePrefix, r.Name))
	return err
}

func (r *Role) save(ctx context.Context, s logical.Storage) error {
	if err := r.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePrefix, r.Name), r)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (r *Role) getServiceAccountName() (string, error) {
	if r.ServiceAccountName != "" {
		return r.ServiceAccountName, nil
	}
	if r.Name != "" {
		return roleAccountNamePrefix + r.Name + roleAccountNameSuffix, nil
	}
	return "", fmt.Errorf("can't generate service account name: role name not set")
}

func (r *Role) buildLMUser(ctx context.Context, s logical.Storage) (*lm.Admin, error) {
	username, err := r.getServiceAccountName()
	if err != nil {
		return nil, err
	}

	roles, err := r.buildLMRoles()
	if err != nil {
		return nil, err
	}

	pw, err := utilities.GeneratePassword()
	if err != nil {
		return nil, err
	}

	defaultUser := &lm.Admin{
		AcceptEULA: true,
		Email:      defaultEmail,
		Note:       fmt.Sprintf(roleAccountNoteTmpl, r.Name),
		Password:   pw,
		Roles:      roles,
		Username:   username,
	}

	// if we can't get a client, just bail and return the generic user
	ctx, client, err := newLMClient(ctx, s)
	if err != nil {
		return defaultUser, nil
	}

	// attempt to update existing user if it exists
	oldUser, err := getLMUserByName(ctx, client, username)
	if err == nil && oldUser != nil {
		oldUser.Roles = roles
		return oldUser, nil
	}
	return defaultUser, nil
}

func (r *Role) buildLMRoles() ([]lm.Role, error) {
	var roles []lm.Role
	for _, i := range r.RoleIDs {
		t := lm.Role{}
		t.Id = i
		roles = append(roles, t)
	}
	return roles, nil
}

func getLMRoleIds(ctx context.Context, client *lm.APIClient, roles []string) ([]int32, error) {
	var ret []int32
	for _, n := range roles {
		role, err := getLMRoleByName(ctx, client, n)
		if err != nil {
			return nil, err
		}
		ret = append(ret, role.Id)
	}
	return ret, nil
}

func getLMRoleByName(ctx context.Context, client *lm.APIClient, name string) (*lm.Role, error) {
	opts := lm.GetRoleListOpts{
		Size:   optional.NewInt32(-1),
		Offset: optional.NewInt32(0),
		Filter: optional.NewString(fmt.Sprintf("name:%s", url.QueryEscape(strings.Trim(name, " ")))),
	}
	restResponse, apiResponse, err := client.DefaultApi.GetRoleList(ctx, &opts)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return nil, fmt.Errorf("Failed to get roles list when searching for %q: %v", name, _err)
	}

	for _, r := range restResponse.Data.Items {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("LogicMonitor role %q not found", name)
}

func getLMUserByName(ctx context.Context, client *lm.APIClient, name string) (*lm.Admin, error) {
	opts := lm.GetAdminListOpts{
		Size:   optional.NewInt32(-1),
		Offset: optional.NewInt32(0),
		Filter: optional.NewString(fmt.Sprintf("username:%s", url.QueryEscape(name))),
	}
	restResponse, apiResponse, err := client.DefaultApi.GetAdminList(ctx, &opts)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return nil, fmt.Errorf("Failed to get users list when searching for %q: %v", name, _err)
	}

	for _, u := range restResponse.Data.Items {
		if u.Username == name {
			return &u, nil
		}
	}
	return nil, nil
}

// func getLMUserByID(ctx context.Context, client *lm.APIClient, id int32) (*lm.Admin, error) {
// 	opts := lm.GetAdminByIdOpts{}
// 	restResponse, apiResponse, err := client.DefaultApi.GetAdminById(ctx, id, &opts)
// 	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
// 		return nil, fmt.Errorf("Failed to get users list when searching for %q: %v", id, _err)
// 	}
// 	return restResponse.Data, nil
// }

func deleteLMUser(ctx context.Context, client *lm.APIClient, id int32) error {
	restResponse, apiResponse, err := client.DefaultApi.DeleteAdminById(ctx, id)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return fmt.Errorf("Failed to delete user %q: %v", id, _err)
	}
	return nil
}

func createUpdateLMUser(ctx context.Context, client *lm.APIClient, user *lm.Admin) (*lm.Admin, error) {
	oldUser, err := getLMUserByName(ctx, client, user.Username)
	if err != nil {
		return nil, err
	}

	if oldUser == nil {
		restResponse, apiResponse, err2 := client.DefaultApi.AddAdmin(ctx, *user)
		if _err := utilities.CheckAllErrors(restResponse, apiResponse, err2); _err != nil {
			return nil, fmt.Errorf("Failed to create user: %v", _err)
		}
		return restResponse.Data, nil
	}

	// user exists. update.
	opts := lm.UpdateAdminByIdOpts{}

	restResponse, apiResponse, err := client.DefaultApi.UpdateAdminById(ctx, oldUser.Id, *user, &opts)
	if _err := utilities.CheckAllErrors(restResponse, apiResponse, err); _err != nil {
		return nil, fmt.Errorf("Failed to update user: %v", _err)
	}
	return restResponse.Data, nil
}
