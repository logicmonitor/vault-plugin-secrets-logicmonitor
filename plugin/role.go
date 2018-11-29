package lmsecrets

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/logicmonitor/lm-sdk-go/client/lm"

	lmclient "github.com/logicmonitor/lm-sdk-go/client"
	"github.com/logicmonitor/lm-sdk-go/models"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
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

func (r *Role) buildLMUser(ctx context.Context, s logical.Storage) (*models.Admin, error) {
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

	email := defaultEmail
	defaultUser := &models.Admin{
		AcceptEULA: true,
		Email:      &email,
		Note:       fmt.Sprintf(roleAccountNoteTmpl, r.Name),
		Password:   &pw,
		Roles:      roles,
		Username:   &username,
	}

	// if we can't get a client, just bail and return the generic user
	_, client, err := newLMClient(ctx, s)
	if err != nil {
		return defaultUser, nil
	}

	// attempt to update existing user if it exists
	oldUser, err := getLMUserByName(client, username)
	if err == nil && oldUser != nil {
		oldUser.Roles = roles
		return oldUser, nil
	}
	return defaultUser, nil
}

func (r *Role) buildLMRoles() ([]*models.Role, error) {
	var roles []*models.Role
	for _, i := range r.RoleIDs {
		t := models.Role{}
		t.ID = i
		roles = append(roles, &t)
	}
	return roles, nil
}

func getLMRoleIds(client *lmclient.LMSdkGo, roles []string) ([]int32, error) {
	var ret []int32
	for _, n := range roles {
		role, err := getLMRoleByName(client, n)
		if err != nil {
			return nil, err
		}
		ret = append(ret, role.ID)
	}
	return ret, nil
}

func getLMRoleByName(client *lmclient.LMSdkGo, name string) (*models.Role, error) {
	filter := fmt.Sprintf("name:\"%s\"", url.QueryEscape(strings.Trim(name, " ")))
	params := lm.NewGetRoleListParams()
	params.SetFilter(&filter)
	params.SetOffset(utilities.LiteralInt32Pointer(int32(0)))
	params.SetSize(utilities.LiteralInt32Pointer(int32(-1)))
	response, err := client.LM.GetRoleList(params)
	if err != nil {
		return nil, fmt.Errorf("Failed to get roles list when searching for %q: %s", name, err)
	}

	for _, r := range response.Payload.Items {
		if *r.Name == name {
			return r, nil
		}
	}
	return nil, fmt.Errorf("LogicMonitor role %q not found", name)
}

func getLMUserByName(client *lmclient.LMSdkGo, name string) (*models.Admin, error) {
	filter := fmt.Sprintf("username:\"%s\"", url.QueryEscape(name))
	params := lm.NewGetAdminListParams()
	params.SetFilter(&filter)
	params.SetOffset(utilities.LiteralInt32Pointer(int32(0)))
	params.SetSize(utilities.LiteralInt32Pointer(int32(-1)))
	response, err := client.LM.GetAdminList(params)
	if err != nil {
		return nil, fmt.Errorf("Failed to get users list when searching for %q: %v", name, err)
	}

	for _, u := range response.Payload.Items {
		if *u.Username == name {
			return u, nil
		}
	}
	return nil, nil
}

func deleteLMUser(ctx context.Context, client *lmclient.LMSdkGo, id int32) error {
	params := lm.NewDeleteAdminByIDParams()
	params.SetID(id)
	_, err := client.LM.DeleteAdminByID(params)
	if err != nil {
		return fmt.Errorf("Failed to delete user %q: %v", id, err)
	}
	return nil
}

func createUpdateLMUser(ctx context.Context, client *lmclient.LMSdkGo, user *models.Admin) (*models.Admin, error) {
	oldUser, err := getLMUserByName(client, *user.Username)
	if err != nil {
		return nil, err
	}

	if oldUser == nil {
		params := lm.NewAddAdminParams()
		params.SetBody(user)
		response, err2 := client.LM.AddAdmin(params)
		if err2 != nil {
			return nil, fmt.Errorf("Failed to create user: %v", err2)
		}
		return response.Payload, nil
	}

	// user exists. update.
	params := lm.NewUpdateAdminByIDParams()
	params.SetBody(user)
	params.SetID(oldUser.ID)
	response, err := client.LM.UpdateAdminByID(params)
	if err != nil {
		return nil, fmt.Errorf("Failed to update user: %v", err)
	}
	return response.Payload, nil
}
