package icpdv1_test

import (
	"fmt"
	"go-sdk-template/icpdv1"
	"testing"

	"github.com/IBM/go-sdk-core/core"
	"github.com/stretchr/testify/assert"
)

var service *icpdv1.IcpdV1
var serviceErr error

func init() {

	service, serviceErr = icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
		URL: "https://zen-cp4d2-cpd-zen-cp4d2.apps.xen-cp4dss-oct-2-lb-1.fyre.ibm.com/icp4d-api",
		Authenticator: &core.BearerTokenAuthenticator{
			BearerToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViIjoiYWRtaW4iLCJpc3MiOiJLTk9YU1NPIiwiYXVkIjoiRFNYIiwicm9sZSI6IkFkbWluIiwicGVybWlzc2lvbnMiOlsiYWRtaW5pc3RyYXRvciIsImNhbl9wcm92aXNpb24iXSwidWlkIjoiMTAwMDMzMDk5OSIsImF1dGhlbnRpY2F0b3IiOiJkZWZhdWx0IiwiZGlzcGxheV9uYW1lIjoiYWRtaW4iLCJpYXQiOjE1Njk1NjU5NTcsImV4cCI6MTU2OTYwOTE1N30.HD6gqu1FeFKJhNBQj-RMapWzYP6qCk8dQBYScwOf6jeKvfCf1eApIsHM8jWgClH2K0IESSXq88818dJr4qYnxly4NRB8NhGJYEdhhuTw6ONE3yfN4A_yWurJymfQAyfutye41aU8_d4sgH3_cBLkAuO-zmdiPghVikxRYCtHfjADIdK1vz_TQWGzOSXAmgHe7SR_YnVVMtce5BTRuat29dYYLbUQ-Gxr76G9VMm_TPJEL5sUAAT2SenmjsMDP7nFufZtmSahDlLX5DtPY5vYtCClefZhVPM1exs-5T25hAdWZ1cOVzG7IiFrwSjOgqWOS9MxfW-IojTjf-uUbg4meA",
		},
	})

	// Check successful instantiation
	if serviceErr != nil {
		fmt.Println(serviceErr)
		return
	}

	service.Service.DisableSSLVerification()

}

func shouldSkipTest(t *testing.T) {
	if service == nil {
		t.Skip("Skipping test as service credentials are missing")
	}
}

func TestUserManagement(t *testing.T) {
	shouldSkipTest(t)

	//Get all users
	response, responseErr := service.GetAllUsers(
		&icpdv1.GetAllUsersOptions{},
	)
	assert.Nil(t, responseErr)

	allUsers := service.GetGetAllUsersResult(response)
	assert.NotNil(t, allUsers)

	//t.Skip("Skip rest of user API tests")

	// Create user
	response, responseErr = service.CreateUser(
		&icpdv1.CreateUserOptions{
			DisplayName: core.StringPtr("Test BA"),
			Email:       core.StringPtr("testba@gmail.com"),
			UserName:    core.StringPtr("testbusinessanalyst"),
			UserRoles:   []string{"Business Analyst"},
		},
	)

	assert.Nil(t, responseErr)

	createUser := service.GetCreateUserResult(response)
	assert.NotNil(t, createUser)

	//Get user
	response, responseErr = service.GetUser(
		&icpdv1.GetUserOptions{
			UserName: core.StringPtr("testuser"),
		},
	)
	assert.Nil(t, responseErr)

	getUser := service.GetGetUserResult(response)
	assert.NotNil(t, getUser)

	// Update user
	response, responseErr = service.UpdateUser(
		&icpdv1.UpdateUserOptions{
			UserName:       core.StringPtr("testbusinessanalyst"),
			ApprovalStatus: core.StringPtr("approved"),
			DisplayName:    core.StringPtr("Test BA"),
			Email:          core.StringPtr("testba@gmail.com"),
			UserRoles:      []string{"Data Engineer"},
		},
	)
	assert.Nil(t, responseErr)

	UpdateUser := service.GetUpdateUserResult(response)
	assert.NotNil(t, UpdateUser)

	//Delete user
	response, responseErr = service.DeleteUser(
		&icpdv1.DeleteUserOptions{
			UserName: core.StringPtr("testbusinessanalyst"),
		},
	)
	assert.Nil(t, responseErr)
}

func TestRoleManagement(t *testing.T) {
	shouldSkipTest(t)

	//List all roles
	response, responseErr := service.GetAllRoles(
		&icpdv1.GetAllRolesOptions{},
	)
	assert.Nil(t, responseErr)

	allRoles := service.GetGetAllRolesResult(response)
	assert.NotNil(t, allRoles)

	//t.Skip("Skip rest of user API tests")

	// Create role
	response, responseErr = service.CreateRole(
		&icpdv1.CreateRoleOptions{
			RoleName:    core.StringPtr("Administrator"),
			Description: core.StringPtr("Testing Role"),
			Permissions: []string{"administrator", "deployment_admin"},
		},
	)
	assert.Nil(t, responseErr)

	createRole := service.GetCreateRoleResult(response)
	assert.NotNil(t, createRole)

	//list all permissions
	response, responseErr = service.GetAllPermissions(
		&icpdv1.GetAllPermissionsOptions{},
	)
	assert.Nil(t, responseErr)

	allPermissions := service.GetGetAllPermissionsResult(response)
	assert.NotNil(t, allPermissions)

	//Get role information
	response, responseErr = service.GetRole(
		&icpdv1.GetRoleOptions{
			RoleName: core.StringPtr("Administrator"),
		},
	)
	assert.Nil(t, responseErr)

	getRole := service.GetGetRoleResult(response)
	assert.NotNil(t, getRole)

	//Update role
	response, responseErr = service.UpdateRole(
		&icpdv1.UpdateRoleOptions{
			RoleName:    core.StringPtr("Administrator"),
			Description: core.StringPtr("Admin role"),
		},
	)
	assert.Nil(t, responseErr)

	UpdateRole := service.GetUpdateAssetBundleResult(response)
	assert.NotNil(t, UpdateRole)

	//Delete role
	response, responseErr = service.DeleteRole(
		&icpdv1.DeleteRoleOptions{
			RoleName: core.StringPtr("Administrator"),
		},
	)
	assert.Nil(t, responseErr)
}

func TestAccountManagement(t *testing.T) {
	shouldSkipTest(t)

	//Change my password
	response, responseErr := service.ChangePassword(
		&icpdv1.ChangePasswordOptions{
			Password: core.StringPtr("NewPassword"),
		},
	)
	assert.Nil(t, responseErr)

	ChangePassword := service.GetChangePasswordResult(response)
	assert.NotNil(t, ChangePassword)

	//Get my account information
	response, responseErr = service.GetMe(
		&icpdv1.GetMeOptions{},
	)
	assert.Nil(t, responseErr)

	getMe := service.GetGetMeResult(response)
	assert.NotNil(t, getMe)

	//Update my information
	response, responseErr = service.UpdateMe(
		&icpdv1.UpdateMeOptions{
			DisplayName: core.StringPtr("New Display Name"),
			Email:       core.StringPtr("newEmail@gmail.com"),
		},
	)
	assert.Nil(t, responseErr)

	UpdateMe := service.GetUpdateMeResult(response)
	assert.NotNil(t, UpdateMe)
}
