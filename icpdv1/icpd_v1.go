/**
 * (C) Copyright IBM Corp. 2019.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package icpdv1 : Operations and models for the IcpdV1 service
package icpdv1

import (
	"fmt"
	"os"

	"github.com/IBM/go-sdk-core/core"
	common "github.com/watson-developer-cloud/go-sdk/common"
)

// IcpdV1 : Swagger for the IBM Cloud Private for Data offerings - with Data Governance and Analytics API's
//
// Version: 1.0.0
type IcpdV1 struct {
	Service *core.BaseService
}

const defaultServiceURL = "https://i493-master-1.fyre.ibm.com:31843/icp4d-api/"

// IcpdV1Options : Service options
type IcpdV1Options struct {
	URL           string
	Authenticator core.Authenticator
}

// NewIcpdV1 : Instantiate IcpdV1
func NewIcpdV1(options *IcpdV1Options) (service *IcpdV1, err error) {
	if options.URL == "" {
		options.URL = defaultServiceURL
	}

	serviceOptions := &core.ServiceOptions{
		URL:           options.URL,
		Authenticator: options.Authenticator,
	}

	baseService, err := core.NewBaseService(serviceOptions, "icpd", "ICPD")
	if err != nil {
		return
	}

	service = &IcpdV1{
		Service: baseService,
	}

	return
}

// GetAuthorizationToken : Get authorization token
// Provide icp4d login credentials to receive authorization bearer token.
func (icpd *IcpdV1) GetAuthorizationToken(getAuthorizationTokenOptions *GetAuthorizationTokenOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getAuthorizationTokenOptions, "getAuthorizationTokenOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getAuthorizationTokenOptions, "getAuthorizationTokenOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/authorize"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAuthorizationTokenOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAuthorizationToken")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if getAuthorizationTokenOptions.Password != nil {
		body["password"] = getAuthorizationTokenOptions.Password
	}
	if getAuthorizationTokenOptions.Username != nil {
		body["username"] = getAuthorizationTokenOptions.Username
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(LoginResponse))
	return response, err
}

// GetGetAuthorizationTokenResult : Retrieve result of GetAuthorizationToken operation
func (icpd *IcpdV1) GetGetAuthorizationTokenResult(response *core.DetailedResponse) *LoginResponse {
	result, ok := response.Result.(*LoginResponse)
	if ok {
		return result
	}
	return nil
}

// GetAllUsers : Get all users
// Get all users from the cluster.
func (icpd *IcpdV1) GetAllUsers(getAllUsersOptions *GetAllUsersOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getAllUsersOptions, "getAllUsersOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/users"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAllUsersOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAllUsers")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getAllUsersOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getAllUsersOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetAllUsersResponse))
	return response, err
}

// GetGetAllUsersResult : Retrieve result of GetAllUsers operation
func (icpd *IcpdV1) GetGetAllUsersResult(response *core.DetailedResponse) *GetAllUsersResponse {
	result, ok := response.Result.(*GetAllUsersResponse)
	if ok {
		return result
	}
	return nil
}

// CreateUser : Create user
// Create a new user for the cluster.
func (icpd *IcpdV1) CreateUser(createUserOptions *CreateUserOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(createUserOptions, "createUserOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/users"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range createUserOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "CreateUser")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createUserOptions.DisplayName != nil {
		body["displayName"] = createUserOptions.DisplayName
	}
	if createUserOptions.Email != nil {
		body["email"] = createUserOptions.Email
	}
	if createUserOptions.UserName != nil {
		body["user_name"] = createUserOptions.UserName
	}
	if createUserOptions.UserRoles != nil {
		body["user_roles"] = createUserOptions.UserRoles
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(CreateUserSuccessResponse))
	return response, err
}

// GetCreateUserResult : Retrieve result of CreateUser operation
func (icpd *IcpdV1) GetCreateUserResult(response *core.DetailedResponse) *CreateUserSuccessResponse {
	result, ok := response.Result.(*CreateUserSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetUser : Get user information
// Get existing user information.
func (icpd *IcpdV1) GetUser(getUserOptions *GetUserOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getUserOptions, "getUserOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getUserOptions, "getUserOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/users"}
	pathParameters := []string{*getUserOptions.UserName}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getUserOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetUser")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getUserOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getUserOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetUserResponse))
	return response, err
}

// GetGetUserResult : Retrieve result of GetUser operation
func (icpd *IcpdV1) GetGetUserResult(response *core.DetailedResponse) *GetUserResponse {
	result, ok := response.Result.(*GetUserResponse)
	if ok {
		return result
	}
	return nil
}

// UpdateUser : Update user details
// Update an existing user information.
func (icpd *IcpdV1) UpdateUser(updateUserOptions *UpdateUserOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(updateUserOptions, "updateUserOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(updateUserOptions, "updateUserOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/users"}
	pathParameters := []string{*updateUserOptions.UserName}

	builder := core.NewRequestBuilder(core.PUT)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range updateUserOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "UpdateUser")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateUserOptions.ApprovalStatus != nil {
		body["approval_status"] = updateUserOptions.ApprovalStatus
	}
	if updateUserOptions.DisplayName != nil {
		body["displayName"] = updateUserOptions.DisplayName
	}
	if updateUserOptions.Email != nil {
		body["email"] = updateUserOptions.Email
	}
	if updateUserOptions.UserRoles != nil {
		body["user_roles"] = updateUserOptions.UserRoles
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetUpdateUserResult : Retrieve result of UpdateUser operation
func (icpd *IcpdV1) GetUpdateUserResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// DeleteUser : Delete user
// Delete user from the cluster.
func (icpd *IcpdV1) DeleteUser(deleteUserOptions *DeleteUserOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(deleteUserOptions, "deleteUserOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(deleteUserOptions, "deleteUserOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/users"}
	pathParameters := []string{*deleteUserOptions.UserName}

	builder := core.NewRequestBuilder(core.DELETE)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range deleteUserOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "DeleteUser")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if deleteUserOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*deleteUserOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetDeleteUserResult : Retrieve result of DeleteUser operation
func (icpd *IcpdV1) GetDeleteUserResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAllRoles : List all roles
// Get all roles from the cluster.
func (icpd *IcpdV1) GetAllRoles(getAllRolesOptions *GetAllRolesOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getAllRolesOptions, "getAllRolesOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAllRolesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAllRoles")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getAllRolesOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getAllRolesOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetAllRolesResponse))
	return response, err
}

// GetGetAllRolesResult : Retrieve result of GetAllRoles operation
func (icpd *IcpdV1) GetGetAllRolesResult(response *core.DetailedResponse) *GetAllRolesResponse {
	result, ok := response.Result.(*GetAllRolesResponse)
	if ok {
		return result
	}
	return nil
}

// CreateRole : Create new role
// Create a new role for the cluster.
func (icpd *IcpdV1) CreateRole(createRoleOptions *CreateRoleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(createRoleOptions, "createRoleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range createRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "CreateRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createRoleOptions.Description != nil {
		body["description"] = createRoleOptions.Description
	}
	if createRoleOptions.Permissions != nil {
		body["permissions"] = createRoleOptions.Permissions
	}
	if createRoleOptions.RoleName != nil {
		body["role_name"] = createRoleOptions.RoleName
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetCreateRoleResult : Retrieve result of CreateRole operation
func (icpd *IcpdV1) GetCreateRoleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAllPermissions : List all permissions
// Get all defined permissions.
func (icpd *IcpdV1) GetAllPermissions(getAllPermissionsOptions *GetAllPermissionsOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getAllPermissionsOptions, "getAllPermissionsOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles/permissions"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAllPermissionsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAllPermissions")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getAllPermissionsOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getAllPermissionsOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetPermissionsResponse))
	return response, err
}

// GetGetAllPermissionsResult : Retrieve result of GetAllPermissions operation
func (icpd *IcpdV1) GetGetAllPermissionsResult(response *core.DetailedResponse) *GetPermissionsResponse {
	result, ok := response.Result.(*GetPermissionsResponse)
	if ok {
		return result
	}
	return nil
}

// GetRole : Get role information
// Get existing role information.
func (icpd *IcpdV1) GetRole(getRoleOptions *GetRoleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getRoleOptions, "getRoleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getRoleOptions, "getRoleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles"}
	pathParameters := []string{*getRoleOptions.RoleName}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getRoleOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getRoleOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetRoleResponse))
	return response, err
}

// GetGetRoleResult : Retrieve result of GetRole operation
func (icpd *IcpdV1) GetGetRoleResult(response *core.DetailedResponse) *GetRoleResponse {
	result, ok := response.Result.(*GetRoleResponse)
	if ok {
		return result
	}
	return nil
}

// UpdateRole : Update role
// Update an existing role.
func (icpd *IcpdV1) UpdateRole(updateRoleOptions *UpdateRoleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(updateRoleOptions, "updateRoleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(updateRoleOptions, "updateRoleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles"}
	pathParameters := []string{*updateRoleOptions.RoleName}

	builder := core.NewRequestBuilder(core.PUT)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range updateRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "UpdateRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateRoleOptions.Description != nil {
		body["description"] = updateRoleOptions.Description
	}
	if updateRoleOptions.Permissions != nil {
		body["permissions"] = updateRoleOptions.Permissions
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetUpdateRoleResult : Retrieve result of UpdateRole operation
func (icpd *IcpdV1) GetUpdateRoleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// DeleteRole : Delete role
// Delete role from the cluster.
func (icpd *IcpdV1) DeleteRole(deleteRoleOptions *DeleteRoleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(deleteRoleOptions, "deleteRoleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(deleteRoleOptions, "deleteRoleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/roles"}
	pathParameters := []string{*deleteRoleOptions.RoleName}

	builder := core.NewRequestBuilder(core.DELETE)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range deleteRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "DeleteRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if deleteRoleOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*deleteRoleOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetDeleteRoleResult : Retrieve result of DeleteRole operation
func (icpd *IcpdV1) GetDeleteRoleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// ChangePassword : Change my password
// Change password for the logged in user.
func (icpd *IcpdV1) ChangePassword(changePasswordOptions *ChangePasswordOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(changePasswordOptions, "changePasswordOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(changePasswordOptions, "changePasswordOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/changepassword"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range changePasswordOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "ChangePassword")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	builder.AddFormData("password", "", "", fmt.Sprint(*changePasswordOptions.Password))

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetChangePasswordResult : Retrieve result of ChangePassword operation
func (icpd *IcpdV1) GetChangePasswordResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetMe : Get my account information
// Get logged in user information.
func (icpd *IcpdV1) GetMe(getMeOptions *GetMeOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getMeOptions, "getMeOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/me"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getMeOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetMe")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getMeOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getMeOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(GetMeResponse))
	return response, err
}

// GetGetMeResult : Retrieve result of GetMe operation
func (icpd *IcpdV1) GetGetMeResult(response *core.DetailedResponse) *GetMeResponse {
	result, ok := response.Result.(*GetMeResponse)
	if ok {
		return result
	}
	return nil
}

// UpdateMe : Update my information
// Update my user information.
func (icpd *IcpdV1) UpdateMe(updateMeOptions *UpdateMeOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(updateMeOptions, "updateMeOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/me"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.PUT)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range updateMeOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "UpdateMe")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateMeOptions.DisplayName != nil {
		body["displayName"] = updateMeOptions.DisplayName
	}
	if updateMeOptions.Email != nil {
		body["email"] = updateMeOptions.Email
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetUpdateMeResult : Retrieve result of UpdateMe operation
func (icpd *IcpdV1) GetUpdateMeResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAllAssetBundles : Get the list of registered asset bundles
// Provides a list of registered asset bundles.
func (icpd *IcpdV1) GetAllAssetBundles(getAllAssetBundlesOptions *GetAllAssetBundlesOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getAllAssetBundlesOptions, "getAllAssetBundlesOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assetBundles"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAllAssetBundlesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAllAssetBundles")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(AssetBundlesGetSuccessResponse))
	return response, err
}

// GetGetAllAssetBundlesResult : Retrieve result of GetAllAssetBundles operation
func (icpd *IcpdV1) GetGetAllAssetBundlesResult(response *core.DetailedResponse) *AssetBundlesGetSuccessResponse {
	result, ok := response.Result.(*AssetBundlesGetSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// UpdateAssetBundle : Update a previously registered asset bundle
// Updates previously registered asset bundle. Upload the zip file with updated bundle definition.
func (icpd *IcpdV1) UpdateAssetBundle(updateAssetBundleOptions *UpdateAssetBundleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(updateAssetBundleOptions, "updateAssetBundleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(updateAssetBundleOptions, "updateAssetBundleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assetBundles"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.PUT)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range updateAssetBundleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "UpdateAssetBundle")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	builder.AddFormData("file", "filename",
		core.StringNilMapper(updateAssetBundleOptions.FileContentType), updateAssetBundleOptions.File)

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetUpdateAssetBundleResult : Retrieve result of UpdateAssetBundle operation
func (icpd *IcpdV1) GetUpdateAssetBundleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// CreateAssetBundle : Register a new Asset bundle
// Registers a new Asset bundle. Upload the zip file with the bundle definition and the properties. More information on
// how to construct the zip file can be found
// [here](https://github.com/IBM-ICP4D/icp4d-apis/tree/master/custom-bundle-utility).
func (icpd *IcpdV1) CreateAssetBundle(createAssetBundleOptions *CreateAssetBundleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(createAssetBundleOptions, "createAssetBundleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(createAssetBundleOptions, "createAssetBundleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assetBundles"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range createAssetBundleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "CreateAssetBundle")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	builder.AddFormData("file", "filename",
		core.StringNilMapper(createAssetBundleOptions.FileContentType), createAssetBundleOptions.File)

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetCreateAssetBundleResult : Retrieve result of CreateAssetBundle operation
func (icpd *IcpdV1) GetCreateAssetBundleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAssetBundle : Download a registered bundle as a zip file
// Outputs the bundle definition zip file, needing the Asset bundle ID to process the request.
func (icpd *IcpdV1) GetAssetBundle(getAssetBundleOptions *GetAssetBundleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getAssetBundleOptions, "getAssetBundleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getAssetBundleOptions, "getAssetBundleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assetBundles"}
	pathParameters := []string{*getAssetBundleOptions.AssetID}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAssetBundleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAssetBundle")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, nil)
	return response, err
}

// DeleteAssetBundle : Delete an asset bundle
// Delete the asset bundle, needing the asset bundle ID as input.
func (icpd *IcpdV1) DeleteAssetBundle(deleteAssetBundleOptions *DeleteAssetBundleOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(deleteAssetBundleOptions, "deleteAssetBundleOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(deleteAssetBundleOptions, "deleteAssetBundleOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assetBundles"}
	pathParameters := []string{*deleteAssetBundleOptions.AssetID}

	builder := core.NewRequestBuilder(core.DELETE)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range deleteAssetBundleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "DeleteAssetBundle")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetDeleteAssetBundleResult : Retrieve result of DeleteAssetBundle operation
func (icpd *IcpdV1) GetDeleteAssetBundleResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAsset : Get an asset
// Provides information about an asset type. For custom asset, please provide the asset type as
// {asset_family_name}-{asset_type}.
func (icpd *IcpdV1) GetAsset(getAssetOptions *GetAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getAssetOptions, "getAssetOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getAssetOptions, "getAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	builder.AddQuery("asset_type", fmt.Sprint(*getAssetOptions.AssetType))
	builder.AddQuery("asset_property", fmt.Sprint(*getAssetOptions.AssetProperty))
	builder.AddQuery("asset_value", fmt.Sprint(*getAssetOptions.AssetValue))

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(AssetDetailsSuccessResponse))
	return response, err
}

// GetGetAssetResult : Retrieve result of GetAsset operation
func (icpd *IcpdV1) GetGetAssetResult(response *core.DetailedResponse) *AssetDetailsSuccessResponse {
	result, ok := response.Result.(*AssetDetailsSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// CreateAsset : Create an asset
// Create custom and pre-defined assets using this endpoint. For term asset types, provide category_name under
// custom_properties. For custom asset types, provide the asset_family_name and the parent asset information, if asset
// not the top element.
func (icpd *IcpdV1) CreateAsset(createAssetOptions *CreateAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(createAssetOptions, "createAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range createAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "CreateAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createAssetOptions.AssetFamily != nil {
		body["asset_family"] = createAssetOptions.AssetFamily
	}
	if createAssetOptions.AssetName != nil {
		body["asset_name"] = createAssetOptions.AssetName
	}
	if createAssetOptions.AssetType != nil {
		body["asset_type"] = createAssetOptions.AssetType
	}
	if createAssetOptions.CustomProperties != nil {
		body["custom_properties"] = createAssetOptions.CustomProperties
	}
	if createAssetOptions.IsCustom != nil {
		body["is_custom"] = createAssetOptions.IsCustom
	}
	if createAssetOptions.ParentAssetName != nil {
		body["parent_asset_name"] = createAssetOptions.ParentAssetName
	}
	if createAssetOptions.ParentAssetType != nil {
		body["parent_asset_type"] = createAssetOptions.ParentAssetType
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetCreateAssetResult : Retrieve result of CreateAsset operation
func (icpd *IcpdV1) GetCreateAssetResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// DeleteAsset : Delete Asset
// Delete asset. For custom asset type, provide asset_type as {asset_family_name}-{asset_type}.
func (icpd *IcpdV1) DeleteAsset(deleteAssetOptions *DeleteAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(deleteAssetOptions, "deleteAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.DELETE)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range deleteAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "DeleteAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if deleteAssetOptions.AssetProperty != nil {
		body["asset_property"] = deleteAssetOptions.AssetProperty
	}
	if deleteAssetOptions.AssetType != nil {
		body["asset_type"] = deleteAssetOptions.AssetType
	}
	if deleteAssetOptions.AssetValue != nil {
		body["asset_value"] = deleteAssetOptions.AssetValue
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetDeleteAssetResult : Retrieve result of DeleteAsset operation
func (icpd *IcpdV1) GetDeleteAssetResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetAssetByID : Get an asset by id
// Retrieve information on an asset based on asset ID.
func (icpd *IcpdV1) GetAssetByID(getAssetByIDOptions *GetAssetByIDOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getAssetByIDOptions, "getAssetByIDOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getAssetByIDOptions, "getAssetByIDOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/assets"}
	pathParameters := []string{*getAssetByIDOptions.AssetID}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getAssetByIDOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetAssetByID")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(AssetDetailsSuccessResponse))
	return response, err
}

// GetGetAssetByIDResult : Retrieve result of GetAssetByID operation
func (icpd *IcpdV1) GetGetAssetByIDResult(response *core.DetailedResponse) *AssetDetailsSuccessResponse {
	result, ok := response.Result.(*AssetDetailsSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetTypes : Get all asset types
// Retrieves all available asset types.
func (icpd *IcpdV1) GetTypes(getTypesOptions *GetTypesOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getTypesOptions, "getTypesOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/types"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getTypesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetTypes")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(TypesSuccessResponse))
	return response, err
}

// GetGetTypesResult : Retrieve result of GetTypes operation
func (icpd *IcpdV1) GetGetTypesResult(response *core.DetailedResponse) *TypesSuccessResponse {
	result, ok := response.Result.(*TypesSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetTypeInfo : Get type metadata
// Get information about an asset type.
func (icpd *IcpdV1) GetTypeInfo(getTypeInfoOptions *GetTypeInfoOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getTypeInfoOptions, "getTypeInfoOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getTypeInfoOptions, "getTypeInfoOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/types"}
	pathParameters := []string{*getTypeInfoOptions.TypeName}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getTypeInfoOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetTypeInfo")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if getTypeInfoOptions.ShowEditProperties != nil {
		builder.AddQuery("show_edit_properties", fmt.Sprint(*getTypeInfoOptions.ShowEditProperties))
	}
	if getTypeInfoOptions.ShowViewProperties != nil {
		builder.AddQuery("show_view_properties", fmt.Sprint(*getTypeInfoOptions.ShowViewProperties))
	}
	if getTypeInfoOptions.ShowCreateProperties != nil {
		builder.AddQuery("show_create_properties", fmt.Sprint(*getTypeInfoOptions.ShowCreateProperties))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(AssetDetailsSuccessResponse))
	return response, err
}

// GetGetTypeInfoResult : Retrieve result of GetTypeInfo operation
func (icpd *IcpdV1) GetGetTypeInfoResult(response *core.DetailedResponse) *AssetDetailsSuccessResponse {
	result, ok := response.Result.(*AssetDetailsSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetTypeAssets : Get assets of a particular type
// Retrieves all available asset of a particular type.
func (icpd *IcpdV1) GetTypeAssets(getTypeAssetsOptions *GetTypeAssetsOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getTypeAssetsOptions, "getTypeAssetsOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getTypeAssetsOptions, "getTypeAssetsOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/types", "assets"}
	pathParameters := []string{*getTypeAssetsOptions.TypeName}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getTypeAssetsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetTypeAssets")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(AssetDetailsSuccessResponse))
	return response, err
}

// GetGetTypeAssetsResult : Retrieve result of GetTypeAssets operation
func (icpd *IcpdV1) GetGetTypeAssetsResult(response *core.DetailedResponse) *AssetDetailsSuccessResponse {
	result, ok := response.Result.(*AssetDetailsSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetRelatedAsset : Find related assets
// Outputs assets related to the provided asset.
func (icpd *IcpdV1) GetRelatedAsset(getRelatedAssetOptions *GetRelatedAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateNotNil(getRelatedAssetOptions, "getRelatedAssetOptions cannot be nil"); err != nil {
		return nil, err
	}
	if err := core.ValidateStruct(getRelatedAssetOptions, "getRelatedAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/relatedAssets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getRelatedAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetRelatedAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	builder.AddQuery("asset_type", fmt.Sprint(*getRelatedAssetOptions.AssetType))
	builder.AddQuery("asset_name", fmt.Sprint(*getRelatedAssetOptions.AssetName))

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(RelatedAssetsFindSuccessResponse))
	return response, err
}

// GetGetRelatedAssetResult : Retrieve result of GetRelatedAsset operation
func (icpd *IcpdV1) GetGetRelatedAssetResult(response *core.DetailedResponse) *RelatedAssetsFindSuccessResponse {
	result, ok := response.Result.(*RelatedAssetsFindSuccessResponse)
	if ok {
		return result
	}
	return nil
}

// CreateRelatedAsset : Relate with other assets
// Associate metadata about two related assets that are existing in the governance catalog. For example, add category
// asset association to a term asset.
func (icpd *IcpdV1) CreateRelatedAsset(createRelatedAssetOptions *CreateRelatedAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(createRelatedAssetOptions, "createRelatedAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/relatedAssets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.POST)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range createRelatedAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "CreateRelatedAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createRelatedAssetOptions.AssetName != nil {
		body["asset_name"] = createRelatedAssetOptions.AssetName
	}
	if createRelatedAssetOptions.AssetType != nil {
		body["asset_type"] = createRelatedAssetOptions.AssetType
	}
	if createRelatedAssetOptions.RelatedAssetName != nil {
		body["related_asset_name"] = createRelatedAssetOptions.RelatedAssetName
	}
	if createRelatedAssetOptions.RelatedAssetType != nil {
		body["related_asset_type"] = createRelatedAssetOptions.RelatedAssetType
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetCreateRelatedAssetResult : Retrieve result of CreateRelatedAsset operation
func (icpd *IcpdV1) GetCreateRelatedAssetResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// DeleteRelatedAsset : Remove related asset
// Remove existing asset's association.
func (icpd *IcpdV1) DeleteRelatedAsset(deleteRelatedAssetOptions *DeleteRelatedAssetOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(deleteRelatedAssetOptions, "deleteRelatedAssetOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/relatedAssets"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.DELETE)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range deleteRelatedAssetOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "DeleteRelatedAsset")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if deleteRelatedAssetOptions.AssetName != nil {
		body["asset_name"] = deleteRelatedAssetOptions.AssetName
	}
	if deleteRelatedAssetOptions.AssetType != nil {
		body["asset_type"] = deleteRelatedAssetOptions.AssetType
	}
	if deleteRelatedAssetOptions.RelatedAssetName != nil {
		body["related_asset_name"] = deleteRelatedAssetOptions.RelatedAssetName
	}
	if deleteRelatedAssetOptions.RelatedAssetType != nil {
		body["related_asset_type"] = deleteRelatedAssetOptions.RelatedAssetType
	}
	if _, err := builder.SetBodyContentJSON(body); err != nil {
		return nil, err
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetDeleteRelatedAssetResult : Retrieve result of DeleteRelatedAsset operation
func (icpd *IcpdV1) GetDeleteRelatedAssetResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// GetMonitor : Check server status
// Provides basic heartbeat endpoint to check if the icp4d open api server is running.
func (icpd *IcpdV1) GetMonitor(getMonitorOptions *GetMonitorOptions) (*core.DetailedResponse, error) {
	if err := core.ValidateStruct(getMonitorOptions, "getMonitorOptions"); err != nil {
		return nil, err
	}

	pathSegments := []string{"v1/monitor"}
	pathParameters := []string{}

	builder := core.NewRequestBuilder(core.GET)
	if _, err := builder.ConstructHTTPURL(icpd.Service.Options.URL, pathSegments, pathParameters); err != nil {
		return nil, err
	}

	for headerName, headerValue := range getMonitorOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("icpd", "V1", "GetMonitor")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "*/*")
	if getMonitorOptions.Accept != nil {
		builder.AddHeader("Accept", fmt.Sprint(*getMonitorOptions.Accept))
	}

	request, err := builder.Build()
	if err != nil {
		return nil, err
	}

	response, err := icpd.Service.Request(request, new(SuccessResponse))
	return response, err
}

// GetGetMonitorResult : Retrieve result of GetMonitor operation
func (icpd *IcpdV1) GetGetMonitorResult(response *core.DetailedResponse) *SuccessResponse {
	result, ok := response.Result.(*SuccessResponse)
	if ok {
		return result
	}
	return nil
}

// ChangePasswordOptions : The ChangePassword options.
type ChangePasswordOptions struct {

	// New Password.
	Password *string `json:"password" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewChangePasswordOptions : Instantiate ChangePasswordOptions
func (icpd *IcpdV1) NewChangePasswordOptions(password string) *ChangePasswordOptions {
	return &ChangePasswordOptions{
		Password: core.StringPtr(password),
	}
}

// SetPassword : Allow user to set Password
func (options *ChangePasswordOptions) SetPassword(password string) *ChangePasswordOptions {
	options.Password = core.StringPtr(password)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ChangePasswordOptions) SetHeaders(param map[string]string) *ChangePasswordOptions {
	options.Headers = param
	return options
}

// CreateAssetBundleOptions : The CreateAssetBundle options.
type CreateAssetBundleOptions struct {

	// File.
	File *os.File `json:"file" validate:"required"`

	// The content type of file.
	FileContentType *string `json:"file_content_type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateAssetBundleOptions : Instantiate CreateAssetBundleOptions
func (icpd *IcpdV1) NewCreateAssetBundleOptions(file *os.File) *CreateAssetBundleOptions {
	return &CreateAssetBundleOptions{
		File: file,
	}
}

// SetFile : Allow user to set File
func (options *CreateAssetBundleOptions) SetFile(file *os.File) *CreateAssetBundleOptions {
	options.File = file
	return options
}

// SetFileContentType : Allow user to set FileContentType
func (options *CreateAssetBundleOptions) SetFileContentType(fileContentType string) *CreateAssetBundleOptions {
	options.FileContentType = core.StringPtr(fileContentType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateAssetBundleOptions) SetHeaders(param map[string]string) *CreateAssetBundleOptions {
	options.Headers = param
	return options
}

// CreateAssetOptions : The CreateAsset options.
type CreateAssetOptions struct {

	// Custom Application Name.
	AssetFamily *string `json:"asset_family,omitempty"`

	// Functional area name.
	AssetName *string `json:"asset_name,omitempty"`

	// Asset type. Non custom asset supported types are term, category, information_governance_policy,
	// information_governance_rule, collection, label and data_class.
	AssetType *string `json:"asset_type,omitempty"`

	// JSON payload of attributes, values.
	CustomProperties map[string]string `json:"custom_properties,omitempty"`

	// Is this a custom asset type? If yes, asset family name is required as well.
	IsCustom *bool `json:"is_custom,omitempty"`

	// If top level asset type this will be NA, if not it will be the parent asset name.
	ParentAssetName *string `json:"parent_asset_name,omitempty"`

	// If top level asset type this will be NA, if not it will be the parent asset type.
	ParentAssetType *string `json:"parent_asset_type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateAssetOptions : Instantiate CreateAssetOptions
func (icpd *IcpdV1) NewCreateAssetOptions() *CreateAssetOptions {
	return &CreateAssetOptions{}
}

// SetAssetFamily : Allow user to set AssetFamily
func (options *CreateAssetOptions) SetAssetFamily(assetFamily string) *CreateAssetOptions {
	options.AssetFamily = core.StringPtr(assetFamily)
	return options
}

// SetAssetName : Allow user to set AssetName
func (options *CreateAssetOptions) SetAssetName(assetName string) *CreateAssetOptions {
	options.AssetName = core.StringPtr(assetName)
	return options
}

// SetAssetType : Allow user to set AssetType
func (options *CreateAssetOptions) SetAssetType(assetType string) *CreateAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetCustomProperties : Allow user to set CustomProperties
func (options *CreateAssetOptions) SetCustomProperties(customProperties map[string]string) *CreateAssetOptions {
	options.CustomProperties = customProperties
	return options
}

// SetIsCustom : Allow user to set IsCustom
func (options *CreateAssetOptions) SetIsCustom(isCustom bool) *CreateAssetOptions {
	options.IsCustom = core.BoolPtr(isCustom)
	return options
}

// SetParentAssetName : Allow user to set ParentAssetName
func (options *CreateAssetOptions) SetParentAssetName(parentAssetName string) *CreateAssetOptions {
	options.ParentAssetName = core.StringPtr(parentAssetName)
	return options
}

// SetParentAssetType : Allow user to set ParentAssetType
func (options *CreateAssetOptions) SetParentAssetType(parentAssetType string) *CreateAssetOptions {
	options.ParentAssetType = core.StringPtr(parentAssetType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateAssetOptions) SetHeaders(param map[string]string) *CreateAssetOptions {
	options.Headers = param
	return options
}

// CreateRelatedAssetOptions : The CreateRelatedAsset options.
type CreateRelatedAssetOptions struct {

	// Functional area instance name. Ex- TermOne.
	AssetName *string `json:"asset_name,omitempty"`

	// Functional area name. Ex- term.
	AssetType *string `json:"asset_type,omitempty"`

	// Functional area instance name. Ex- CategoryOne.
	RelatedAssetName *string `json:"related_asset_name,omitempty"`

	// Functional area name from this Asset Family or could be an asset class name unrelated to this Asset Family. Ex-
	// category.
	RelatedAssetType *string `json:"related_asset_type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateRelatedAssetOptions : Instantiate CreateRelatedAssetOptions
func (icpd *IcpdV1) NewCreateRelatedAssetOptions() *CreateRelatedAssetOptions {
	return &CreateRelatedAssetOptions{}
}

// SetAssetName : Allow user to set AssetName
func (options *CreateRelatedAssetOptions) SetAssetName(assetName string) *CreateRelatedAssetOptions {
	options.AssetName = core.StringPtr(assetName)
	return options
}

// SetAssetType : Allow user to set AssetType
func (options *CreateRelatedAssetOptions) SetAssetType(assetType string) *CreateRelatedAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetRelatedAssetName : Allow user to set RelatedAssetName
func (options *CreateRelatedAssetOptions) SetRelatedAssetName(relatedAssetName string) *CreateRelatedAssetOptions {
	options.RelatedAssetName = core.StringPtr(relatedAssetName)
	return options
}

// SetRelatedAssetType : Allow user to set RelatedAssetType
func (options *CreateRelatedAssetOptions) SetRelatedAssetType(relatedAssetType string) *CreateRelatedAssetOptions {
	options.RelatedAssetType = core.StringPtr(relatedAssetType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateRelatedAssetOptions) SetHeaders(param map[string]string) *CreateRelatedAssetOptions {
	options.Headers = param
	return options
}

// CreateRoleOptions : The CreateRole options.
type CreateRoleOptions struct {

	// Role description e.g. Administrator role.
	Description *string `json:"description,omitempty"`

	// List of permissions e.g. administrator.
	Permissions []string `json:"permissions,omitempty"`

	// Role name e.g. admin.
	RoleName *string `json:"role_name,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateRoleOptions : Instantiate CreateRoleOptions
func (icpd *IcpdV1) NewCreateRoleOptions() *CreateRoleOptions {
	return &CreateRoleOptions{}
}

// SetDescription : Allow user to set Description
func (options *CreateRoleOptions) SetDescription(description string) *CreateRoleOptions {
	options.Description = core.StringPtr(description)
	return options
}

// SetPermissions : Allow user to set Permissions
func (options *CreateRoleOptions) SetPermissions(permissions []string) *CreateRoleOptions {
	options.Permissions = permissions
	return options
}

// SetRoleName : Allow user to set RoleName
func (options *CreateRoleOptions) SetRoleName(roleName string) *CreateRoleOptions {
	options.RoleName = core.StringPtr(roleName)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateRoleOptions) SetHeaders(param map[string]string) *CreateRoleOptions {
	options.Headers = param
	return options
}

// CreateUserOptions : The CreateUser options.
type CreateUserOptions struct {

	// Display Name for the user e.g. Admin.
	DisplayName *string `json:"displayName,omitempty"`

	// Email for the user e.g. admin@user.net.
	Email *string `json:"email,omitempty"`

	// User name e.g. admin.
	UserName *string `json:"user_name,omitempty"`

	// List of user roles.
	UserRoles []string `json:"user_roles,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateUserOptions : Instantiate CreateUserOptions
func (icpd *IcpdV1) NewCreateUserOptions() *CreateUserOptions {
	return &CreateUserOptions{}
}

// SetDisplayName : Allow user to set DisplayName
func (options *CreateUserOptions) SetDisplayName(displayName string) *CreateUserOptions {
	options.DisplayName = core.StringPtr(displayName)
	return options
}

// SetEmail : Allow user to set Email
func (options *CreateUserOptions) SetEmail(email string) *CreateUserOptions {
	options.Email = core.StringPtr(email)
	return options
}

// SetUserName : Allow user to set UserName
func (options *CreateUserOptions) SetUserName(userName string) *CreateUserOptions {
	options.UserName = core.StringPtr(userName)
	return options
}

// SetUserRoles : Allow user to set UserRoles
func (options *CreateUserOptions) SetUserRoles(userRoles []string) *CreateUserOptions {
	options.UserRoles = userRoles
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateUserOptions) SetHeaders(param map[string]string) *CreateUserOptions {
	options.Headers = param
	return options
}

// DeleteAssetBundleOptions : The DeleteAssetBundle options.
type DeleteAssetBundleOptions struct {

	// Asset Bundle ID.
	AssetID *string `json:"assetID" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteAssetBundleOptions : Instantiate DeleteAssetBundleOptions
func (icpd *IcpdV1) NewDeleteAssetBundleOptions(assetID string) *DeleteAssetBundleOptions {
	return &DeleteAssetBundleOptions{
		AssetID: core.StringPtr(assetID),
	}
}

// SetAssetID : Allow user to set AssetID
func (options *DeleteAssetBundleOptions) SetAssetID(assetID string) *DeleteAssetBundleOptions {
	options.AssetID = core.StringPtr(assetID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteAssetBundleOptions) SetHeaders(param map[string]string) *DeleteAssetBundleOptions {
	options.Headers = param
	return options
}

// DeleteAssetOptions : The DeleteAsset options.
type DeleteAssetOptions struct {

	// Property name to search by, can search for all assets with a given name to delete. Ex- name.
	AssetProperty *string `json:"asset_property,omitempty"`

	// Functional area name. Ex- term.
	AssetType *string `json:"asset_type,omitempty"`

	// Property value to search by. Ex- TermOne.
	AssetValue *string `json:"asset_value,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteAssetOptions : Instantiate DeleteAssetOptions
func (icpd *IcpdV1) NewDeleteAssetOptions() *DeleteAssetOptions {
	return &DeleteAssetOptions{}
}

// SetAssetProperty : Allow user to set AssetProperty
func (options *DeleteAssetOptions) SetAssetProperty(assetProperty string) *DeleteAssetOptions {
	options.AssetProperty = core.StringPtr(assetProperty)
	return options
}

// SetAssetType : Allow user to set AssetType
func (options *DeleteAssetOptions) SetAssetType(assetType string) *DeleteAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetAssetValue : Allow user to set AssetValue
func (options *DeleteAssetOptions) SetAssetValue(assetValue string) *DeleteAssetOptions {
	options.AssetValue = core.StringPtr(assetValue)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteAssetOptions) SetHeaders(param map[string]string) *DeleteAssetOptions {
	options.Headers = param
	return options
}

// DeleteRelatedAssetOptions : The DeleteRelatedAsset options.
type DeleteRelatedAssetOptions struct {

	// Functional area instance name. Ex- TermOne.
	AssetName *string `json:"asset_name,omitempty"`

	// Functional area name. Ex- term.
	AssetType *string `json:"asset_type,omitempty"`

	// Functional area instance name. Ex- CategoryOne.
	RelatedAssetName *string `json:"related_asset_name,omitempty"`

	// Functional area name from this Asset Family or could be an asset class name unrelated to this Asset Family. Ex-
	// category.
	RelatedAssetType *string `json:"related_asset_type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteRelatedAssetOptions : Instantiate DeleteRelatedAssetOptions
func (icpd *IcpdV1) NewDeleteRelatedAssetOptions() *DeleteRelatedAssetOptions {
	return &DeleteRelatedAssetOptions{}
}

// SetAssetName : Allow user to set AssetName
func (options *DeleteRelatedAssetOptions) SetAssetName(assetName string) *DeleteRelatedAssetOptions {
	options.AssetName = core.StringPtr(assetName)
	return options
}

// SetAssetType : Allow user to set AssetType
func (options *DeleteRelatedAssetOptions) SetAssetType(assetType string) *DeleteRelatedAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetRelatedAssetName : Allow user to set RelatedAssetName
func (options *DeleteRelatedAssetOptions) SetRelatedAssetName(relatedAssetName string) *DeleteRelatedAssetOptions {
	options.RelatedAssetName = core.StringPtr(relatedAssetName)
	return options
}

// SetRelatedAssetType : Allow user to set RelatedAssetType
func (options *DeleteRelatedAssetOptions) SetRelatedAssetType(relatedAssetType string) *DeleteRelatedAssetOptions {
	options.RelatedAssetType = core.StringPtr(relatedAssetType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteRelatedAssetOptions) SetHeaders(param map[string]string) *DeleteRelatedAssetOptions {
	options.Headers = param
	return options
}

// DeleteRoleOptions : The DeleteRole options.
type DeleteRoleOptions struct {

	// existing role.
	RoleName *string `json:"role_name" validate:"required"`

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteRoleOptions : Instantiate DeleteRoleOptions
func (icpd *IcpdV1) NewDeleteRoleOptions(roleName string) *DeleteRoleOptions {
	return &DeleteRoleOptions{
		RoleName: core.StringPtr(roleName),
	}
}

// SetRoleName : Allow user to set RoleName
func (options *DeleteRoleOptions) SetRoleName(roleName string) *DeleteRoleOptions {
	options.RoleName = core.StringPtr(roleName)
	return options
}

// SetAccept : Allow user to set Accept
func (options *DeleteRoleOptions) SetAccept(accept string) *DeleteRoleOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteRoleOptions) SetHeaders(param map[string]string) *DeleteRoleOptions {
	options.Headers = param
	return options
}

// DeleteUserOptions : The DeleteUser options.
type DeleteUserOptions struct {

	// User name.
	UserName *string `json:"user_name" validate:"required"`

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteUserOptions : Instantiate DeleteUserOptions
func (icpd *IcpdV1) NewDeleteUserOptions(userName string) *DeleteUserOptions {
	return &DeleteUserOptions{
		UserName: core.StringPtr(userName),
	}
}

// SetUserName : Allow user to set UserName
func (options *DeleteUserOptions) SetUserName(userName string) *DeleteUserOptions {
	options.UserName = core.StringPtr(userName)
	return options
}

// SetAccept : Allow user to set Accept
func (options *DeleteUserOptions) SetAccept(accept string) *DeleteUserOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteUserOptions) SetHeaders(param map[string]string) *DeleteUserOptions {
	options.Headers = param
	return options
}

// GetAllAssetBundlesOptions : The GetAllAssetBundles options.
type GetAllAssetBundlesOptions struct {

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAllAssetBundlesOptions : Instantiate GetAllAssetBundlesOptions
func (icpd *IcpdV1) NewGetAllAssetBundlesOptions() *GetAllAssetBundlesOptions {
	return &GetAllAssetBundlesOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *GetAllAssetBundlesOptions) SetHeaders(param map[string]string) *GetAllAssetBundlesOptions {
	options.Headers = param
	return options
}

// GetAllPermissionsOptions : The GetAllPermissions options.
type GetAllPermissionsOptions struct {

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAllPermissionsOptions : Instantiate GetAllPermissionsOptions
func (icpd *IcpdV1) NewGetAllPermissionsOptions() *GetAllPermissionsOptions {
	return &GetAllPermissionsOptions{}
}

// SetAccept : Allow user to set Accept
func (options *GetAllPermissionsOptions) SetAccept(accept string) *GetAllPermissionsOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAllPermissionsOptions) SetHeaders(param map[string]string) *GetAllPermissionsOptions {
	options.Headers = param
	return options
}

// GetAllRolesOptions : The GetAllRoles options.
type GetAllRolesOptions struct {

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAllRolesOptions : Instantiate GetAllRolesOptions
func (icpd *IcpdV1) NewGetAllRolesOptions() *GetAllRolesOptions {
	return &GetAllRolesOptions{}
}

// SetAccept : Allow user to set Accept
func (options *GetAllRolesOptions) SetAccept(accept string) *GetAllRolesOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAllRolesOptions) SetHeaders(param map[string]string) *GetAllRolesOptions {
	options.Headers = param
	return options
}

// GetAllUsersOptions : The GetAllUsers options.
type GetAllUsersOptions struct {

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAllUsersOptions : Instantiate GetAllUsersOptions
func (icpd *IcpdV1) NewGetAllUsersOptions() *GetAllUsersOptions {
	return &GetAllUsersOptions{}
}

// SetAccept : Allow user to set Accept
func (options *GetAllUsersOptions) SetAccept(accept string) *GetAllUsersOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAllUsersOptions) SetHeaders(param map[string]string) *GetAllUsersOptions {
	options.Headers = param
	return options
}

// GetAssetBundleOptions : The GetAssetBundle options.
type GetAssetBundleOptions struct {

	// Asset Bundle ID.
	AssetID *string `json:"assetID" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAssetBundleOptions : Instantiate GetAssetBundleOptions
func (icpd *IcpdV1) NewGetAssetBundleOptions(assetID string) *GetAssetBundleOptions {
	return &GetAssetBundleOptions{
		AssetID: core.StringPtr(assetID),
	}
}

// SetAssetID : Allow user to set AssetID
func (options *GetAssetBundleOptions) SetAssetID(assetID string) *GetAssetBundleOptions {
	options.AssetID = core.StringPtr(assetID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAssetBundleOptions) SetHeaders(param map[string]string) *GetAssetBundleOptions {
	options.Headers = param
	return options
}

// GetAssetByIDOptions : The GetAssetByID options.
type GetAssetByIDOptions struct {

	// Asset ID.
	AssetID *string `json:"asset_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAssetByIDOptions : Instantiate GetAssetByIDOptions
func (icpd *IcpdV1) NewGetAssetByIDOptions(assetID string) *GetAssetByIDOptions {
	return &GetAssetByIDOptions{
		AssetID: core.StringPtr(assetID),
	}
}

// SetAssetID : Allow user to set AssetID
func (options *GetAssetByIDOptions) SetAssetID(assetID string) *GetAssetByIDOptions {
	options.AssetID = core.StringPtr(assetID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAssetByIDOptions) SetHeaders(param map[string]string) *GetAssetByIDOptions {
	options.Headers = param
	return options
}

// GetAssetOptions : The GetAsset options.
type GetAssetOptions struct {

	// Functional area name Ex- category.
	AssetType *string `json:"asset_type" validate:"required"`

	// Property name to search by, as an example we might want to search for all assets with a given name. Ex- name.
	AssetProperty *string `json:"asset_property" validate:"required"`

	// What property value are we searching by? Ex- Logical Area.
	AssetValue *string `json:"asset_value" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAssetOptions : Instantiate GetAssetOptions
func (icpd *IcpdV1) NewGetAssetOptions(assetType string, assetProperty string, assetValue string) *GetAssetOptions {
	return &GetAssetOptions{
		AssetType:     core.StringPtr(assetType),
		AssetProperty: core.StringPtr(assetProperty),
		AssetValue:    core.StringPtr(assetValue),
	}
}

// SetAssetType : Allow user to set AssetType
func (options *GetAssetOptions) SetAssetType(assetType string) *GetAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetAssetProperty : Allow user to set AssetProperty
func (options *GetAssetOptions) SetAssetProperty(assetProperty string) *GetAssetOptions {
	options.AssetProperty = core.StringPtr(assetProperty)
	return options
}

// SetAssetValue : Allow user to set AssetValue
func (options *GetAssetOptions) SetAssetValue(assetValue string) *GetAssetOptions {
	options.AssetValue = core.StringPtr(assetValue)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAssetOptions) SetHeaders(param map[string]string) *GetAssetOptions {
	options.Headers = param
	return options
}

// GetAuthorizationTokenOptions : The GetAuthorizationToken options.
type GetAuthorizationTokenOptions struct {
	Password *string `json:"password" validate:"required"`

	Username *string `json:"username" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetAuthorizationTokenOptions : Instantiate GetAuthorizationTokenOptions
func (icpd *IcpdV1) NewGetAuthorizationTokenOptions(password string, username string) *GetAuthorizationTokenOptions {
	return &GetAuthorizationTokenOptions{
		Password: core.StringPtr(password),
		Username: core.StringPtr(username),
	}
}

// SetPassword : Allow user to set Password
func (options *GetAuthorizationTokenOptions) SetPassword(password string) *GetAuthorizationTokenOptions {
	options.Password = core.StringPtr(password)
	return options
}

// SetUsername : Allow user to set Username
func (options *GetAuthorizationTokenOptions) SetUsername(username string) *GetAuthorizationTokenOptions {
	options.Username = core.StringPtr(username)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetAuthorizationTokenOptions) SetHeaders(param map[string]string) *GetAuthorizationTokenOptions {
	options.Headers = param
	return options
}

// GetMeOptions : The GetMe options.
type GetMeOptions struct {

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetMeOptions : Instantiate GetMeOptions
func (icpd *IcpdV1) NewGetMeOptions() *GetMeOptions {
	return &GetMeOptions{}
}

// SetAccept : Allow user to set Accept
func (options *GetMeOptions) SetAccept(accept string) *GetMeOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetMeOptions) SetHeaders(param map[string]string) *GetMeOptions {
	options.Headers = param
	return options
}

// GetMonitorOptions : The GetMonitor options.
type GetMonitorOptions struct {

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetMonitorOptions : Instantiate GetMonitorOptions
func (icpd *IcpdV1) NewGetMonitorOptions() *GetMonitorOptions {
	return &GetMonitorOptions{}
}

// SetAccept : Allow user to set Accept
func (options *GetMonitorOptions) SetAccept(accept string) *GetMonitorOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetMonitorOptions) SetHeaders(param map[string]string) *GetMonitorOptions {
	options.Headers = param
	return options
}

// GetRelatedAssetOptions : The GetRelatedAsset options.
type GetRelatedAssetOptions struct {

	// Functional area name Ex- category.
	AssetType *string `json:"asset_type" validate:"required"`

	// Asset name.
	AssetName *string `json:"asset_name" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetRelatedAssetOptions : Instantiate GetRelatedAssetOptions
func (icpd *IcpdV1) NewGetRelatedAssetOptions(assetType string, assetName string) *GetRelatedAssetOptions {
	return &GetRelatedAssetOptions{
		AssetType: core.StringPtr(assetType),
		AssetName: core.StringPtr(assetName),
	}
}

// SetAssetType : Allow user to set AssetType
func (options *GetRelatedAssetOptions) SetAssetType(assetType string) *GetRelatedAssetOptions {
	options.AssetType = core.StringPtr(assetType)
	return options
}

// SetAssetName : Allow user to set AssetName
func (options *GetRelatedAssetOptions) SetAssetName(assetName string) *GetRelatedAssetOptions {
	options.AssetName = core.StringPtr(assetName)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetRelatedAssetOptions) SetHeaders(param map[string]string) *GetRelatedAssetOptions {
	options.Headers = param
	return options
}

// GetRoleOptions : The GetRole options.
type GetRoleOptions struct {

	// existing role.
	RoleName *string `json:"role_name" validate:"required"`

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetRoleOptions : Instantiate GetRoleOptions
func (icpd *IcpdV1) NewGetRoleOptions(roleName string) *GetRoleOptions {
	return &GetRoleOptions{
		RoleName: core.StringPtr(roleName),
	}
}

// SetRoleName : Allow user to set RoleName
func (options *GetRoleOptions) SetRoleName(roleName string) *GetRoleOptions {
	options.RoleName = core.StringPtr(roleName)
	return options
}

// SetAccept : Allow user to set Accept
func (options *GetRoleOptions) SetAccept(accept string) *GetRoleOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetRoleOptions) SetHeaders(param map[string]string) *GetRoleOptions {
	options.Headers = param
	return options
}

// GetTypeAssetsOptions : The GetTypeAssets options.
type GetTypeAssetsOptions struct {

	// Asset type.
	TypeName *string `json:"type_name" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetTypeAssetsOptions : Instantiate GetTypeAssetsOptions
func (icpd *IcpdV1) NewGetTypeAssetsOptions(typeName string) *GetTypeAssetsOptions {
	return &GetTypeAssetsOptions{
		TypeName: core.StringPtr(typeName),
	}
}

// SetTypeName : Allow user to set TypeName
func (options *GetTypeAssetsOptions) SetTypeName(typeName string) *GetTypeAssetsOptions {
	options.TypeName = core.StringPtr(typeName)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetTypeAssetsOptions) SetHeaders(param map[string]string) *GetTypeAssetsOptions {
	options.Headers = param
	return options
}

// GetTypeInfoOptions : The GetTypeInfo options.
type GetTypeInfoOptions struct {

	// Asset type.
	TypeName *string `json:"type_name" validate:"required"`

	// List the properties that can be edited.
	ShowEditProperties *bool `json:"show_edit_properties,omitempty"`

	// List the properties that can be viewed.
	ShowViewProperties *bool `json:"show_view_properties,omitempty"`

	// List the properties that can be defined when the asset is created.
	ShowCreateProperties *bool `json:"show_create_properties,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetTypeInfoOptions : Instantiate GetTypeInfoOptions
func (icpd *IcpdV1) NewGetTypeInfoOptions(typeName string) *GetTypeInfoOptions {
	return &GetTypeInfoOptions{
		TypeName: core.StringPtr(typeName),
	}
}

// SetTypeName : Allow user to set TypeName
func (options *GetTypeInfoOptions) SetTypeName(typeName string) *GetTypeInfoOptions {
	options.TypeName = core.StringPtr(typeName)
	return options
}

// SetShowEditProperties : Allow user to set ShowEditProperties
func (options *GetTypeInfoOptions) SetShowEditProperties(showEditProperties bool) *GetTypeInfoOptions {
	options.ShowEditProperties = core.BoolPtr(showEditProperties)
	return options
}

// SetShowViewProperties : Allow user to set ShowViewProperties
func (options *GetTypeInfoOptions) SetShowViewProperties(showViewProperties bool) *GetTypeInfoOptions {
	options.ShowViewProperties = core.BoolPtr(showViewProperties)
	return options
}

// SetShowCreateProperties : Allow user to set ShowCreateProperties
func (options *GetTypeInfoOptions) SetShowCreateProperties(showCreateProperties bool) *GetTypeInfoOptions {
	options.ShowCreateProperties = core.BoolPtr(showCreateProperties)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetTypeInfoOptions) SetHeaders(param map[string]string) *GetTypeInfoOptions {
	options.Headers = param
	return options
}

// GetTypesOptions : The GetTypes options.
type GetTypesOptions struct {

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetTypesOptions : Instantiate GetTypesOptions
func (icpd *IcpdV1) NewGetTypesOptions() *GetTypesOptions {
	return &GetTypesOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *GetTypesOptions) SetHeaders(param map[string]string) *GetTypesOptions {
	options.Headers = param
	return options
}

// GetUserOptions : The GetUser options.
type GetUserOptions struct {

	// User name.
	UserName *string `json:"user_name" validate:"required"`

	// The type of the response:  or *_/_*.
	Accept *string `json:"Accept,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetUserOptions : Instantiate GetUserOptions
func (icpd *IcpdV1) NewGetUserOptions(userName string) *GetUserOptions {
	return &GetUserOptions{
		UserName: core.StringPtr(userName),
	}
}

// SetUserName : Allow user to set UserName
func (options *GetUserOptions) SetUserName(userName string) *GetUserOptions {
	options.UserName = core.StringPtr(userName)
	return options
}

// SetAccept : Allow user to set Accept
func (options *GetUserOptions) SetAccept(accept string) *GetUserOptions {
	options.Accept = core.StringPtr(accept)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetUserOptions) SetHeaders(param map[string]string) *GetUserOptions {
	options.Headers = param
	return options
}

// UpdateAssetBundleOptions : The UpdateAssetBundle options.
type UpdateAssetBundleOptions struct {

	// File.
	File *os.File `json:"file" validate:"required"`

	// The content type of file.
	FileContentType *string `json:"file_content_type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateAssetBundleOptions : Instantiate UpdateAssetBundleOptions
func (icpd *IcpdV1) NewUpdateAssetBundleOptions(file *os.File) *UpdateAssetBundleOptions {
	return &UpdateAssetBundleOptions{
		File: file,
	}
}

// SetFile : Allow user to set File
func (options *UpdateAssetBundleOptions) SetFile(file *os.File) *UpdateAssetBundleOptions {
	options.File = file
	return options
}

// SetFileContentType : Allow user to set FileContentType
func (options *UpdateAssetBundleOptions) SetFileContentType(fileContentType string) *UpdateAssetBundleOptions {
	options.FileContentType = core.StringPtr(fileContentType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateAssetBundleOptions) SetHeaders(param map[string]string) *UpdateAssetBundleOptions {
	options.Headers = param
	return options
}

// UpdateMeOptions : The UpdateMe options.
type UpdateMeOptions struct {

	// Display Name for the user e.g. Admin.
	DisplayName *string `json:"displayName,omitempty"`

	// Email for the user e.g. admin@user.net.
	Email *string `json:"email,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateMeOptions : Instantiate UpdateMeOptions
func (icpd *IcpdV1) NewUpdateMeOptions() *UpdateMeOptions {
	return &UpdateMeOptions{}
}

// SetDisplayName : Allow user to set DisplayName
func (options *UpdateMeOptions) SetDisplayName(displayName string) *UpdateMeOptions {
	options.DisplayName = core.StringPtr(displayName)
	return options
}

// SetEmail : Allow user to set Email
func (options *UpdateMeOptions) SetEmail(email string) *UpdateMeOptions {
	options.Email = core.StringPtr(email)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateMeOptions) SetHeaders(param map[string]string) *UpdateMeOptions {
	options.Headers = param
	return options
}

// UpdateRoleOptions : The UpdateRole options.
type UpdateRoleOptions struct {

	// existing role.
	RoleName *string `json:"role_name" validate:"required"`

	// Role description e.g. Admin.
	Description *string `json:"description,omitempty"`

	// List of permissions e.g. administrator.
	Permissions []string `json:"permissions,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateRoleOptions : Instantiate UpdateRoleOptions
func (icpd *IcpdV1) NewUpdateRoleOptions(roleName string) *UpdateRoleOptions {
	return &UpdateRoleOptions{
		RoleName: core.StringPtr(roleName),
	}
}

// SetRoleName : Allow user to set RoleName
func (options *UpdateRoleOptions) SetRoleName(roleName string) *UpdateRoleOptions {
	options.RoleName = core.StringPtr(roleName)
	return options
}

// SetDescription : Allow user to set Description
func (options *UpdateRoleOptions) SetDescription(description string) *UpdateRoleOptions {
	options.Description = core.StringPtr(description)
	return options
}

// SetPermissions : Allow user to set Permissions
func (options *UpdateRoleOptions) SetPermissions(permissions []string) *UpdateRoleOptions {
	options.Permissions = permissions
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateRoleOptions) SetHeaders(param map[string]string) *UpdateRoleOptions {
	options.Headers = param
	return options
}

// UpdateUserOptions : The UpdateUser options.
type UpdateUserOptions struct {

	// User name.
	UserName *string `json:"user_name" validate:"required"`

	// Approval status for the user, can be either 'pending' or 'approved'.
	ApprovalStatus *string `json:"approval_status,omitempty"`

	// Display Name for the user e.g. Admin.
	DisplayName *string `json:"displayName,omitempty"`

	// Email for the user e.g. admin@user.net.
	Email *string `json:"email,omitempty"`

	// List of user roles.
	UserRoles []string `json:"user_roles,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateUserOptions : Instantiate UpdateUserOptions
func (icpd *IcpdV1) NewUpdateUserOptions(userName string) *UpdateUserOptions {
	return &UpdateUserOptions{
		UserName: core.StringPtr(userName),
	}
}

// SetUserName : Allow user to set UserName
func (options *UpdateUserOptions) SetUserName(userName string) *UpdateUserOptions {
	options.UserName = core.StringPtr(userName)
	return options
}

// SetApprovalStatus : Allow user to set ApprovalStatus
func (options *UpdateUserOptions) SetApprovalStatus(approvalStatus string) *UpdateUserOptions {
	options.ApprovalStatus = core.StringPtr(approvalStatus)
	return options
}

// SetDisplayName : Allow user to set DisplayName
func (options *UpdateUserOptions) SetDisplayName(displayName string) *UpdateUserOptions {
	options.DisplayName = core.StringPtr(displayName)
	return options
}

// SetEmail : Allow user to set Email
func (options *UpdateUserOptions) SetEmail(email string) *UpdateUserOptions {
	options.Email = core.StringPtr(email)
	return options
}

// SetUserRoles : Allow user to set UserRoles
func (options *UpdateUserOptions) SetUserRoles(userRoles []string) *UpdateUserOptions {
	options.UserRoles = userRoles
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateUserOptions) SetHeaders(param map[string]string) *UpdateUserOptions {
	options.Headers = param
	return options
}

// AssetBundlesGetSuccessResponse : AssetBundlesGetSuccessResponse struct
type AssetBundlesGetSuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	AssetBundles []string `json:"AssetBundles,omitempty"`
}

// AssetDetailsSuccessResponse : AssetDetailsSuccessResponse struct
type AssetDetailsSuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	AssetDetails interface{} `json:"asset_details,omitempty"`
}

// CreateUserSuccessResponse : CreateUserSuccessResponse struct
type CreateUserSuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	User *CreateUserSuccessResponseAllOf1User `json:"User,omitempty"`
}

// CreateUserSuccessResponseAllOf1User : CreateUserSuccessResponseAllOf1User struct
type CreateUserSuccessResponseAllOf1User struct {

	// user name.
	ID *string `json:"ID,omitempty"`

	// Auto generated password for the new user.
	Password *string `json:"password,omitempty"`
}

// GetAllRolesResponse : GetAllRolesResponse struct
type GetAllRolesResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	Roles []GetAllRolesResponseAllOf1RolesItems `json:"Roles,omitempty"`
}

// GetAllRolesResponseAllOf1RolesItems : GetAllRolesResponseAllOf1RolesItems struct
type GetAllRolesResponseAllOf1RolesItems struct {

	// Role ID.
	ID *string `json:"ID,omitempty"`

	// Role description.
	Description *string `json:"description,omitempty"`

	// List of role permissions.
	Permissions []string `json:"permissions,omitempty"`

	// Role name.
	RoleName *string `json:"role_name,omitempty"`
}

// GetAllUsersResponse : GetAllUsersResponse struct
type GetAllUsersResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	UsersInfo []GetAllUsersResponseAllOf1UsersInfoItems `json:"UsersInfo,omitempty"`
}

// GetAllUsersResponseAllOf1UsersInfoItems : GetAllUsersResponseAllOf1UsersInfoItems struct
type GetAllUsersResponseAllOf1UsersInfoItems struct {

	// Approval status of user.
	ApprovalStatus *string `json:"approval_status,omitempty"`

	// User authenticator.
	Authenticator *string `json:"authenticator,omitempty"`

	// Timestamp of creation.
	CreatedTimestamp *string `json:"created_timestamp,omitempty"`

	// User current account status.
	CurrentAccountStatus *string `json:"current_account_status,omitempty"`

	// User display name.
	DisplayName *string `json:"displayName,omitempty"`

	// User email.
	Email *string `json:"email,omitempty"`

	// Timestamp of last modification.
	LastModifiedTimestamp *string `json:"last_modified_timestamp,omitempty"`

	// List of user permissions.
	Permissions []string `json:"permissions,omitempty"`

	// User role.
	Role *string `json:"role,omitempty"`

	// User ID.
	Uid *string `json:"uid,omitempty"`

	// List of user roles.
	UserRoles []string `json:"user_roles,omitempty"`

	// User Name.
	Username *string `json:"username,omitempty"`
}

// GetMeResponse : GetMeResponse struct
type GetMeResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	UserInfo *GetMeResponseAllOf1UserInfo `json:"UserInfo,omitempty"`
}

// GetMeResponseAllOf1UserInfo : GetMeResponseAllOf1UserInfo struct
type GetMeResponseAllOf1UserInfo struct {

	// User display name.
	DisplayName *string `json:"displayName,omitempty"`

	// User email.
	Email *string `json:"email,omitempty"`

	// List of user permissions.
	Permissions []string `json:"permissions,omitempty"`

	// User role.
	Role *string `json:"role,omitempty"`

	// User ID.
	Uid *string `json:"uid,omitempty"`

	// User Name.
	Username *string `json:"username,omitempty"`
}

// GetPermissionsResponse : GetPermissionsResponse struct
type GetPermissionsResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	Permissions []string `json:"Permissions,omitempty"`
}

// GetRoleResponse : GetRoleResponse struct
type GetRoleResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	RoleInfo *GetRoleResponseAllOf1RoleInfo `json:"RoleInfo,omitempty"`
}

// GetRoleResponseAllOf1RoleInfo : GetRoleResponseAllOf1RoleInfo struct
type GetRoleResponseAllOf1RoleInfo struct {

	// Role ID.
	ID *string `json:"ID,omitempty"`

	// Role description.
	Description *string `json:"description,omitempty"`

	// List of role permissions.
	Permissions []string `json:"permissions,omitempty"`

	// Role name.
	RoleName *string `json:"role_name,omitempty"`
}

// GetUserResponse : GetUserResponse struct
type GetUserResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	UserInfo *GetUserResponseAllOf1UserInfo `json:"UserInfo,omitempty"`
}

// GetUserResponseAllOf1UserInfo : GetUserResponseAllOf1UserInfo struct
type GetUserResponseAllOf1UserInfo struct {

	// Approval status of user.
	ApprovalStatus *string `json:"approval_status,omitempty"`

	// User authenticator.
	Authenticator *string `json:"authenticator,omitempty"`

	// Timestamp of creation.
	CreatedTimestamp *string `json:"created_timestamp,omitempty"`

	// User current account status.
	CurrentAccountStatus *string `json:"current_account_status,omitempty"`

	// User display name.
	DisplayName *string `json:"displayName,omitempty"`

	// User email.
	Email *string `json:"email,omitempty"`

	// Timestamp of first failed attempt.
	FirstFailedAttemptTimestamp *string `json:"first_failed_attempt_timestamp,omitempty"`

	// Timestamp of last modification.
	LastModifiedTimestamp *string `json:"last_modified_timestamp,omitempty"`

	// List of user permissions.
	Permissions []string `json:"permissions,omitempty"`

	// Recent number of failed attempts.
	RecentNumberOfFailedAttempts *float64 `json:"recent_number_of_failed_attempts,omitempty"`

	// Release lock at timestamp.
	ReleaseLockAtTimestamp *string `json:"release_lock_at_timestamp,omitempty"`

	// User role.
	Role *string `json:"role,omitempty"`

	// User ID.
	Uid *string `json:"uid,omitempty"`

	// List of user roles.
	UserRoles []string `json:"user_roles,omitempty"`

	// User Name.
	Username *string `json:"username,omitempty"`
}

// LoginResponse : LoginResponse struct
type LoginResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	// Authorization bearer token used for accessing api.
	Token *string `json:"token,omitempty"`
}

// RelatedAssetsFindSuccessResponse : RelatedAssetsFindSuccessResponse struct
type RelatedAssetsFindSuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	RelatedAssets []RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems `json:"relatedAssets,omitempty"`
}

// RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems : RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems struct
type RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems struct {

	// asset_name.
	Name *string `json:"_name,omitempty"`

	// asset_type.
	Type *string `json:"_type,omitempty"`
}

// SuccessResponse : SuccessResponse struct
type SuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`
}

// TypesSuccessResponse : TypesSuccessResponse struct
type TypesSuccessResponse struct {

	// message code.
	MessageCode *string `json:"_messageCode_,omitempty"`

	// message.
	Message *string `json:"message,omitempty"`

	Types []interface{} `json:"Types,omitempty"`
}
