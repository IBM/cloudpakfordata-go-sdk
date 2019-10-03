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

package icpdv1_test

import (
	"fmt"
	"go-sdk-template/icpdv1"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/IBM/go-sdk-core/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`IcpdV1`, func() {
	Describe(`GetAuthorizationToken(getAuthorizationTokenOptions *GetAuthorizationTokenOptions)`, func() {
		getAuthorizationTokenPath := "/v1/authorize"
		password := "exampleString"
		username := "exampleString"
		Context(`Successfully - Get authorization token`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAuthorizationTokenPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAuthorizationToken`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAuthorizationToken(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAuthorizationTokenOptions := testService.NewGetAuthorizationTokenOptions(password, username)
				returnValue, returnValueErr = testService.GetAuthorizationToken(getAuthorizationTokenOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAuthorizationTokenResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAllUsers(getAllUsersOptions *GetAllUsersOptions)`, func() {
		getAllUsersPath := "/v1/users"
		Context(`Successfully - Get all users`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAllUsersPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAllUsers`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAllUsers(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAllUsersOptions := testService.NewGetAllUsersOptions()
				returnValue, returnValueErr = testService.GetAllUsers(getAllUsersOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAllUsersResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateUser(createUserOptions *CreateUserOptions)`, func() {
		createUserPath := "/v1/users"
		Context(`Successfully - Create user`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createUserPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call CreateUser`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.CreateUser(nil)
				Expect(returnValueErr).NotTo(BeNil())

				createUserOptions := testService.NewCreateUserOptions()
				returnValue, returnValueErr = testService.CreateUser(createUserOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetCreateUserResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetUser(getUserOptions *GetUserOptions)`, func() {
		getUserPath := "/v1/users/{user_name}"
		userName := "exampleString"
		getUserPath = strings.Replace(getUserPath, "{user_name}", userName, 1)
		Context(`Successfully - Get user information`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getUserPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetUser`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetUser(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getUserOptions := testService.NewGetUserOptions(userName)
				returnValue, returnValueErr = testService.GetUser(getUserOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetUserResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateUser(updateUserOptions *UpdateUserOptions)`, func() {
		updateUserPath := "/v1/users/{user_name}"
		userName := "exampleString"
		updateUserPath = strings.Replace(updateUserPath, "{user_name}", userName, 1)
		Context(`Successfully - Update user details`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateUserPath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call UpdateUser`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.UpdateUser(nil)
				Expect(returnValueErr).NotTo(BeNil())

				updateUserOptions := testService.NewUpdateUserOptions(userName)
				returnValue, returnValueErr = testService.UpdateUser(updateUserOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetUpdateUserResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteUser(deleteUserOptions *DeleteUserOptions)`, func() {
		deleteUserPath := "/v1/users/{user_name}"
		userName := "exampleString"
		deleteUserPath = strings.Replace(deleteUserPath, "{user_name}", userName, 1)
		Context(`Successfully - Delete user`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteUserPath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteUser`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.DeleteUser(nil)
				Expect(returnValueErr).NotTo(BeNil())

				deleteUserOptions := testService.NewDeleteUserOptions(userName)
				returnValue, returnValueErr = testService.DeleteUser(deleteUserOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetDeleteUserResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAllRoles(getAllRolesOptions *GetAllRolesOptions)`, func() {
		getAllRolesPath := "/v1/roles"
		Context(`Successfully - List all roles`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAllRolesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAllRoles`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAllRoles(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAllRolesOptions := testService.NewGetAllRolesOptions()
				returnValue, returnValueErr = testService.GetAllRoles(getAllRolesOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAllRolesResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateRole(createRoleOptions *CreateRoleOptions)`, func() {
		createRolePath := "/v1/roles"
		Context(`Successfully - Create new role`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createRolePath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call CreateRole`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.CreateRole(nil)
				Expect(returnValueErr).NotTo(BeNil())

				createRoleOptions := testService.NewCreateRoleOptions()
				returnValue, returnValueErr = testService.CreateRole(createRoleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetCreateRoleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAllPermissions(getAllPermissionsOptions *GetAllPermissionsOptions)`, func() {
		getAllPermissionsPath := "/v1/roles/permissions"
		Context(`Successfully - List all permissions`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAllPermissionsPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAllPermissions`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAllPermissions(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAllPermissionsOptions := testService.NewGetAllPermissionsOptions()
				returnValue, returnValueErr = testService.GetAllPermissions(getAllPermissionsOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAllPermissionsResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetRole(getRoleOptions *GetRoleOptions)`, func() {
		getRolePath := "/v1/roles/{role_name}"
		roleName := "exampleString"
		getRolePath = strings.Replace(getRolePath, "{role_name}", roleName, 1)
		Context(`Successfully - Get role information`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getRolePath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetRole`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetRole(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getRoleOptions := testService.NewGetRoleOptions(roleName)
				returnValue, returnValueErr = testService.GetRole(getRoleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetRoleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateRole(updateRoleOptions *UpdateRoleOptions)`, func() {
		updateRolePath := "/v1/roles/{role_name}"
		roleName := "exampleString"
		updateRolePath = strings.Replace(updateRolePath, "{role_name}", roleName, 1)
		Context(`Successfully - Update role`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateRolePath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call UpdateRole`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.UpdateRole(nil)
				Expect(returnValueErr).NotTo(BeNil())

				updateRoleOptions := testService.NewUpdateRoleOptions(roleName)
				returnValue, returnValueErr = testService.UpdateRole(updateRoleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetUpdateRoleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteRole(deleteRoleOptions *DeleteRoleOptions)`, func() {
		deleteRolePath := "/v1/roles/{role_name}"
		roleName := "exampleString"
		deleteRolePath = strings.Replace(deleteRolePath, "{role_name}", roleName, 1)
		Context(`Successfully - Delete role`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteRolePath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteRole`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.DeleteRole(nil)
				Expect(returnValueErr).NotTo(BeNil())

				deleteRoleOptions := testService.NewDeleteRoleOptions(roleName)
				returnValue, returnValueErr = testService.DeleteRole(deleteRoleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetDeleteRoleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`ChangePassword(changePasswordOptions *ChangePasswordOptions)`, func() {
		changePasswordPath := "/v1/changepassword"
		password := "exampleString"
		Context(`Successfully - Change my password`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(changePasswordPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call ChangePassword`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.ChangePassword(nil)
				Expect(returnValueErr).NotTo(BeNil())

				changePasswordOptions := testService.NewChangePasswordOptions(password)
				returnValue, returnValueErr = testService.ChangePassword(changePasswordOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetChangePasswordResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetMe(getMeOptions *GetMeOptions)`, func() {
		getMePath := "/v1/me"
		Context(`Successfully - Get my account information`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getMePath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetMe`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetMe(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getMeOptions := testService.NewGetMeOptions()
				returnValue, returnValueErr = testService.GetMe(getMeOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetMeResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateMe(updateMeOptions *UpdateMeOptions)`, func() {
		updateMePath := "/v1/me"
		Context(`Successfully - Update my information`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateMePath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call UpdateMe`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.UpdateMe(nil)
				Expect(returnValueErr).NotTo(BeNil())

				updateMeOptions := testService.NewUpdateMeOptions()
				returnValue, returnValueErr = testService.UpdateMe(updateMeOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetUpdateMeResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAllAssetBundles(getAllAssetBundlesOptions *GetAllAssetBundlesOptions)`, func() {
		getAllAssetBundlesPath := "/v1/assetBundles"
		Context(`Successfully - Get the list of registered asset bundles`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAllAssetBundlesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAllAssetBundles`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAllAssetBundles(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAllAssetBundlesOptions := testService.NewGetAllAssetBundlesOptions()
				returnValue, returnValueErr = testService.GetAllAssetBundles(getAllAssetBundlesOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAllAssetBundlesResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateAssetBundle(updateAssetBundleOptions *UpdateAssetBundleOptions)`, func() {
		updateAssetBundlePath := "/v1/assetBundles"
		file := new(os.File)
		Context(`Successfully - Update a previously registered asset bundle`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateAssetBundlePath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call UpdateAssetBundle`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.UpdateAssetBundle(nil)
				Expect(returnValueErr).NotTo(BeNil())

				updateAssetBundleOptions := testService.NewUpdateAssetBundleOptions(file)
				returnValue, returnValueErr = testService.UpdateAssetBundle(updateAssetBundleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetUpdateAssetBundleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateAssetBundle(createAssetBundleOptions *CreateAssetBundleOptions)`, func() {
		createAssetBundlePath := "/v1/assetBundles"
		file := new(os.File)
		Context(`Successfully - Register a new Asset bundle`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createAssetBundlePath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call CreateAssetBundle`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.CreateAssetBundle(nil)
				Expect(returnValueErr).NotTo(BeNil())

				createAssetBundleOptions := testService.NewCreateAssetBundleOptions(file)
				returnValue, returnValueErr = testService.CreateAssetBundle(createAssetBundleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetCreateAssetBundleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAssetBundle(getAssetBundleOptions *GetAssetBundleOptions)`, func() {
		getAssetBundlePath := "/v1/assetBundles/{assetID}"
		assetID := "exampleString"
		getAssetBundlePath = strings.Replace(getAssetBundlePath, "{assetID}", assetID, 1)
		Context(`Successfully - Download a registered bundle as a zip file`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAssetBundlePath))
				Expect(req.Method).To(Equal("GET"))
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAssetBundle`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAssetBundle(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAssetBundleOptions := testService.NewGetAssetBundleOptions(assetID)
				returnValue, returnValueErr = testService.GetAssetBundle(getAssetBundleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteAssetBundle(deleteAssetBundleOptions *DeleteAssetBundleOptions)`, func() {
		deleteAssetBundlePath := "/v1/assetBundles/{assetID}"
		assetID := "exampleString"
		deleteAssetBundlePath = strings.Replace(deleteAssetBundlePath, "{assetID}", assetID, 1)
		Context(`Successfully - Delete an asset bundle`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteAssetBundlePath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteAssetBundle`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.DeleteAssetBundle(nil)
				Expect(returnValueErr).NotTo(BeNil())

				deleteAssetBundleOptions := testService.NewDeleteAssetBundleOptions(assetID)
				returnValue, returnValueErr = testService.DeleteAssetBundle(deleteAssetBundleOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetDeleteAssetBundleResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAsset(getAssetOptions *GetAssetOptions)`, func() {
		getAssetPath := "/v1/assets"
		assetType := "exampleString"
		assetProperty := "exampleString"
		assetValue := "exampleString"
		Context(`Successfully - Get an asset`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAssetPath))
				Expect(req.Method).To(Equal("GET"))
				Expect(req.URL.Query()["asset_type"]).To(Equal([]string{assetType}))

				Expect(req.URL.Query()["asset_property"]).To(Equal([]string{assetProperty}))

				Expect(req.URL.Query()["asset_value"]).To(Equal([]string{assetValue}))

				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAssetOptions := testService.NewGetAssetOptions(assetType, assetProperty, assetValue)
				returnValue, returnValueErr = testService.GetAsset(getAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateAsset(createAssetOptions *CreateAssetOptions)`, func() {
		createAssetPath := "/v1/assets"
		Context(`Successfully - Create an asset`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createAssetPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call CreateAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.CreateAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				createAssetOptions := testService.NewCreateAssetOptions()
				returnValue, returnValueErr = testService.CreateAsset(createAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetCreateAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteAsset(deleteAssetOptions *DeleteAssetOptions)`, func() {
		deleteAssetPath := "/v1/assets"
		Context(`Successfully - Delete Asset`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteAssetPath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.DeleteAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				deleteAssetOptions := testService.NewDeleteAssetOptions()
				returnValue, returnValueErr = testService.DeleteAsset(deleteAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetDeleteAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetAssetByID(getAssetByIDOptions *GetAssetByIDOptions)`, func() {
		getAssetByIDPath := "/v1/assets/{asset_id}"
		assetID := "exampleString"
		getAssetByIDPath = strings.Replace(getAssetByIDPath, "{asset_id}", assetID, 1)
		Context(`Successfully - Get an asset by id`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getAssetByIDPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetAssetByID`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetAssetByID(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getAssetByIDOptions := testService.NewGetAssetByIDOptions(assetID)
				returnValue, returnValueErr = testService.GetAssetByID(getAssetByIDOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetAssetByIDResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetTypes(getTypesOptions *GetTypesOptions)`, func() {
		getTypesPath := "/v1/types"
		Context(`Successfully - Get all asset types`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getTypesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetTypes`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetTypes(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getTypesOptions := testService.NewGetTypesOptions()
				returnValue, returnValueErr = testService.GetTypes(getTypesOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetTypesResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetTypeInfo(getTypeInfoOptions *GetTypeInfoOptions)`, func() {
		getTypeInfoPath := "/v1/types/{type_name}"
		typeName := "exampleString"
		getTypeInfoPath = strings.Replace(getTypeInfoPath, "{type_name}", typeName, 1)
		Context(`Successfully - Get type metadata`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getTypeInfoPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetTypeInfo`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetTypeInfo(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getTypeInfoOptions := testService.NewGetTypeInfoOptions(typeName)
				returnValue, returnValueErr = testService.GetTypeInfo(getTypeInfoOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetTypeInfoResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetTypeAssets(getTypeAssetsOptions *GetTypeAssetsOptions)`, func() {
		getTypeAssetsPath := "/v1/types/{type_name}/assets"
		typeName := "exampleString"
		getTypeAssetsPath = strings.Replace(getTypeAssetsPath, "{type_name}", typeName, 1)
		Context(`Successfully - Get assets of a particular type`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getTypeAssetsPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetTypeAssets`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetTypeAssets(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getTypeAssetsOptions := testService.NewGetTypeAssetsOptions(typeName)
				returnValue, returnValueErr = testService.GetTypeAssets(getTypeAssetsOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetTypeAssetsResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetRelatedAsset(getRelatedAssetOptions *GetRelatedAssetOptions)`, func() {
		getRelatedAssetPath := "/v1/relatedAssets"
		assetType := "exampleString"
		assetName := "exampleString"
		Context(`Successfully - Find related assets`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getRelatedAssetPath))
				Expect(req.Method).To(Equal("GET"))
				Expect(req.URL.Query()["asset_type"]).To(Equal([]string{assetType}))

				Expect(req.URL.Query()["asset_name"]).To(Equal([]string{assetName}))

				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetRelatedAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetRelatedAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getRelatedAssetOptions := testService.NewGetRelatedAssetOptions(assetType, assetName)
				returnValue, returnValueErr = testService.GetRelatedAsset(getRelatedAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetRelatedAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateRelatedAsset(createRelatedAssetOptions *CreateRelatedAssetOptions)`, func() {
		createRelatedAssetPath := "/v1/relatedAssets"
		Context(`Successfully - Relate with other assets`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createRelatedAssetPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call CreateRelatedAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.CreateRelatedAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				createRelatedAssetOptions := testService.NewCreateRelatedAssetOptions()
				returnValue, returnValueErr = testService.CreateRelatedAsset(createRelatedAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetCreateRelatedAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteRelatedAsset(deleteRelatedAssetOptions *DeleteRelatedAssetOptions)`, func() {
		deleteRelatedAssetPath := "/v1/relatedAssets"
		Context(`Successfully - Remove related asset`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteRelatedAssetPath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteRelatedAsset`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.DeleteRelatedAsset(nil)
				Expect(returnValueErr).NotTo(BeNil())

				deleteRelatedAssetOptions := testService.NewDeleteRelatedAssetOptions()
				returnValue, returnValueErr = testService.DeleteRelatedAsset(deleteRelatedAssetOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetDeleteRelatedAssetResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetMonitor(getMonitorOptions *GetMonitorOptions)`, func() {
		getMonitorPath := "/v1/monitor"
		Context(`Successfully - Check server status`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getMonitorPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				fmt.Fprintf(res, `{}`)
				res.WriteHeader(200)
			}))
			It(`Succeed to call GetMonitor`, func() {
				defer testServer.Close()

				testService, testServiceErr := icpdv1.NewIcpdV1(&icpdv1.IcpdV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				returnValue, returnValueErr := testService.GetMonitor(nil)
				Expect(returnValueErr).NotTo(BeNil())

				getMonitorOptions := testService.NewGetMonitorOptions()
				returnValue, returnValueErr = testService.GetMonitor(getMonitorOptions)
				Expect(returnValueErr).To(BeNil())
				Expect(returnValue).ToNot(BeNil())

				result := testService.GetGetMonitorResult(returnValue)
				Expect(result).ToNot(BeNil())
			})
		})
	})
})
