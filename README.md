# IBM Cloud Pak for Data - Go SDK
This repository contains Go SDKs that are produced with the
[IBM OpenAPI SDK Generator](https://github.ibm.com/CloudEngineering/openapi-sdkgen).

You can use the contents of this repository to understand creating Go SDKs.

## Steps to create a similar Go SDK

##### 1. Copy the repository 
Copy the files contained in this repository [Go SDK Template](https://github.ibm.com/CloudEngineering/go-sdk-template) as a starting point when building your own Go SDK
for one or more IBM Cloud services.

##### 2. Modify the copied files to reflect your SDK
The following files will need to be modified after copying them from this template repository:
* .travis.yml - Update this file as needed to incorporate any required steps for your SDK


* headers.go - Go SDKs built with the IBM OpenAPI SDK Generator
need to implement a package called "common" which contains a function called `GetSdkHeaders`.  
The `GetSdkHeaders` function is invoked by the generated service methods and should be modified to suit the
needs of your particular SDK.

##### 3. Generate the Go code with the IBM OpenAPI SDK Generator
This is the step that you've been waiting for!

In this step, you'll invoke the IBM OpenAPI SDK Generator to process your API definition.

This will generate a collection of Go source files which will be included in your SDK project.
You'll find instructions on how to do this [here](https://github.ibm.com/CloudEngineering/openapi-sdkgen/wiki).

##### 4. Integration tests
Integration tests are recommended to be a part of SDKs to validate the working and functionality of APIs in all scenarios. For a reference, observe the existing integration tests in this repo - `icpd_v1_integration_test.go` file.
