# HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products
Synchronizes Azure AD groups to HelloID Self service products

<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products/network/members"><img src="https://img.shields.io/github/forks/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products" alt="Forks Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products/pulls"><img src="https://img.shields.io/github/issues-pr/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products" alt="Pull Requests Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products/issues"><img src="https://img.shields.io/github/issues/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products" alt="Issues Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products?color=2b9348"></a>

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Table of Contents
- [HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products](#helloid-conn-sa-sync-azureactivedirectory-groups-to-selfservice-products)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Create an API key and secret for HelloID](#create-an-api-key-and-secret-for-helloid)
    - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
      - [Application Registration](#application-registration)
      - [Configuring App Permissions](#configuring-app-permissions)
      - [Authentication and Authorization](#authentication-and-authorization)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- **App ID & App Secret** for the app registration with permissions to the Microsoft Graph API.
- Make sure the sychronization is configured to meet your requirements.

## Introduction
By using this connector, you will have the ability to create and remove HelloID SelfService Products based on groups in your Azure Active Directory.

The products will be create for each group in scope. This way you won't have to manually create a product for each group.

And vice versa for the removing of the products. The products will be removed (or disabled, based on your preference) when a group is nog longer in scope. This way no products will remain that "should no longer exist".

This is intended for scenarios where there are (lots of) groups that we want to be requestable as a product. This group sync is desinged to work in combination with the [Azure Active Directory Groupmembersips to Productassignments Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groupmemberships-To-SelfService-Productassignments).

## Getting started

### Create an API key and secret for HelloID
1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.

### Getting the Azure AD graph API access

By using this connector you will have the ability to manage Azure AD Guest accounts.

#### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

#### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

#### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Overview</b>.

### Synchronization settings
| Variable name | Description   | Notes |
| ------------- | -----------   | ----- |
| $portalBaseUrl    | String value of HelloID Base Url  | (Default Global Variable) |
| $portalApiKey | String value of HelloID Api Key   | (Default Global Variable) |
| $portalApiSecret  | String value of HelloID Api Secret    | (Default Global Variable) |
| $AzureADtenantID    | String value of Azure AD Tenant ID  | Recommended to set as Global Variable |
| $AzureADAppId | String value of Azure AD App ID  | Recommended to set as Global Variable |
| $AzureADAppSecret  | String value of Azure AD App Secret  | Recommended to set as Global Variable |
| $AzureADGroupsSearchFilter   | String value of seachfilter of which Azure AD groups to include   | Optional, when no filter is provided ($AzureADGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections  |
| $ProductAccessGroup  | String value of which HelloID group will have access to the products | Optional, if not found, the product is created without Access Group  |
| $ProductCategory  | String value of which HelloID category will be used for the products | Required, must be an existing category if not found, the task will fail  |
| $SAProductResourceOwner  | String value of which HelloID group to use as resource owner for the products | Optional, if empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")  |
| $SAProductWorkflow  | String value of which HelloID Approval Workflow to use for the products | Optional, if empty. The Default HelloID Workflow is used. If specified Workflow does not exist the task will fail  |
| $FaIcon  | String value of which Font Awesome icon to use for the products | For more valid icon names, see the Font Awesome cheat sheet [here](https://fontawesome.com/v5/cheatsheet)  |
| $productVisibility  | String value of which Visbility to use for the products | Supported values: All, Resource Owner And Manager, Resource Owner, Disabled. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $productRequestCommentOption  | String value of which Comment Option to use for the products | Supported values: Optional, Hidden, Required. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $returnProductOnUserDisable  | Boolean value of whether to set the option Return Product On User Disable for the products | For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $createDefaultEmailActions  | Boolean value of whether to set the option Create Default Email Action for the products | For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $multipleRequestOption  | Integer value of which option of Multiple Requests to use for the products | Supported values: 1, 2.For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $removeProduct  | Boolean value of whether to remove the products when they are no longer in scope | If set to $false, obsolete products will be disabled  |
| $overwriteExistingProduct  | Boolean value of whether to overwrite existing products in scope with the specified properties of this task | **Only meant for when you changed something in the product properties (e.g. the description, approval worklow or icon) and need to update this for all products in scope, should not be set to true when running daily!**  |
| $overwriteExistingProductAction  | Boolean value of whether to overwrite existing actions of products in scope with the specified actions of this task | **Only meant for when you changed something in the product actions and need to update this for all products in scope, should not be set to true when running daily!**  |
| $addMissingProductAction  | Boolean value of whether to add the missing specified actions of this task to existing products in scope | **Only meant when you **Only meant for when you changed the product actions and need to add this to all products in scope, should not be set to true when running daily!**  |
| $ProductSkuPrefix | String value of prefix that will be used in the Code for the products | Optional, but recommended, when no SkuPrefix is provided the products won't be recognizable as created by this task |
| $azureADGroupUniqueProperty   | String value of name of the property that is unique for the Azure AD groups and will be used in the Code for the products | The default value ("id") is set be as unique as possible   |

## Remarks
- The Products are created and removed by default. Make sure your configuration is correct to avoid unwanted removals (and change this to disable)
- This group sync is desinged to work in combination with the [Azure Active Directory Groupmembersips to Productassignments Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groupmemberships-To-SelfService-Productassignments).

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
