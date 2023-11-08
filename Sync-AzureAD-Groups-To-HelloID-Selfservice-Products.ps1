#####################################################
# HelloID-SA-Sync-AzureAD-Groups-To-Products
#
# Version: 2.0.0
#####################################################
$VerbosePreference = "SilentlyContinue"
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey = "" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

#AzureAD Connection Configuration
$MSGraphBaseUri = "https://graph.microsoft.com/" # Fixed value
# $AzureADtenantID = "" # Set from Global Variable
# $AzureADAppId = "" # Set from Global Variable
# $AzureADAppSecret = "" # Set from Global Variable
$azureADGroupsSearchFilter = "`$search=`"displayName:department_`"" # Optional, when no filter is provided ($azureADGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections

#HelloID Self service Product Configuration
$productAccessGroup = "Local/__HelloID Selfservice Users"  # If not found, the product is created without extra Access Group
$calculateProductResourceOwnerPrefixSuffix = $false # If True the resource owner group will be defined per product based on specfied prefix or suffix - If no calculated group is found, the group from $productResourseOwner will be used
$calculatedResourceOwnerGroupSource = "AzureAD" # Specify the source of the groups - if left empty, this will result in creation of a new group
$calculatedResourceOwnerGroupPrefix = "" # Specify prefix to recognize the owner group - the owner group will be queried based on the Group name and the specified prefix and suffix - if both left empty, this will result in creation of a new group - if group is not found, it will be created
$calculatedResourceOwnerGroupSuffix = " - Owner" # Specify suffix to recognize the owner group - the owner group will be queried based on the Group name and the specified prefix and suffix - if both left empty, this will result in creation of a new group - if group is not found, it will be created
$productResourseOwner = "AzureAD/HelloID_SA_Owners" # If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]") - Only used when is false
$productApprovalWorkflowId = "37ccd286-9f22-44e3-bc2e-7f421387e98e" # If empty, the Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.
$productVisibility = "All" # If empty, "Disabled" is used. Supported options: All, ResourceOwnerAndManager, ResourceOwner, Disabled
$productRequestCommentOption = "Required" # If empty, "Optional" is used. Supported options: Optional, Hidden, Required
$productAllowMultipleRequests = $false # If True the product can be requested unlimited times
$productFaIcon = "windows"
$productCategory = "Application Groups" # If the category is not found, the task will fail
$productReturnOnUserDisable = $true # If True the product will be returned when the user owning the product gets disabled

$removeProduct = $true # If False product will be disabled
$overwriteExistingProduct = $false # If True existing product will be overwritten with the input from this script (e.g. the, description, approval worklow or icon). Only use this when you actually changed the product input
$overwriteExistingProductAction = $false  # If True existing product actions will be overwritten with the input from this script. Only use this when you actually changed the script or variables for the action(s)
$addMissingProductAction = $false # If True missing product actions (according to the the input from this script) will be added

$removeProduct = $true # If False product will be disabled
$overwriteExistingProduct = $true # If True existing product will be overwritten with the input from this script (e.g. the approval worklow or icon). Only use this when you actually changed the product input
# Note: Actions are always overwritten, no compare takes place between the current actions and the actions this sync would set
$overwriteAccessGroup = $false # Should be on false by default, only set this to true to overwrite product access group - Only meant for "manual" bulk update, not daily scheduled
# Note: Access group is always overwritten, no compare takes place between the current access group and the access group this sync would set

#Target System Configuration
# Dynamic property invocation
# The prefix will be used as the first part HelloID Self service Product SKU.
$ProductSkuPrefix = "AADGRP"
# The value of the property will be used as HelloID Self service Product SKU
$azureADGroupUniqueProperty = "id"

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatParams = @{
            Uri         = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers     = $headers
            Method      = $Method
            ErrorAction = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatParams["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatParams
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatParams["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatParams

            return $response
        }

    }
    catch {
        throw $_
    }
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $authUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}
#endregion functions

#region HelloId_Actions_Variables
#region Add AzureAD user to Group script
<# First use a double-quoted here-string, where variables are replaced by their values here string (to be able to use a variable) #>
$addAzureADUserToAzureADGroupScript = @"
`$group = [Guid]::New((`$product.code.replace("$ProductSkuPrefix","")))

"@
<# Then use a single-quoted here-string, where variables are interpreted literally and reproduced exactly #> 
$addAzureADUserToAzureADGroupScript = $addAzureADUserToAzureADGroupScript + @'
$user = $request.requestedFor.userName

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Microsoft Graph API
$MSGraphBaseUri = "https://graph.microsoft.com/" # Fixed value

# Set from Global Variable
# $AzureADTenantID = "<Azure AD Tenant ID>" # Set from Global Variable
# $AzureADAppId = "<Azure AD App ID>" # Set from Global Variable
# $AzureADAppSecret = "<Azure AD App Secret>" # Set from Global Variable

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }

        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $authUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions
try {
    $headers = New-AuthorizationHeaders -TenantId $AzureADTenantID -ClientId $AzureADAppId -ClientSecret $AzureADAppSecret
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error creating authorization headers. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Query Azure AD user (to use object in further actions)
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
    $queryAzureADUserSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/users/$($user)"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Querying Azure AD user [$($user)]"

    $azureAdUser = Invoke-RestMethod @queryAzureADUserSplatParams -Verbose:$false
  
    # Check result count, and throw error when no results are found.
    if (($azureAdUser | Measure-Object).Count -eq 0) {
        throw "Azure AD user [$($user)] not found"
    }

    Write-Information "Successfully queried Azure AD user [$($user)]. Name: [$($azureAdUser.displayName)], UserPrincipalName: [$($azureAdUser.userPrincipalName)], ID: [$($azureAdUser.id)]"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD user [$($user)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Query Azure AD group (to use object in further actions)
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http
    $queryAzureADGroupSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($group)"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Querying Azure AD group [$($group)]"

    $azureAdGroup = Invoke-RestMethod @queryAzureADGroupSplatParams -Verbose:$false
  
    # Check result count, and throw error when no results are found.
    if (($azureAdGroup | Measure-Object).Count -eq 0) {
        throw "Azure AD group [$($group)] not found"
    }

    Write-Information "Successfully queried Azure AD group [$($group)]. Name: [$($azureAdGroup.displayName)], Description: [$($azureAdGroup.description)], ID: [$($azureAdGroup.id)]"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD group [$($group)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Add Azure AD user to Azure AD group
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
    $body = [PSCustomObject]@{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($azureAdUser.id)"
    } | ConvertTo-Json -Depth 10

    $addAzureADMemberToGroupSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($azureAdGroup.id)/members/`$ref"
        Headers     = $headers
        Method      = 'POST'
        Body        = ([System.Text.Encoding]::UTF8.GetBytes($body))
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Adding Azure AD user [$($azureAdUser.id)] to Azure AD group [$($azureAdGroup.id)]"

    $addAzureADMemberToGroup = Invoke-RestMethod @addAzureADMemberToGroupSplatParams -Verbose:$false

    $Log = @{
        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Successfully added Azure AD user [$($azureAdUser.displayName)] to Azure AD group [$($azureAdGroup.displayName)]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $azureAdUser.displayName # optional (free format text)
        TargetIdentifier  = $azureAdUser.id # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
    # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    if ($errorMessage.auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
        $Log = @{
            Action            = "GrantMembership" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Azure AD user [$($azureAdUser.displayName)] is already a member of Azure AD group [$($azureAdGroup.displayName)]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $azureAdUser.displayName # optional (free format text)
            TargetIdentifier  = $azureAdUser.id # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    else {
        $Log = @{
            Action            = "GrantMembership" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Error adding Azure AD user [$($azureAdUser.displayName)] to Azure AD group [$($azureAdGroup.displayName)]. Error Message: $($errorMessage.AuditErrorMessage)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $azureAdUser.displayName # optional (free format text)
            TargetIdentifier  = $azureAdUser.id # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        
        throw "Error adding Azure AD user [$($azureAdUser.displayName)] to Azure AD group [$($azureAdGroup.displayName)]. Error Message: $($errorMessage.AuditErrorMessage)"
    }
}
'@
#endregion Add AzureAD user to Group script

#region Remove AzureAD user from Group script
<# First use a double-quoted here-string, where variables are replaced by their values here string (to be able to use a variable) #>
$removeAzureADUserFromAzureADGroupScript = @"
`$group = [Guid]::New((`$product.code.replace("$ProductSkuPrefix","")))

"@
<# Then use a single-quoted here-string, where variables are interpreted literally and reproduced exactly #> 
$removeAzureADUserFromAzureADGroupScript = $removeAzureADUserFromAzureADGroupScript + @'
$user = $request.requestedFor.userName

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Microsoft Graph API
$MSGraphBaseUri = "https://graph.microsoft.com/" # Fixed value

# Set from Global Variable
# $AzureADTenantID = "<Azure AD Tenant ID>" # Set from Global Variable
# $AzureADAppId = "<Azure AD App ID>" # Set from Global Variable
# $AzureADAppSecret = "<Azure AD App Secret>" # Set from Global Variable

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }

        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $authUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions
try {
    $headers = New-AuthorizationHeaders -TenantId $AzureADTenantID -ClientId $AzureADAppId -ClientSecret $AzureADAppSecret
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error creating authorization headers. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Query Azure AD user (to use object in further actions)
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
    $queryAzureADUserSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/users/$($user)"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Querying Azure AD user [$($user)]"

    $azureAdUser = Invoke-RestMethod @queryAzureADUserSplatParams -Verbose:$false
  
    # Check result count, and throw error when no results are found.
    if (($azureAdUser | Measure-Object).Count -eq 0) {
        throw "Azure AD user [$($user)] not found"
    }

    Write-Information "Successfully queried Azure AD user [$($user)]. Name: [$($azureAdUser.displayName)], UserPrincipalName: [$($azureAdUser.userPrincipalName)], ID: [$($azureAdUser.id)]"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD user [$($user)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Query Azure AD group (to use object in further actions)
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http
    $queryAzureADGroupSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($group)"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Querying Azure AD group [$($group)]"

    $azureAdGroup = Invoke-RestMethod @queryAzureADGroupSplatParams -Verbose:$false
  
    # Check result count, and throw error when no results are found.
    if (($azureAdGroup | Measure-Object).Count -eq 0) {
        throw "Azure AD group [$($group)] not found"
    }

    Write-Information "Successfully queried Azure AD group [$($group)]. Name: [$($azureAdGroup.displayName)], Description: [$($azureAdGroup.description)], ID: [$($azureAdGroup.id)]"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD group [$($group)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Remove Azure AD user from Azure AD group
try {
    # More information about the API call: https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http
    $removeAzureADMemberToGroupSplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($azureAdGroup.id)/members/$($azureAdUser.id)/`$ref"
        Headers     = $headers
        Method      = 'DELETE'
        ErrorAction = 'Stop' # Makes sure the action enters the catch when an error occurs
    }

    Write-Verbose "Removing Azure AD user [$($azureAdUser.id)] from Azure AD group [$($azureAdGroup.id)]"

    $removeAzureADMemberToGroup = Invoke-RestMethod @removeAzureADMemberToGroupSplatParams -Verbose:$false

    $Log = @{
        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Successfully removed Azure AD user [$($azureAdUser.displayName)] from Azure AD group [$($azureAdGroup.displayName)]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $azureAdUser.displayName # optional (free format text)
        TargetIdentifier  = $azureAdUser.id # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
    # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    if ($auditErrorMessage -like "*Error code: Request_ResourceNotFound*" -and $auditErrorMessage -like "*$($azureAdGroup.id)*") {
        $Log = @{
            Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Azure AD user [$($azureAdUser.displayName)] is already no longer a member of Azure AD group [$($azureAdGroup.displayName)]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $azureAdUser.displayName # optional (free format text)
            TargetIdentifier  = $azureAdUser.id # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    else {
        $Log = @{
            Action            = "GrantMembership" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Error removing Azure AD user [$($azureAdUser.displayName)] from Azure AD group [$($azureAdGroup.displayName)]. Error Message: $($errorMessage.AuditErrorMessage)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $azureAdUser.displayName # optional (free format text)
            TargetIdentifier  = $azureAdUser.id # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        
        throw "Error removing Azure AD user [$($azureAdUser.displayName)] from Azure AD group [$($azureAdGroup.displayName)]. Error Message: $($errorMessage.AuditErrorMessage)"
    }
}
'@
#endregion Remove AzureAD user from Group script
#endregion HelloId_Actions_Variables

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Azure Active Directory to HelloID Self service Producs"
Hid-Write-Status -Event Information -Message "------[[Azure Active Directory]]-----------"
# Get Azure AD Groups
try {  
    $headers = New-AuthorizationHeaders -TenantId $azureADtenantID -ClientId $azureADAppId -ClientSecret $azureADAppSecret

    $properties = @(
        "id"
        , "displayName"
        , "description"
        , "onPremisesSyncEnabled"
        , "groupTypes"
    )
    $select = "`$select=$($properties -join ",")"

    $m365GroupFilter = "groupTypes/any(c:c+eq+'Unified')"
    $securityGroupFilter = "NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true"
    $managableGroupsFilter = "`$filter=$m365GroupFilter or $securityGroupFilter"
  
    $azureADQuerySplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups?$managableGroupsFilter&$azureADGroupsSearchFilter&$select&`$top=999&`$count=true"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop'
    }

    $azureADGroups = [System.Collections.ArrayList]@()
    $getAzureADGroupsResponse = $null
    $getAzureADGroupsResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
    if ($getAzureADGroupsResponse.value -is [array]) {
        [void]$azureADGroups.AddRange($getAzureADGroupsResponse.value)
    }
    else {
        [void]$azureADGroups.Add($getAzureADGroupsResponse.value)
    }

    while (![string]::IsNullOrEmpty($getAzureADGroupsResponse.'@odata.nextLink')) {
        $azureADQuerySplatParams = @{
            Uri         = $getAzureADGroupsResponse.'@odata.nextLink'
            Headers     = $headers
            Method      = 'GET'
            ErrorAction = 'Stop'
        }
        $getAzureADGroupsResponse = $null
        $getAzureADGroupsResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
        if ($getAzureADGroupsResponse.value -is [array]) {
            [void]$azureADGroups.AddRange($getAzureADGroupsResponse.value)
        }
        else {
            [void]$azureADGroups.Add($getAzureADGroupsResponse.value)
        }
    }


    $azureADGroupsInScope = [System.Collections.Generic.List[Object]]::New()
    foreach ($azureADGroup in $azureADGroups) {
        # Custom - Only process groups with a description
        if ([string]::IsNullOrEmpty($azureADGroup.description)) {
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Warning "No description set in Azure AD for Azure AD group [$($azureADGroup)]"
            }
        }
        else {
            [void]$azureADGroupsInScope.Add($azureADGroup)
        }
    }

    if (($azureADGroupsInScope | Measure-Object).Count -eq 0) {
        throw "No Azure Active Directory Groups have been found"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Azure AD groups. Result count: $(($azureADGroupsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD groups that match filter [$($azureADGroupsSearchFilter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[HelloID]------"
try {

    $splatParams = @{
        Method = "GET"
        Uri    = "agentpools"
    }
    $helloIDAgentPools = Invoke-HIDRestMethod @splatParams

    # Filter for default agent pool
    $helloIDAgentPoolsInScope = $null
    $helloIDAgentPoolsInScope = $helloIDAgentPools | Where-Object { $_.options -eq "1" }
    Hid-Write-Status -Event Success -Message "Successfully queried agent pools from HelloID (after filtering for default agent pool). Result count: $(($helloIDAgentPoolsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying agent pools from from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    $splatParams = @{
        Method = "GET"
        Uri    = "selfservice/categories"
    }
    $helloIDSelfserviceCategories = Invoke-HIDRestMethod @splatParams

    # Filter for specified category
    $helloIDSelfserviceCategoriesInScope = $null
    $helloIDSelfserviceCategoriesInScope = $helloIDSelfserviceCategories | Where-Object { $_.name -eq "$productCategory" }

    if (($helloIDSelfserviceCategoriesInScope | Measure-Object).Count -eq 0) {
        throw "No HelloID Self service Categories have been found with the name [$productCategory]"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Self service product categories from HelloID (after filtering for specified category). Result count: $(($helloIDSelfserviceCategoriesInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service product categories from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    $splatParams = @{
        Method   = "GET"
        Uri      = "products"
        PageSize = 1000
    }
    $helloIDSelfServiceProducts = Invoke-HIDRestMethod @splatParams

    # Filter for products with specified Sku Prefix
    if (-not[String]::IsNullOrEmpty($ProductSkuPrefix)) {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts | Where-Object { $_.code -like "$($ProductSkuPrefix)*" }
    }
    else {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts
    }

    $helloIDSelfServiceProductsInScopeGrouped = $helloIDSelfServiceProductsInScope | Group-Object -Property "code" -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified SKU prefix). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    $splatParams = @{
        Method   = "GET"
        Uri      = "groups"
        PageSize = 1000
    }
    $helloIDGroups = Invoke-HIDRestMethod @splatParams

    $helloIDGroupsInScope = $null
    $helloIDGroupsInScope = $helloIDGroups 

    $helloIDGroupsInScope | Add-Member -MemberType NoteProperty -Name SourceAndName -Value $null
    $helloIDGroupsInScope | ForEach-Object {
        if ([string]::IsNullOrEmpty($_.source)) {
            $_.source = "Local"
        }
        $_.SourceAndName = "$($_.source)/$($_.name)"
    }
    $helloIDGroupsInScopeGroupedBySourceAndName = $helloIDGroupsInScope | Group-Object -Property "SourceAndName" -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Groups from HelloID. Result count: $(($helloIDGroupsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Groups from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete products
try {
    # Define product objects
    $productObjects = [System.Collections.ArrayList]@()
    foreach ($azureADGroupInScope in $azureADGroupsInScope) {
        # Define ManagedBy Group
        if ( $calculateProductResourceOwnerPrefixSuffix -eq $true ) {
            # Calculate resource owner group by specfied prefix or suffix
            if (-not[string]::IsNullOrEmpty($($calculatedResourceOwnerGroupPrefix)) -or -not[string]::IsNullOrEmpty($($calculatedResourceOwnerGroupSuffix))) {
                $resourceOwnerGroupName = "$($calculatedResourceOwnerGroupSource)/" + "$($calculatedResourceOwnerGroupPrefix)" + "$($azureADGroupInScope.DisplayName)" + "$($calculatedResourceOwnerGroupSuffix)"
            }
            elseif ([string]::IsNullOrEmpty($($calculatedResourceOwnerGroupPrefix)) -and [string]::IsNullOrEmpty($($calculatedResourceOwnerGroupSuffix))) {
                $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($productResourseOwner) ) { "Local/$($azureADGroupInScope.DisplayName) Resource Owners" } else { $productResourseOwner }
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Warning "No Resource Owner Group Prefix of Suffix specified. Using default resource owner group [$($resourceOwnerGroupName)]"
                }
            }
        }
        else {
            $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($productResourseOwner) ) { "Local/$($azureADGroupInScope.DisplayName) Resource Owners" } else { $productResourseOwner }
        }

        # Get HelloID Resource Owner Group and create if it doesn't exist
        $helloIDResourceOwnerGroup = $null
        if (-not[string]::IsNullOrEmpty($resourceOwnerGroupName)) {
            $helloIDResourceOwnerGroup = $helloIDGroupsInScopeGroupedBySourceAndName["$($resourceOwnerGroupName)"]
            if ($null -eq $helloIDResourceOwnerGroup) {
                # Only create group if it's a Local group (otherwise sync should handle this)
                if ($resourceOwnerGroupName -like "Local/*") {
                    # Create HelloID Resource Owner Group
                    try {                       
                        $helloIDGroupBody = @{
                            Name      = "$($resourceOwnerGroupName.split("/")[-1])"
                            IsEnabled = $true
                            Source    = "Local"
                        }

                        $splatParams = @{
                            Method = "POST"
                            Uri    = "groups"
                            Body   = ($helloIDGroupBody | ConvertTo-Json -Depth 10)
                        }

                        if ($dryRun -eq $false) {
                            $helloIDResourceOwnerGroup = Invoke-HIDRestMethod @splatParams
        
                            if ($verboseLogging -eq $true) {
                                Hid-Write-Status -Event Success "Successfully created new resource owner group [$($resourceOwnerGroupName)] for HelloID Self service Product [$($newProduct.Name)]"
                            }
                        }
                        else {
                            if ($verboseLogging -eq $true) {
                                Hid-Write-Status -Event Warning "DryRun: Would create new resource owner group [$($resourceOwnerGroupName)] for HelloID Self service Product [$($newProduct.Name)]"
                            }
                        }
                    }
                    catch {
                        $ex = $PSItem
                        $errorMessage = Get-ErrorMessage -ErrorObject $ex
                        
                        Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
                        
                        throw "Error creating new resource owner group [$($resourceOwnerGroupName)] for HelloID Self service Product [$($newProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Warning "No resource owner group [$($resourceOwnerGroupName)] found for HelloID Self service Product [$($newProduct.Name)]"
                    }
                }
            }
        }

        # Define actions for product
        #region Define On Request actions
        $onRequestActions = [System.Collections.Generic.list[object]]@()
        #endregion Define On Request actions

        #region Define On Approve actions
        $onApproveActions = [System.Collections.Generic.list[object]]@()

        # Add action to Add Azure AD user to Azure AD Group
        [void]$onApproveActions.Add([PSCustomObject]@{
                id          = "" # supplying an id when creating a product action is not supported. You have to leave the 'id' property empty or leave the property out alltogether when creating a new product action
                name        = "Add-AzureADUserToAzureADGroup"
                script      = $addAzureADUserToAzureADGroupScript
                agentPoolId = "$($helloIDAgentPoolsInScope.agentPoolGUID)"
                runInCloud  = $false
            })
        #endregion Define On Approve actions

        #region Define On Deny actions
        $onDenyActions = [System.Collections.Generic.list[object]]@()
        #endregion Define On Deny actions

        #region Define On Return actions
        $onReturnActions = [System.Collections.Generic.list[object]]@()

        # Add action to Remove Azure AD user from Azure AD Group
        [void]$onReturnActions.Add([PSCustomObject]@{
                id          = "" # supplying an id when creating a product action is not supported. You have to leave the 'id' property empty or leave the property out alltogether when creating a new product action
                name        = "Remove-AzureADUserFromAzureADGroup"
                script      = $removeAzureADUserFromAzureADGroupScript
                agentPoolId = "$($helloIDAgentPoolsInScope.agentPoolGUID)"
                runInCloud  = $false
            })

        #endregion Define On Return actions

        #region Define On Withdrawn actions
        $onWithdrawnActions = [System.Collections.Generic.list[object]]@()
        #endregion Define On Withdrawn actions

        $productObject = [PSCustomObject]@{
            name                       = "$($azureADGroupInScope.displayName)"
            description                = "Access to the group $($azureADGroupInScope.displayName)"
            code                       = ("$($ProductSKUPrefix)" + "$($adGroupInScope.$azureADGroupUniqueProperty)").Replace("-", "")
            resourceOwnerGroup         = [PSCustomObject]@{
                id = $helloIDResourceOwnerGroup.groupGuid
            }
            approvalWorkflow           = [PSCustomObject]@{
                id = $productApprovalWorkflowId
            }
            showPrice                  = $false
            price                      = $null
            visibility                 = $productVisibility
            requestComment             = $productRequestCommentOption
            maxCount                   = $null
            hasRiskFactor              = $false
            riskFactor                 = 1
            allowMultipleRequests      = $productAllowMultipleRequests
            icon                       = $null
            useFaIcon                  = $true 
            faIcon                     = "fa-$productFaIcon"
            categories                 = @(
                [PSCustomObject]@{
                    id = "$($helloIDSelfserviceCategoriesInScope.selfServiceCategoryGUID)"
                }
            )
            agentPool                  = [PSCustomObject]@{
                id = "$($helloIDAgentPoolsInScope.agentPoolGUID)"
            }
            returnOnUserDisable        = $productReturnOnUserDisable
            
            # Form
            dynamicForm                = $null

            # Actions
            onRequest                  = $onRequestActions
            onApprove                  = $onApproveActions
            onDeny                     = $onDenyActions
            onReturn                   = $onReturnActions
            onWithdrawn                = $onWithdrawnActions

            # Groups - Are set with an additional API call
            
            # Time Limit
            hasTimeLimit               = $false
            managerCanOverrideDuration = $true
            limitType                  = "Maximum"
            ownershipMaxDuration       = 3650
        }

        [void]$productObjects.Add($productObject)
    }

    # Define product to create
    $newProducts = [System.Collections.ArrayList]@()
    $newProducts = $productObjects | Where-Object { $_.Code -notin $helloIDSelfServiceProductsInScope.code }

    # Define products to revoke
    $obsoleteProducts = [System.Collections.ArrayList]@()
    $obsoleteProducts = $helloIDSelfServiceProductsInScope | Where-Object { $_.code -notin $productObjects.Code }

    # Define products already existing
    $existingProducts = [System.Collections.ArrayList]@()
    $existingProducts = $productObjects | Where-Object { $_.code -in $helloIDSelfServiceProductsInScope.Code }

    # Define total products (existing + new products)
    $totalProducts = ($(($existingProducts | Measure-Object).Count) + $(($newProducts | Measure-Object).Count))
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete products. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Summary]------"

Hid-Write-Status -Event Information -Message "Total Azure AD Groups in scope [$(($azureADGroupsInScope | Measure-Object).Count)]"

if ($overwriteExistingProduct -eq $true -or $overwriteExistingProductAction -eq $true -or $addMissingProductAction -eq $true) {
    Hid-Write-Status -Event Information "Total HelloID Self service Product(s) already exist (and will be updated) [$(($existingProducts | Measure-Object).Count)]. Overwrite Product: [$($overwriteExistingProduct)]"
}
else {
    Hid-Write-Status -Event Information -Message "Total HelloID Self service Product(s) already exist (and won't be changed) [$(($existingProducts | Measure-Object).Count)]"
}

Hid-Write-Status -Event Information -Message "Total HelloID Self service Product(s) to create [$(($newProducts | Measure-Object).Count)]"

if ($removeProduct) {
    Hid-Write-Status -Event Information "Total HelloID Self service Product(s) to remove [$(($obsoleteProducts | Measure-Object).Count)]"
}
else {
    Hid-Write-Status -Event Information "Total HelloID Self service Product(s) to disable [$(($obsoleteProducts | Measure-Object).Count)]"
}

Hid-Write-Status -Event Information -Message "------[Processing]------------------"
try {
    $productCreatesSuccess = 0
    $productCreatesError = 0
    foreach ($newProduct in $newProducts) {
        try {
            # Create HelloID Self service Product
            try {
                # Create custom productbody object
                $createHelloIDSelfServiceProductBody = [PSCustomObject]@{}

                # Copy product properties into productbody object
                $newProduct.psobject.properties | ForEach-Object {
                    $createHelloIDSelfServiceProductBody | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                }
                
                $splatParams = @{
                    Method      = "POST"
                    Uri         = "products"
                    Body        = ($createHelloIDSelfServiceProductBody | ConvertTo-Json -Depth 10)
                    ErrorAction = "Stop"
                }

                if ($dryRun -eq $false) {
                    $createdHelloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams

                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Success "Successfully created HelloID Self service Product [$($createHelloIDSelfServiceProductBody.Name)]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Warning "DryRun: Would create HelloID Self service Product [$($createHelloIDSelfServiceProductBody.name)]"
                    }
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
                throw "Error creating HelloID Self service Product [$($createHelloIDSelfServiceProductBody.name)]. Error Message: $($errorMessage.AuditErrorMessage)"
            }

            # Get HelloID Access Group
            $helloIDAccessGroup = $null
            $helloIDAccessGroup = $helloIDGroupsInScopeGroupedBySourceAndName["$($productAccessGroup)"]

            # Add HelloID Access Group to HelloID Self service Product
            if (-not $null -eq $helloIDAccessGroup) {
                try {
                    $addHelloIDAccessGroupToProductBody = @{
                        GroupGuid = "$($helloIDAccessGroup.groupGuid)"
                    }

                    $splatParams = @{
                        Method = "POST"
                        Uri    = "selfserviceproducts/$($createdHelloIDSelfServiceProduct.productId)/groups"
                        Body   = ($addHelloIDAccessGroupToProductBody | ConvertTo-Json -Depth 10)
                    }

                    if ($dryRun -eq $false) {
                        $addHelloIDAccessGroupToProduct = Invoke-HIDRestMethod @splatParams

                        if ($verboseLogging -eq $true) {
                            Hid-Write-Status -Event Success "Successfully added HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($createdHelloIDSelfServiceProduct.Name)]"
                        }
                    }
                    else {
                        if ($verboseLogging -eq $true) {
                            Hid-Write-Status -Event Warning "DryRun: Would add HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($createdHelloIDSelfServiceProduct.Name)]"
                        }
                    }
                }
                catch {
                    $ex = $PSItem
                    $errorMessage = Get-ErrorMessage -ErrorObject $ex
                
                    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
                
                    throw "Error adding HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($createdHelloIDSelfServiceProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
                }
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status  -Event Warning -Message "The Specified HelloID Access Group [$($productAccessGroup)] does not exist. We will continue without adding the access Group to HelloID Self service Product [$($createdHelloIDSelfServiceProduct.Name)]"
                }
            }
            $productCreatesSuccess++            
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            $productCreatesError++
            throw "Error creating HelloID Self service Product [$($newProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    if ($dryRun -eq $false) {
        if ($productCreatesSuccess -ge 1 -or $productCreatesError -ge 1) {
            Hid-Write-Status -Event Information -Message "Created HelloID Self service Products. Success: $($productCreatesSuccess). Error: $($productCreatesError)"
            Hid-Write-Summary -Event Information -Message "Created HelloID Self service Products. Success: $($productCreatesSuccess). Error: $($productCreatesError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would create [$(($newProducts | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Status -Event Warning -Message "DryRun: Would create [$(($newProducts | Measure-Object).Count)] HelloID Self service Products"
    }

    $productRemovesSuccess = 0
    $productRemovesError = 0
    $productDisablesSuccess = 0
    $productDisablesError = 0
    foreach ($obsoleteProduct in $obsoleteProducts) {
        if ($removeProduct -eq $true) {
            # Remove HelloID Self service Product
            try {
                $splatParams = @{
                    Method = "DELETE"
                    Uri    = "products/$($obsoleteProduct.productId)"
                }
    
                if ($dryRun -eq $false) {
                    $deletedHelloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams                
    
                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Success "Successfully removed HelloID Self service Product [$($obsoleteProduct.Name)]"
                    }
                    $productRemovesSuccess++
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Warning "DryRun: Would remove HelloID Self service Product [$($obsoleteProduct.Name)]"
                    }
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
                $productRemovesError++
                throw "Error removing HelloID Self service Product [$($obsoleteProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
        else {
            # Disable HelloID Self service Product
            try {
                # Create custom productbody object
                $disableHelloIDSelfServiceProductBody = [PSCustomObject]@{}

                # Copy product properties into productbody object (all but the properties that aren't supported when updating a HelloID Self service Product)
                $obsoleteProduct.psobject.properties | ForEach-Object {
                    $disableHelloIDSelfServiceProductBody | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                }

                # Set Visibility to Disabled in product productbody object
                $disableHelloIDSelfServiceProductBody.Visibility = "Disabled"

                $splatParams = @{
                    Method = "POST"
                    Uri    = "products"
                    Body   = ($disableHelloIDSelfServiceProductBody | ConvertTo-Json -Depth 10)
                }

                if ($dryRun -eq $false) {
                    $disableHelloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams

                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Success "Successfully disabled HelloID Self service Product [$($obsoleteProduct.Name)]"
                    }
                    $productDisablesSuccess++
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Hid-Write-Status -Event Warning "DryRun: Would disable HelloID Self service Product [$($obsoleteProduct.Name)]"
                    }
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex

                Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

                $productDisablesError++
                throw "Error disabling HelloID Self service Product [$($obsoleteProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($removeProduct -eq $true) {
        if ($dryRun -eq $false) {
            if ($productRemovesSuccess -ge 1 -or $productRemoveserror -ge 1) {
                Hid-Write-Status -Event Information -Message "Removed HelloID Self service Products. Success: $($productRemovesSuccess). Error: $($productRemoveserror)"
                Hid-Write-Summary -Event Information -Message "Removed HelloID Self service Products. Success: $($productRemovesSuccess). Error: $($productRemoveserror)"
            }
        }
        else {
            Hid-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteProducts | Measure-Object).Count)] HelloID Self service Products"
            Hid-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteProducts | Measure-Object).Count)] HelloID Self service Products"
        }
    }
    else {
        if ($dryRun -eq $false) {
            if ($productDisablesSuccess -ge 1 -or $productDisablesError -ge 1) {
                Hid-Write-Status -Event Information -Message "Disabled HelloID Self service Products. Success: $($productDisablesSuccess). Error: $($productDisablesError)"
                Hid-Write-Summary -Event Information -Message "Disabled HelloID Self service Products. Success: $($productDisablesSuccess). Error: $($productDisablesError)"
            }
        }
        else {
            Hid-Write-Status -Event Warning -Message "DryRun: Would disable [$(($obsoleteProducts | Measure-Object).Count)] HelloID Self service Products"
            Hid-Write-Status -Event Warning -Message "DryRun: Would disable [$(($obsoleteProducts | Measure-Object).Count)] HelloID Self service Products"
        }
    }

    $productUpdatesSuccess = 0
    $productUpdatesError = 0
    foreach ($existingProduct in $existingProducts) {
        try {
            $currentProductInHelloID = $null
            $currentProductInHelloID = $helloIDSelfServiceProductsInScopeGrouped[$existingProduct.Code]
            # Convert collection object to PsCustomObject
            $currentProductInHelloID = $currentProductInHelloID | Select-Object -Property *

            if ($null -ne $currentProductInHelloID -and $overwriteExistingProduct -eq $true) {
                # Update HelloID Self service Product
                try {
                    # Create custom productbody object
                    $updateHelloIDSelfServiceProductBody = [PSCustomObject]@{}

                    # Copy properties of current product in HelloID into productbody object
                    $currentProductInHelloID.PSObject.Properties | ForEach-Object {
                        $updateHelloIDSelfServiceProductBody | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                    }

                    # Calculate changes between current data and provided data
                    $actionProperties = @("onRequest", "onApprove", "onApprove", "onDeny", "onReturn", "onWithdrawn")
                    $splatCompareProperties = @{
                        ReferenceObject  = @($currentProductInHelloID.PSObject.Properties)
                        DifferenceObject = @($existingProduct.PSObject.Properties | Where-Object { $_.Name -notin $actionProperties }) # exclude the action variables, as aren't in the current product object
                    }
                    $changedProperties = $null
                    $changedProperties = (Compare-Object @splatCompareProperties -PassThru)
                    $newProperties = $changedProperties.Where( { $_.SideIndicator -eq "=>" })

                    if (($newProperties | Measure-Object).Count -ge 1) {
                        foreach ($newProperty in $newProperties) {
                            $updateHelloIDSelfServiceProductBody | Add-Member -MemberType NoteProperty -Name $newProperty.Name -Value $newProperty.Value -Force
                        }
                        # Always add the product actions, as they aren't in the current product object and otherwise it will be a product without actions
                        foreach ($actionProperty in $actionProperties) {
                            $updateHelloIDSelfServiceProductBody | Add-Member -MemberType NoteProperty -Name $actionProperty -Value $existingProduct.$actionProperty -Force
                        }

                        $splatParams = @{
                            Method = "POST"
                            Uri    = "products"
                            Body   = ($updateHelloIDSelfServiceProductBody | ConvertTo-Json -Depth 10)
                        }
    
                        if ($dryRun -eq $false) {
                            $updatedHelloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams
    
                            if ($verboseLogging -eq $true) {
                                Hid-Write-Status -Event Success "Successfully updated HelloID Self service Product [$($updateHelloIDSelfServiceProductBody.Name)]"
                            }
                        }
                        else {
                            Hid-Write-Status -Event Warning "DryRun: Would update HelloID Self service Product [$($updateHelloIDSelfServiceProductBody.name)]"
                        }
                    }
                    else {
                        if ($dryRun -eq $false) {
                            if ($verboseLogging -eq $true) {
                                Hid-Write-Status -Event Success "No changes to HelloID Self service Product [$($updateHelloIDSelfServiceProductBody.Name)]"
                            }
                        }
                        else {
                            Hid-Write-Status -Event Warning "DryRun: No changes to HelloID Self service Product [$($updateHelloIDSelfServiceProductBody.Name)]"
                        }
                    }
                }
                catch {
                    $ex = $PSItem
                    $errorMessage = Get-ErrorMessage -ErrorObject $ex
                    
                    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
                    
                    throw "Error updating HelloID Self service Product [$($updateHelloIDSelfServiceProductBody.name)]. Error Message: $($errorMessage.AuditErrorMessage)"
                }

                if ($overwriteAccessGroup -eq $true) {
                    # Get HelloID Access Group
                    $helloIDAccessGroup = $null
                    $helloIDAccessGroup = $helloIDGroupsInScopeGroupedBySourceAndName["$($productAccessGroup)"]

                    # Add HelloID Access Group to HelloID Self service Product
                    if (-not $null -eq $helloIDAccessGroup) {
                        try {
                            $addHelloIDAccessGroupToProductBody = @{
                                GroupGuid = "$($helloIDAccessGroup.groupGuid)"
                            }

                            $splatParams = @{
                                Method = "POST"
                                Uri    = "selfserviceproducts/$($currentProductInHelloID.productId)/groups"
                                Body   = ($addHelloIDAccessGroupToProductBody | ConvertTo-Json -Depth 10)
                            }

                            if ($dryRun -eq $false) {
                                $addHelloIDAccessGroupToProduct = Invoke-HIDRestMethod @splatParams

                                if ($verboseLogging -eq $true) {
                                    Hid-Write-Status -Event Success "Successfully added HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($updatedHelloIDSelfServiceProduct.Name)]"
                                }
                            }
                            else {
                                if ($verboseLogging -eq $true) {
                                    Hid-Write-Status -Event Warning "DryRun: Would add HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($updatedHelloIDSelfServiceProduct.Name)]"
                                }
                            }
                        }
                        catch {
                            $ex = $PSItem
                            $errorMessage = Get-ErrorMessage -ErrorObject $ex
                    
                            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
                    
                            throw "Error adding HelloID Access Group [$($helloIDAccessGroup.Name)] to HelloID Self service Product [$($updatedHelloIDSelfServiceProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
                        }
                    }
                    else {
                        if ($verboseLogging -eq $true) {
                            Hid-Write-Status  -Event Warning -Message "The Specified HelloID Access Group [$($productAccessGroup)] does not exist. We will continue without adding the access Group to HelloID Self service Product [$($updatedHelloIDSelfServiceProduct.Name)]"
                        }
                    }
                }
                
                $productUpdatesSuccess++
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            $productUpdatesError++
            throw "Error updating HelloID Self service Product [$($existingProduct.Name)]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    if ($dryRun -eq $false) {
        if ($productUpdatesSuccess -ge 1 -or $productUpdatesError -ge 1) {
            Hid-Write-Status -Event Information -Message "Updated HelloID Self service Products. Success: $($productUpdatesSuccess). Error: $($productUpdatesError)"
            Hid-Write-Summary -Event Information -Message "Updated HelloID Self service Products. Success: $($productUpdatesSuccess). Error: $($productUpdatesError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would update [$(($existingProducts | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Status -Event Warning -Message "DryRun: Would update [$(($existingProducts | Measure-Object).Count)] HelloID Self service Products"
    }

    if ($dryRun -eq $false) {
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$(($azureADGroupsInScope | Measure-Object).Count)] Azure AD Groups to [$totalProducts] HelloID Self service Products"
}
#endregion