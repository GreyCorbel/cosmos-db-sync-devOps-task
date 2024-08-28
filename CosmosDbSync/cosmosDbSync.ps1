# function declaration
function Initialize-AadAuthenticationFactory 
{
    [CmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [string]$servicePrincipalKey,
        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [string]$cert,
        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [Parameter(ParameterSetName = 'WorkloadIdentityFederation')]
        [string]$servicePrincipalId,
        [Parameter(ParameterSetName = 'WorkloadIdentityFederation')]
        [string]$Assertion,
        [Parameter(ParameterSetName = 'ManagedServiceIdentity')]
        [string]$ServiceConnection,
        [Parameter()]
        [string]$tenantId
    )
    process
    {
        #create authnetication factory and store it into the script variable
        switch($PSCmdlet.ParameterSetName)
        {
            'ServicePrincipal' {
                if ($cert) {
                    $script:aadAuthenticationFactory = New-AadAuthenticationFactory `
                    -TenantId $tenantId `
                    -ClientId $servicePrincipalId `
                    -X509Certificate $cert
                }
                else {
                    $script:aadAuthenticationFactory = New-AadAuthenticationFactory `
                    -TenantId $tenantId `
                    -ClientId $servicePrincipalId `
                    -ClientSecret $servicePrincipalKey
                }
            }
            'ManagedServiceIdentity' {
                $msiClientId = $serviceConnection.Data.msiClientId
                if ($msiClientId) {
                    $script:aadAuthenticationFactory = New-AadAuthenticationFactory `
                    -ClientId $msiClientId `
                    -UseManagedIdentity
                }
                else {
                    $script:aadAuthenticationFactory = New-AadAuthenticationFactory `
                    -UseManagedIdentity
                }
            }
            'WorkloadIdentityFederation' {
                $script:aadAuthenticationFactory = New-AadAuthenticationFactory `
                    -TenantId $tenantId `
                    -ClientId $servicePrincipalId `
                    -Assertion $assertion
            }
        }
    }
}

function Get-AutoAccessToken
{
    param
    (
        [string]$ResourceUri = "https://management.azure.com/.default",
        [switch]$AsHashTable
    )

    process
    {
        if ($null -eq $script:aadAuthenticationFactory)
		{
			throw ('Call Initialize-AadAuthenticationFactory first')
		}
		Get-AadToken -Factory $script:aadAuthenticationFactory -Scopes $ResourceUri -AsHashTable:$AsHashTable
    }
}

Function Update-AzStoredProcedure {
    param (
        [Parameter(Mandatory = $true)]
        [string]$subscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$resourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$accountName,
        [Parameter(Mandatory = $true)]
        [string]$databaseName,
        [Parameter(Mandatory = $true)]
        [string]$containerName,
        [Parameter(Mandatory = $true)]
        [string]$storedProcedureName,
        [Parameter(Mandatory = $true)]
        [string]$storedProcedureBody
    )
    begin {
        $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.DocumentDB/databaseAccounts/$accountName/sqlDatabases/$databaseName/containers/$containerName/storedProcedures/$storedProcedureName?api-version=2024-05-15"
        # develop header and get access token
        $header = @{
            "Content-Type" = "application/json";
            "Authorization" = Get-AutoAccessToken;
        }
        # format req body
        $body = @{
            properties = @{
                resource = @{
                    id   = $storedProcedureName
                    body = $storedProcedureBody
                }
                options = @{}
            }
        } | ConvertTo-Json -Depth 3
    }
    process {
        $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $header -Body $body
        return $response
    }
}

Function Sync-StoredProcedures 
{
    # Process each stored procedure file
    Write-Host "getting difinition files"
    $definitions = @(Get-DefinitionFiles -FileType 'StoredProcedures')
    Write-Host "Iterationg through definition files"
    foreach ($item in $definitions) {
        try {
            Write-Host "Getting file content"
            $contentFile = Get-FileToProcess -FileType 'StoredProcedures' -FileName $item.definition
            $content = Get-Content $contentFile -Raw
            Write-Host "Show me file $($item.Name) content: $content"
            Write-Host "Updating stored procedure: $storedProcedureName"
            $response = Update-AzStoredProcedure -subscriptionId $subscription -resourceGroupName $resourceGroup -accountName $accountName -databaseName $databaseName -containerName $containerName -storedProcedureName $storedProcedureName -storedProcedureBody $content
            Write-Host "Response for $storedProcedureName = $response"
        }
        catch {
            $_
        }
    }
}

Function Sync-Documents
{
    Write-Host "getting difinition files"
    $definitions = @(Get-DefinitionFiles -FileType 'Workflows')
    Write-Host "Connecting to: $accountName using existing addFactory"
    $ctx = Connect-Cosmos -AccountName $accountName -Database $databaseName -Factory $script:aadAuthenticationFactory
    Write-Host "Show context: $ctx" # pak smazat!
    Write-Host "Iterationg through definition files"
    foreach ($item in $definitions) {
        try {
            Write-Host "Getting file content"
            $contentFile = Get-FileToProcess -FileType 'Workflows' -FileName $item.definition
            $content = Get-Content $contentFile -Raw
            Write-Host "Show me file $($item.Name) content: $content"

            Write-Host "Inserting/Updating document..."
            New-CosmosDocument -Context $ctx -Document $content -PartitionKey $content.partitionkey -Collection "requests" -IsUpsert #v source i definition chybí container -> hardcoded
        }
        catch {
            Write-Warning $_.Exception
        }
    }
}

#read pipeline variables
Write-Host "Reading task parameters"

$projectDir = Get-VstsInput -Name 'projectDir' -Require
$environmentName = Get-VstsInput -Name 'environmentName' -Require
$subscription = Get-VstsInput -Name 'subscription' -Require
$azureSubscription = Get-VstsInput -Name 'azureSubscription' -Require
$resourceGroup = Get-VstsInput -Name 'resourceGroup' -Require
$accountName = Get-VstsInput -Name 'accountName' -Require
$containerName = Get-VstsInput -Name 'containerName' -Require
$databaseName = Get-VstsInput -Name 'databaseName' -Require
$scope = Get-VstsInput -Name 'scope' -Require

# validuji vstupy, pak je možný smazat
Write-Host "Input validation..."
Write-Host "---------------------------------------------------------------"
Write-Host "reading projectDir: " $projectDir
Write-Host "reading environmentName: " $environmentName
Write-Host "reading subscription: " $subscription
Write-Host "reading azureSubscription: " $azureSubscription
Write-Host "reading resourceGroup: " $resourceGroup
Write-Host "reading accountName: " $accountName
Write-Host "reading containerName: " $containerName
Write-Host "reading databaseName: " $databaseName
Write-Host "reading scope: " $scope
Write-Host "---------------------------------------------------------------"

 #>#load VstsTaskSdk module
Write-Host "Installing dependencies..."
if ($null -eq (Get-Module -Name VstsTaskSdk -ListAvailable)) {
    Write-Host "VstsTaskSdk module not found, installing..."
    Install-Module -Name VstsTaskSdk -Force -Scope CurrentUser -AllowClobber
}
Write-Host "Installation succeeded!"
Write-Host "---------------------------------------------------------------"

#load AadAuthentiacationFactory
if ($null -eq (Get-Module -Name AadAuthenticationFactory -ListAvailable)) {
    Write-Host "AadAuthenticationFactory module not found, installing..."
    Install-Module -Name AadAuthenticationFactory -Force -Scope CurrentUser
}
Write-Host "Installation succeeded!"
Write-Host "---------------------------------------------------------------"

#load cosmosLite
if ($null -eq (Get-Module -Name CosmosLite -ListAvailable)) {
    Write-Host "CosmosLite module not found, installing..."
    Install-Module -Name CosmosLite -Force -Scope CurrentUser
}
Write-Host "Installation succeeded!"
Write-Host "---------------------------------------------------------------"

# import intermal modules
Write-Host "Importing intermal modules..."
$modulePath = [System.IO.Path]::Combine($PSScriptRoot, 'Module', 'AutoRuntime')
Write-Host "module path: $modulePath"
Import-Module $modulePath -Force -WarningAction SilentlyContinue
Write-Host "Import succeeded!"

# -------------------------------------------------------------------------
# do process...
Write-Host "Starting process..."

#initialize runtime according to environment environment
Write-Host "Getting environment setup and initializing..."
Init-Environment -ProjectDir $ProjectDir -Environment $environmentName

# retrieve service connection object
$serviceConnection = Get-VstsEndpoint -Name $azureSubscription -Require

# define type od service connection and get AT
switch ($serviceConnection.auth.scheme) {
    'ServicePrincipal' { 
        # get service connection object properties
        $servicePrincipalId = $serviceConnection.auth.parameters.serviceprincipalid
        $servicePrincipalkey = $serviceConnection.auth.parameters.serviceprincipalkey
        $tenantId = $serviceConnection.auth.parameters.tenantid

        # SPNcertificate
        if ($serviceConnection.auth.parameters.authenticationType -eq 'SPNCertificate') {
            Write-Host "ServicePrincipal with Certificate auth"

            $certData = $serviceConnection.Auth.parameters.servicePrincipalCertificate
            $cert= [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($certData,$certData)

            Initialize-AadAuthenticationFactory `
            -servicePrincipalId $servicePrincipalId `
            -servicePrincipalKey $servicePrincipalkey `
            -tenantId $tenantId `
            -cert $cert
        }
        #Service Principal
        else {
            Write-Host "ServicePrincipal with ClientSecret auth"

            Initialize-AadAuthenticationFactory `
            -servicePrincipalId $servicePrincipalId `
            -servicePrincipalKey $servicePrincipalkey `
            -tenantId $tenantId
        }
        break;
     }

     'ManagedServiceIdentity' {
        Write-Host "ManagedIdentitx auth"

        Initialize-AadAuthenticationFactory `
            -serviceConnection $serviceConnection
        break;
     }

     'WorkloadIdentityFederation' {
        Write-Host "Workload identity auth"

        # get service connection properties
        $planId = Get-VstsTaskVariable -Name 'System.PlanId' -Require
        $jobId = Get-VstsTaskVariable -Name 'System.JobId' -Require
        $hub = Get-VstsTaskVariable -Name 'System.HostType' -Require
        $projectId = Get-VstsTaskVariable -Name 'System.TeamProjectId' -Require
        $uri = Get-VstsTaskVariable -Name 'System.CollectionUri' -Require
        $serviceConnectionId = $azureSubscription

        $vstsEndpoint = Get-VstsEndpoint -Name SystemVssConnection -Require
        $vstsAccessToken = $vstsEndpoint.auth.parameters.AccessToken
        $servicePrincipalId = $vstsEndpoint.auth.parameters.serviceprincipalid
        $tenantId = $vstsEndpoint.auth.parameters.tenantid
        
        $url = "$uri/$projectId/_apis/distributedtask/hubs/$hub/plans/$planId/jobs/$jobId/oidctoken?serviceConnectionId=$serviceConnectionId`&api-version=7.2-preview.1"

        $username = "username"
        $password = $vstsAccessToken
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))

        $response = Invoke-RestMethod -Uri $url -Method Post -Headers @{ "Authorization" = ("Basic {0}" -f $base64AuthInfo) } -ContentType "application/json"

        $oidcToken = $response.oidcToken
        $assertion = $oidcToken

        Initialize-AadAuthenticationFactory `
            -servicePrincipalId $servicePrincipalId `
            -assertion $assertion `
            -tenantId $tenantId
        break;
     }
}

Write-Host "Do process..."
Write-Host "---------------------------------------------------------------"

# jen kontrola formy AT - pak smazat!
$accessToken = Get-AutoAccessToken
Write-Host "token: " $accessToken
$accessTokenAsHashTable = Get-AutoAccessToken -AsHashTable
Write-Host "accessTokenAsHashTable: " $accessTokenAsHashTable

Write-Host "Checking scope parameter."
Write-Host "---------------------------------------------------------------"

switch ($scope)
{
    'full' 
    {
        Write-Host "full sync starting..."
        Sync-StoredProcedures
        Sync-Documents
        break;
    }
    'procedures'
    {
        Write-Host "storedProcedures sync starting..."
        Sync-StoredProcedures
        break;
    }
    'documents'
    {
        Write-Host "documents sync starting..."
        Sync-Documents
        break;
    }
}

