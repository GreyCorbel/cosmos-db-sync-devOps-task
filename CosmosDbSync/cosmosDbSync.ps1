# function declaration
$CosmosDBEndPoint = "https://$cosmosDBAccountName.documents.azure.com"

function Get-SignedKey {
    param (
        [string] $Verb,
        [string] $ResourceType,
        [string] $ResourceLink,
        [string] $Key,
        [string] $DateTime
    )
    # Add Web Object
    Add-Type -AssemblyName System.Web

    #Define variables
    $keyType = 'master'
    $tokenVersion = '1.0' 
    
    #Build Auth Token
    $hmacSha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacSha256.Key = [System.Convert]::FromBase64String($key) 
    $payLoad = "$($verb.ToLowerInvariant())`n$($resourceType.ToLowerInvariant())`n$resourceLink`n$($dateTime.ToLowerInvariant())`n`n"
    $hashPayLoad = $hmacSha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payLoad))
    $signature = [System.Convert]::ToBase64String($hashPayLoad) 
    $authHeader = [System.Web.HttpUtility]::UrlEncode("type=$keyType&ver=$tokenVersion&sig=$signature")

    return $authHeader
}

function Set-CosmosDBDocument {
    param (
        [string] $CosmosDBEndPoint,
        [string] $Verb,
        [string] $SignedKey,
        [string] $DateTime,
        [string] $Partitionkey,
        [string] $Payload,
        [string] $DocsId,
        [string] $DatabaseId,
        [string] $CollectionId

    )
    $resourceLink = "dbs/$databaseId/colls/$collectionId/docs"
    $queryUri = "$CosmosDBEndPoint/$ResourceLink"
    $queryUri

    # Build Header
    $header = @{
        "Accept" = "application/json";
        "Content-Type" = "application/json";
        "authorization" = $SignedKey;
        "x-ms-version" = "2018-12-31";
        "x-ms-date" = $dateTime;
        "x-ms-documentdb-partitionkey" = $partitionkey;
        "x-ms-documentdb-is-upsert" = $true;
    }

    # Paload
    $body = $Payload

    $result = Invoke-RestMethod -Method $Verb -Uri $queryUri -Headers $header -Body $body
    return $result
}

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
    $procedureFiles = Get-ChildItem -Path "$projectDir/Cosmos/Definitions/StoredProcedures" -Filter *.nosql # nebo .js -> domluvit s Jiřím
    foreach ($file in $procedureFiles) {
        $storedProcedureName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $storedProcedureBody = Get-Content -Path $file.FullName -Raw
    
        Write-Host "Updating stored procedure: $storedProcedureName"
        try 
        {
            $response = Update-AzStoredProcedure -subscriptionId $subscription -resourceGroupName $resourceGroup -accountName $accountName -databaseName $databaseName -containerName $containerName -storedProcedureName $storedProcedureName -storedProcedureBody $storedProcedureBody
            Write-Host "Response for $storedProcedureName = $response"
        }
        catch {
            $_
        }
    }
}

Function Sync-Items
{
    $items = Get-ChildItem -Path "$projectDir/Cosmos/Definitions/Items" -Filter *.nosql # nebo .js -> domluvit s Jiřím
    foreach ($file in $items) {
        $itemName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $itemBody = Get-Content -Path $file.FullName -Raw
    
        Write-Host "inserting item: $itemName"
        try 
        {
            # Get Primary master key
            Write-Host "Geting primary key..."
            #load AadAuthentiacationFactory
            if ($null -eq (Get-Module -Name AadAuthenticationFactory -ListAvailable)) {
                Write-Host "Az.CosmosDB module not found, installing..."
                Install-Module -Name Az.CosmosDB -Force -Scope CurrentUser
            }

            $getkeys = Get-AzCosmosDBAccountKey -ResourceGroupName $resourceGroupName -Name $cosmosDBAccountName -Type "Keys"
            $getPrimarykey = $getkeys.PrimaryMasterKey
            $key = $getPrimarykey
            Write-Host "PrimaryKey retrieved successfully"
            
            if([string]::IsNullOrEmpty($itemBody))
            {
                Write-Warning "Missing implementation file $($definition.definition)"
                continue
            }
            write-host "Having definition file: $file"
            $payload = Get-Content -Path $file -Raw
        
            $workflow = $payload | ConvertFrom-Json
            $docsId = $workflow.id
            $partitionkeyRaw = $workflow.partitionKey
            $partitionkey = "[""$partitionkeyRaw""]"
        
            # define cosmos DB variables
            $verb = "post"
            $resourceType = "docs"
            $resourceLink = "dbs/$databaseName/colls/$containerName"
            $dateTime = [DateTime]::UtcNow.ToString("r")
        
            # get-signedkey
            try {
                $signedKey = Get-SignedKey -Verb $verb -ResourceType $resourceType -ResourceLink $resourceLink -Key $key -DateTime $dateTime
                Write-Host ("Workflow signed key for " + $docsId + " was generated successfully!")
            }
            catch {
                $_
            }
        
            #Set-Document - call CosmosDB API
            try {
                $response = Set-CosmosDBDocument -CosmosDBEndPoint $cosmosDBEndPoint -Verb $verb -SignedKey $signedKey -DateTime $dateTime -Partitionkey $partitionkey -Payload $payload -DocsId $docsId -DatabaseId $databaseName -CollectionId $containerName
                $response
                Write-Host ("Workflow " + $docsId + " was updated successfully!")
            }
            catch {
                $_
            }
        }
        catch {
            _$
        }
    }
}

#read pipeline variables
Write-Host "Reading task parameters"

$projectDir = Get-VstsInput -Name 'projectDir' -Require
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


# -------------------------------------------------------------------------
# do process...
Write-Host "Starting process..."
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
        Sync-Items
        break;
    }
    'procedures'
    {
        Write-Host "procedures sync starting..."
        Sync-StoredProcedures
        break;
    }
    'items'
    {
        Write-Host "items sync starting..."
        Sync-Items
        break;
    }
}

