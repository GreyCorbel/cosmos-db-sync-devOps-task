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

Write-Host "Input validation..."
Write-Host "reading projectDir: " + $projectDir
Write-Host "reading subscription: " + $subscription
Write-Host "reading azureSubscription: " + $azureSubscription
Write-Host "reading resourceGroup: " + $resourceGroup
Write-Host "reading accountName: " + $accountName
Write-Host "reading containerName: " + $containerName
Write-Host "reading databaseName: " + $databaseName
Write-Host "reading scope: " + $scope

 #>#load VstsTaskSdk module
Write-Host "Installing dependencies..."
if ($null -eq (Get-Module -Name VstsTaskSdk -ListAvailable)) {
    Write-Host "VstsTaskSdk module not found, installing..."
    Install-Module -Name VstsTaskSdk -Force -Scope CurrentUser -AllowClobber
}
Write-Host "Installation succeeded!"

#load AadAuthentiacationFactory
if ($null -eq (Get-Module -Name AadAuthenticationFactory -ListAvailable)) {
    Write-Host "AadAuthenticationFactory module not found, installing..."
    Install-Module -Name AadAuthenticationFactory -Force -Scope CurrentUser
}
Write-Host "Installation succeeded!"

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

Function Remove-AutoPowershell7Module
{
    param
    (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter()]
        [string]$AutomationAccountResourceId = $script:AutomationAccountResourceId
    )

    begin
    {
        $headers = Get-AutoAccessToken -AsHashTable
        $uri = "https://management.azure.com$AutomationAccountResourceId/Powershell72Modules/$Name`?api-version=2023-11-01"
    }
    process
    {
        write-verbose "Sending DELETE to $Uri"
        Invoke-RestMethod -Method Delete `
        -Uri $Uri `
        -Headers $headers `
        -ErrorAction Stop
    }
}

Write-Host "Starting process..."
# retrieve service connection object
$serviceConnection = Get-VstsEndpoint -Name $azureSubscription -Require

# define type od service connection
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

    #  'WorkloadIdentityFederation' {
    #     Write-Host "Workload identity auth"

    #     # get service connection properties
    #     $planId = Get-VstsTaskVariable -Name 'System.PlanId' -Require
    #     $jobId = Get-VstsTaskVariable -Name 'System.JobId' -Require
    #     $hub = Get-VstsTaskVariable -Name 'System.HostType' -Require
    #     $projectId = Get-VstsTaskVariable -Name 'System.TeamProjectId' -Require
    #     $uri = Get-VstsTaskVariable -Name 'System.CollectionUri' -Require
    #     $serviceConnectionId = $azureSubscription

    #     $vstsEndpoint = Get-VstsEndpoint -Name SystemVssConnection -Require
    #     $vstsAccessToken = $vstsEndpoint.auth.parameters.AccessToken
    #     $servicePrincipalId = $vstsEndpoint.auth.parameters.serviceprincipalid
    #     $tenantId = $vstsEndpoint.auth.parameters.tenantid
        
    #     $url = "$uri/$projectId/_apis/distributedtask/hubs/$hub/plans/$planId/jobs/$jobId/oidctoken?serviceConnectionId=$serviceConnectionId`&api-version=7.2-preview.1"

    #     $username = "username"
    #     $password = $vstsAccessToken
    #     $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))

    #     $response = Invoke-RestMethod -Uri $url -Method Post -Headers @{ "Authorization" = ("Basic {0}" -f $base64AuthInfo) } -ContentType "application/json"

    #     $oidcToken = $response.oidcToken
    #     $assertion = $oidcToken

    #     Initialize-AadAuthenticationFactory `
    #         -servicePrincipalId $servicePrincipalId `
    #         -assertion $assertion `
    #         -tenantId $tenantId
    #     break;
    #  }
}

Write-Host "Do process..."
$headers = Get-AutoAccessToken -AsHashTable
Write-Host "Header payload: "
$headers

