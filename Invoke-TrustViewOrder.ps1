#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RequestBase64,
    [switch]$ValidateOnly
)

function Get-TrustViewConfiguration {
    $configuration = @{
        OrderUrl = [Environment]::GetEnvironmentVariable('TrustViewOrderUrl', 'Machine')
        TemplateOid = [Environment]::GetEnvironmentVariable('TrustViewTemplateOid', 'Machine')
        KeyVaultName = [Environment]::GetEnvironmentVariable('KeyVaultName', 'Machine')
        SecretName = [Environment]::GetEnvironmentVariable('TrustViewSecretName', 'Machine')
        BlobServiceUri = [Environment]::GetEnvironmentVariable('ResultsBlobServiceUri', 'Machine')
        ContainerName = [Environment]::GetEnvironmentVariable('ResultsContainerName', 'Machine')
    }
    foreach ($value in $configuration.Values) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw 'A required VM configuration setting is missing.'
        }
    }

    $orderUri = [uri]$configuration.OrderUrl
    if (-not $orderUri.IsAbsoluteUri -or $orderUri.Scheme -ne 'https' -or
        $orderUri.UserInfo -or $orderUri.Query -or $orderUri.Fragment -or
        $orderUri.AbsolutePath -cne '/api/v1/monitoredobject/monitoredsslcertificate/order') {
        throw 'TrustViewOrderUrl must be the HTTPS certificate order endpoint.'
    }
    if ($configuration.KeyVaultName -notmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$' -or
        $configuration.SecretName -notmatch '^[a-zA-Z0-9-]{1,127}$' -or
        $configuration.TemplateOid -notmatch '^[0-9]+(\.[0-9]+)+$' -or
        $configuration.BlobServiceUri -cnotmatch '^https://[a-z0-9]{3,24}\.blob\.core\.windows\.net$' -or
        $configuration.ContainerName -cnotmatch '^[a-z0-9](?:[a-z0-9]|-(?!-)){1,61}[a-z0-9]$') {
        throw 'A VM configuration setting is invalid.'
    }
    return $configuration
}

function ConvertFrom-TrustViewRequest {
    param([string]$EncodedRequest)

    if ($EncodedRequest.Length -gt 180000) {
        throw 'The request is too large.'
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $request = $utf8.GetString([Convert]::FromBase64String($EncodedRequest)) | ConvertFrom-Json -ErrorAction Stop
    $allowed = @('domains', 'contactEmail', 'deliveryMethod', 'keyspec', 'ip_sans', 'comment', 'correlationId')
    if ($null -eq $request -or $request -isnot [pscustomobject]) {
        throw 'The request must be an object.'
    }
    foreach ($property in $request.PSObject.Properties.Name) {
        if ($allowed -cnotcontains $property) {
            throw 'An unexpected request property was supplied.'
        }
    }
    if ($request.domains -isnot [array] -or $request.domains.Count -lt 1 -or
        $request.contactEmail -isnot [string] -or $request.contactEmail.Length -lt 3 -or
        @('email', 'download') -cnotcontains $request.deliveryMethod -or
        $request.correlationId -isnot [string] -or $request.correlationId -cnotmatch '^[a-zA-Z0-9-]{1,80}$') {
        throw 'A required request property is invalid.'
    }
    foreach ($domain in $request.domains) {
        if ($domain -isnot [string] -or $domain.Length -lt 1) {
            throw 'A domain is invalid.'
        }
    }
    if ($request.PSObject.Properties.Name -contains 'keyspec' -and
        @('RSA:2048', 'RSA:4096') -cnotcontains $request.keyspec) {
        throw 'The key specification is invalid.'
    }
    if ($request.PSObject.Properties.Name -contains 'ip_sans') {
        if ($request.ip_sans -isnot [array]) {
            throw 'IP SANs must be an array.'
        }
        foreach ($ipSan in $request.ip_sans) {
            if ($ipSan -isnot [string]) {
                throw 'An IP SAN is invalid.'
            }
        }
    }
    if ($request.PSObject.Properties.Name -contains 'comment' -and $request.comment -isnot [string]) {
        throw 'The comment is invalid.'
    }
    return $request
}

function Get-TrustViewManagedIdentityToken {
    param([string]$Resource)

    $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' +
        [uri]::EscapeDataString($Resource)
    # IMDS must bypass proxies, including on Windows PowerShell 5.1.
    $metadataRequest = [Net.HttpWebRequest]::Create($uri)
    $metadataRequest.Proxy = $null
    $metadataRequest.AllowAutoRedirect = $false
    $metadataRequest.Timeout = 30000
    $metadataRequest.ReadWriteTimeout = 30000
    $metadataRequest.Headers.Add('Metadata', 'true')
    $response = $metadataRequest.GetResponse()
    try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        try {
            $token = ($reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop).access_token
        }
        finally { $reader.Dispose() }
    }
    finally { $response.Dispose() }
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Managed identity did not return an access token.'
    }
    return $token
}

function Invoke-TrustViewHttp {
    param(
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        $Body
    )

    $arguments = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        UseBasicParsing = $true
        TimeoutSec = 30
        MaximumRedirection = 0
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $arguments.ContentType = 'application/json; charset=utf-8'
        $arguments.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 20 -Compress))
    }
    $response = Invoke-WebRequest @arguments
    $responseBody = $null
    if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
        $responseBody = $response.Content | ConvertFrom-Json -ErrorAction Stop
    }
    return @{ StatusCode = [int]$response.StatusCode; Body = $responseBody }
}

function ConvertTo-TrustViewFailure {
    param(
        [int]$StatusCode,
        [string]$Code,
        [string]$Message,
        [string]$CorrelationId,
        $CertificateId
    )
    return @{
        statusCode = $StatusCode
        body = @{
            error = $Code
            message = $Message
            correlationId = $CorrelationId
            certificateId = $CertificateId
        }
    }
}

function Invoke-TrustViewOrder {
    param($Request, [hashtable]$Configuration)

    $certificateId = $null
    try {
        $vaultToken = Get-TrustViewManagedIdentityToken -Resource 'https://vault.azure.net'
        $secretUri = 'https://' + $Configuration.KeyVaultName + '.vault.azure.net/secrets/' +
            $Configuration.SecretName + '?api-version=7.4'
        $secret = Invoke-TrustViewHttp -Uri $secretUri -Method Get -Headers @{ Authorization = ('Bearer ' + $vaultToken) }
        $apiKey = [string]$secret.Body.value
        if ([string]::IsNullOrWhiteSpace($apiKey)) {
            throw 'The TrustView API key is missing.'
        }
        $headers = @{ Accept = 'application/json'; 'X-TRUSTVIEW-APIKEY' = $apiKey.Trim() }
        $keyspec = 'RSA:2048'
        if ($Request.keyspec) { $keyspec = $Request.keyspec }
        $comment = 'Ordered through certificate API'
        if ($null -ne $Request.comment) { $comment = $Request.comment }
        $order = Invoke-TrustViewHttp -Uri $Configuration.OrderUrl -Method Post -Headers $headers -Body @{
            issuer = 'ADCS'
            type = 'dv'
            domains = @($Request.domains)
            ip_sans = @($Request.ip_sans | Where-Object { $null -ne $_ })
            keyspec = $keyspec
            adcstemplateoid = $Configuration.TemplateOid
            comment = $comment
        }
        if ($order.StatusCode -ne 201 -or [string]::IsNullOrWhiteSpace([string]$order.Body.id)) {
            return ConvertTo-TrustViewFailure -StatusCode 502 -Code 'unexpected_order_response' `
                -Message 'TrustView did not return HTTP 201 with an order ID. Check TrustView before retrying.' `
                -CorrelationId $Request.correlationId
        }
        $certificateId = $order.Body.id
        $certificateBaseUri = $Configuration.OrderUrl.Substring(0, $Configuration.OrderUrl.Length - 6)
        $certificateUri = $certificateBaseUri + '/' + [uri]::EscapeDataString([string]$certificateId)
        $deadline = [DateTime]::UtcNow.AddMinutes(5)
        for ($attempt = 0; $attempt -lt 30 -and [DateTime]::UtcNow -lt $deadline; $attempt++) {
            $certificate = (Invoke-TrustViewHttp -Uri $certificateUri -Method Get -Headers $headers).Body
            $ready = ([string]$certificate.status).ToLowerInvariant() -eq 'active' -and
                $certificate.hasprivatekey -eq $true
            if ($ready) { break }
            if ($attempt -lt 29) { Start-Sleep -Seconds 10 }
        }
        if (-not $ready) {
            return ConvertTo-TrustViewFailure -StatusCode 504 -Code 'certificate_not_ready' `
                -Message 'The certificate did not become active with a private key within five minutes.' `
                -CorrelationId $Request.correlationId -CertificateId $certificateId
        }

        $contactUri = $certificateBaseUri.Replace('/monitoredobject/monitoredsslcertificate', '/contact')
        $contacts = (Invoke-TrustViewHttp -Uri $contactUri -Method Get -Headers $headers).Body.contacts
        $matchedContacts = @($contacts | Where-Object {
            $null -ne $_ -and ([string]$_.emailAddress).Trim().ToLowerInvariant() -eq
                $Request.contactEmail.Trim().ToLowerInvariant()
        })
        if ($matchedContacts.Count -ne 1) {
            $failure = ConvertTo-TrustViewFailure -StatusCode 422 -Code 'contact_match_failed' `
                -Message 'The supplied email must match exactly one TrustView contact.' `
                -CorrelationId $Request.correlationId -CertificateId $certificateId
            $failure.body.matchCount = $matchedContacts.Count
            $failure.body.contactEmail = $Request.contactEmail
            $failure.body.certificateStatus = $certificate.status
            return $failure
        }
        $contact = $matchedContacts[0]
        if ([string]::IsNullOrWhiteSpace([string]$contact.id)) {
            throw 'The contact has no ID.'
        }
        $null = Invoke-TrustViewHttp -Uri ($certificateUri + '/externalcontact/' +
            [uri]::EscapeDataString([string]$contact.id)) -Method Put -Headers $headers

        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $bytes = New-Object byte[] 32
            $random.GetBytes($bytes)
            $password = 'Tv9!' + [Convert]::ToBase64String($bytes) + '#aZ'
        }
        finally { $random.Dispose() }
        $locale = 'en_US'
        if ($null -ne $contact.locale) { $locale = $contact.locale }
        $checkoutBody = @{
            method = 'download'
            format = 'pfx'
            password = $password
            comment = 'Certificate and private-key checkout through Azure VM Run Command'
            exportprivatekey = $true
            locale = 'en_US'
        }
        if ($Request.deliveryMethod -ceq 'email') {
            $checkoutBody.method = 'mail-mail'
            $checkoutBody.comment = 'Certificate and password delivery through Azure VM Run Command'
            $checkoutBody.locale = $locale
            $checkoutBody.passwordrecipient = $contact.emailAddress
            $checkoutBody.checkoutinfo = $contact.emailAddress
            $checkoutBody.fullchainkeyrecipient = $contact.emailAddress
        }
        $checkout = Invoke-TrustViewHttp -Uri ($certificateUri + '/checkout') -Method Post `
            -Headers $headers -Body $checkoutBody
        if ($checkout.StatusCode -ne 200 -or ($Request.deliveryMethod -ceq 'download' -and
            [string]::IsNullOrWhiteSpace([string]$checkout.Body.fullchainkey_pfx))) {
            return ConvertTo-TrustViewFailure -StatusCode 502 -Code 'certificate_delivery_failed' `
                -Message 'TrustView did not return a successful checkout result.' `
                -CorrelationId $Request.correlationId -CertificateId $certificateId
        }

        $certificateDetails = @{ id = $certificate.id }
        $fields = @{
            name = 'name'; status = 'status'; subject = 'subject'; issuer = 'issuer'
            serialNumber = 'serial'; thumbprint = 'thumbprint'; sha256Fingerprint = 'certificatehashsha256'
            signatureAlgorithm = 'signaturealgorithms'; rsaKeySize = 'rsakeysize'; hasPrivateKey = 'hasprivatekey'
            issuedTimestamp = 'issuedtimestamp'; expiry = 'expiry'; dateCreated = 'datecreated'
            domainsSecured = 'domainssecuredbycertificate'; certificateTemplate = 'certificatetemplatenamev2'
            certificateAuthority = 'certificationauthority'; certificateIssuerType = 'certificateissuertype'
            revocationStatus = 'revocationstatus'; trustViewOrderId = 'orderid'; origin = 'origin'; comment = 'comment'
        }
        foreach ($field in $fields.Keys) { $certificateDetails[$field] = $certificate.($fields[$field]) }
        $body = @{
            id = $certificateId
            format = 'pfx'
            keyLocation = 'trustview'
            correlationId = $Request.correlationId
            contactDetails = @{
                id = $contact.id; fullName = $contact.fullname; emailAddress = $contact.emailAddress
                phone = $contact.phone; company = $contact.company; locale = $contact.locale
                associationStatus = 'added'
            }
            certificateDetails = $certificateDetails
            status = 'order_created_contact_added_and_downloaded'
            delivery = @{ method = 'download'; requested = $true }
        }
        if ($Request.deliveryMethod -ceq 'email') {
            $body.status = 'order_created_contact_added_and_delivery_requested'
            $body.delivery = @{
                method = 'mail-mail'; certificateDelivery = 'email'; passwordDelivery = 'separate_email'
                certificateRecipient = $contact.emailAddress; passwordRecipient = $contact.emailAddress
                locale = $locale; requested = $true
            }
        }
        else {
            $body.pfxBase64 = $checkout.Body.fullchainkey_pfx
            $body.pfxPassword = $password
        }
        return @{ statusCode = 200; body = $body }
    }
    catch {
        # Never copy upstream errors into Run Command output or the caller's response.
        return ConvertTo-TrustViewFailure -StatusCode 502 -Code 'certificate_workflow_failed' `
            -Message 'The VM worker failed. Check TrustView before retrying because an order might have been created.' `
            -CorrelationId $Request.correlationId -CertificateId $certificateId
    }
}

function Send-TrustViewResult {
    param($Result, [string]$CorrelationId, [hashtable]$Configuration, [string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        $Token = Get-TrustViewManagedIdentityToken -Resource 'https://storage.azure.com/'
    }
    $uri = $Configuration.BlobServiceUri + '/' + $Configuration.ContainerName + '/' + $CorrelationId + '.json'
    $headers = @{
        Authorization = ('Bearer ' + $Token)
        'x-ms-version' = '2023-11-03'
        'x-ms-date' = [DateTime]::UtcNow.ToString('R')
        'x-ms-blob-type' = 'BlockBlob'
    }
    $content = [Text.Encoding]::UTF8.GetBytes(($Result | ConvertTo-Json -Depth 30 -Compress))
    $null = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Put -Headers $headers -Body $content `
        -ContentType 'application/json; charset=utf-8' -TimeoutSec 30 -MaximumRedirection 0 -ErrorAction Stop
}

function Invoke-TrustViewWorker {
    param([string]$EncodedRequest, [switch]$ValidateOnly)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
    $DebugPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
    $stage = 'configuration_validation'
    try {
        $configuration = Get-TrustViewConfiguration
        $stage = 'request_validation'
        $request = ConvertFrom-TrustViewRequest -EncodedRequest $EncodedRequest
        if ($ValidateOnly) {
            Write-Output 'Configuration and request validation passed; no network calls or orders were made.'
            return
        }
        $stage = 'order_processing'
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $stage = 'storage_identity'
        $storageToken = Get-TrustViewManagedIdentityToken -Resource 'https://storage.azure.com/'
        $stage = 'result_upload'
        Send-TrustViewResult -Result $result -CorrelationId $request.correlationId `
            -Configuration $configuration -Token $storageToken
        Write-Output 'TrustView processing finished; the result was stored for the workflow.'
    }
    catch {
        $httpStatus = ''
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($null -ne $exception.PSObject.Properties['Response'] -and
                $null -ne $exception.Response -and
                $null -ne $exception.Response.PSObject.Properties['StatusCode']) {
                $statusCode = 0
                $statusValue = $exception.Response.StatusCode
                if ($statusValue -is [enum]) { $statusValue = $statusValue.value__ }
                if ([int]::TryParse([string]$statusValue, [ref]$statusCode) -and
                    $statusCode -ge 100 -and $statusCode -le 599) {
                    $httpStatus = " (HTTP $statusCode)"
                }
                break
            }
            $exception = $exception.InnerException
        }
        # Only fixed stage names and numeric HTTP status codes may leave the worker.
        throw "TrustView worker failed during $stage$httpStatus. Check configuration and permissions; check TrustView before retrying because an order might have been created."
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-TrustViewWorker -EncodedRequest $RequestBase64 -ValidateOnly:$ValidateOnly
}
