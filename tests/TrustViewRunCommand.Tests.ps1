BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $root 'Invoke-TrustViewOrder.ps1') -RequestBase64 'unused-when-dot-sourced'
    $workflow = Get-Content (Join-Path $root 'Trustview_Order_Checkout_RunCommand.json') -Raw | ConvertFrom-Json
    $template = Get-Content (Join-Path $root 'Trustview_Order_Checkout_RunCommand.arm.json') -Raw | ConvertFrom-Json
    $original = Get-Content (Join-Path $root 'Trustview_Order_Checkout.json') -Raw | ConvertFrom-Json
    $configuration = @{
        OrderUrl = 'https://trustview.internal/api/v1/monitoredobject/monitoredsslcertificate/order'
        TemplateOid = '1.2.3.4'
        KeyVaultName = 'example-vault'
        SecretName = 'trustview-api-key'
        BlobServiceUri = 'https://exampleresults.blob.core.windows.net'
        ContainerName = 'trustview-results'
    }
}

Describe 'Request validation' {
    BeforeEach {
        $request = @{
            domains = @('example.internal')
            contactEmail = 'owner@example.internal'
            deliveryMethod = 'email'
            correlationId = 'test-run-123'
        }
    }

    It 'accepts the existing request shape and defaults optional fields' {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json)))
        $decoded = ConvertFrom-TrustViewRequest -EncodedRequest $encoded
        $decoded.domains.Count | Should -Be 1
        $decoded.deliveryMethod | Should -Be 'email'
    }

    It 'rejects malformed base64' {
        { ConvertFrom-TrustViewRequest -EncodedRequest '!not-base64!' } | Should -Throw
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a caller-selected VM'; Property = 'vmName'; Value = 'another-vm' }
        @{ Name = 'an empty domains list'; Property = 'domains'; Value = @() }
        @{ Name = 'a scalar domain'; Property = 'domains'; Value = 'example.internal' }
        @{ Name = 'an invalid delivery method'; Property = 'deliveryMethod'; Value = 'Email' }
        @{ Name = 'an unsupported key size'; Property = 'keyspec'; Value = 'RSA:1024' }
        @{ Name = 'a null comment'; Property = 'comment'; Value = $null }
        @{ Name = 'a scalar SAN'; Property = 'ip_sans'; Value = '127.0.0.1' }
        @{ Name = 'a blob path traversal'; Property = 'correlationId'; Value = '../another-run' }
    ) {
        $request[$Property] = $Value
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json)))
        { ConvertFrom-TrustViewRequest -EncodedRequest $encoded } | Should -Throw
    }

    It 'treats script metacharacters as data' {
        $request.comment = "'; Write-Output 'not-executed'; #"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json)))
        (ConvertFrom-TrustViewRequest -EncodedRequest $encoded).comment | Should -Be $request.comment
    }
}

Describe 'Private TrustView processing' {
    BeforeEach {
        $request = [pscustomobject]@{
            domains = @('example.internal')
            contactEmail = ' OWNER@example.internal '
            deliveryMethod = 'email'
            correlationId = 'test-run-123'
        }
        Mock Get-TrustViewManagedIdentityToken { 'not-a-real-token' }
        Mock Start-Sleep {}
        Mock Invoke-TrustViewHttp {
            param($Uri, $Method, $Headers, $Body)
            if ($Uri -like 'https://*.vault.azure.net/*') {
                return @{ StatusCode = 200; Body = @{ value = ' not-a-real-key ' } }
            }
            if ($Uri -eq $configuration.OrderUrl -and $Method -eq 'Post') {
                return @{ StatusCode = 201; Body = @{ id = 42 } }
            }
            if ($Uri -like '*/externalcontact/*' -and $Method -eq 'Put') {
                return @{ StatusCode = 204; Body = $null }
            }
            if ($Uri -like '*/checkout' -and $Method -eq 'Post') {
                return @{ StatusCode = 200; Body = @{ fullchainkey_pfx = ('A' * 20000) } }
            }
            if ($Uri -like '*/api/v1/contact') {
                return @{
                    StatusCode = 200
                    Body = @{ contacts = @(@{ id = 7; emailAddress = 'owner@example.internal'; fullname = 'Owner' }) }
                }
            }
            if ($Uri -like '*/monitoredsslcertificate/42') {
                return @{ StatusCode = 200; Body = @{ id = 42; status = 'ACTIVE'; hasprivatekey = $true } }
            }
            throw "Unexpected HTTP call: $Method $Uri"
        }
    }

    It 'orders, associates the unique contact, and requests separate email delivery' {
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.statusCode | Should -Be 200
        $result.body.status | Should -Be 'order_created_contact_added_and_delivery_requested'
        $result.body.contactDetails.associationStatus | Should -Be 'added'
        $result.body.delivery.passwordDelivery | Should -Be 'separate_email'
        $result.body.ContainsKey('pfxPassword') | Should -BeFalse
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Get' -and $Uri -like 'https://*.vault.azure.net/*' -and
            $Headers.Authorization -eq ('Bearer ' + 'not-a-real-token')
        }
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Post' -and $Uri -eq $configuration.OrderUrl -and
            $Body.keyspec -eq 'RSA:2048' -and $Body.issuer -eq 'ADCS' -and
            $Body.adcstemplateoid -eq '1.2.3.4' -and $Body.ip_sans.Count -eq 0
        }
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Put' -and $Uri -like '*/42/externalcontact/7'
        }
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Post' -and $Uri -like '*/checkout' -and $Body.method -eq 'mail-mail' -and
            $Body.locale -eq 'en_US' -and $Body.passwordrecipient -eq 'owner@example.internal'
        }
    }

    It 'preserves supplied ordering options' {
        $request | Add-Member keyspec 'RSA:4096'
        $request | Add-Member comment ''
        $request | Add-Member ip_sans @('10.0.0.5')
        $null = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter {
            $Uri -eq $configuration.OrderUrl -and $Body.keyspec -eq 'RSA:4096' -and
            $Body.comment -ceq '' -and $Body.ip_sans[0] -eq '10.0.0.5'
        }
    }

    It 'returns a full PFX larger than the Run Command output limit only as structured data' {
        $request.deliveryMethod = 'download'
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.statusCode | Should -Be 200
        $result.body.pfxBase64.Length | Should -Be 20000
        $result.body.pfxPassword.Length | Should -BeGreaterThan 40
        $result.body.status | Should -Be 'order_created_contact_added_and_downloaded'
    }

    It 'does not checkout when <Count> contacts match' -ForEach @(@{ Count = 0 }, @{ Count = 2 }) {
        Mock Invoke-TrustViewHttp {
            $contacts = @()
            for ($i = 0; $i -lt $Count; $i++) {
                $contacts += @{ id = $i; emailAddress = 'owner@example.internal' }
            }
            return @{ StatusCode = 200; Body = @{ contacts = $contacts } }
        } -ParameterFilter { $Uri -like '*/api/v1/contact' }
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.statusCode | Should -Be 422
        $result.body.matchCount | Should -Be $Count
        Should -Invoke Invoke-TrustViewHttp -Times 0 -ParameterFilter { $Uri -like '*/checkout' }
    }

    It 'waits for both active status and the private key' {
        $script:statusChecks = 0
        Mock Invoke-TrustViewHttp {
            $script:statusChecks++
            return @{
                StatusCode = 200
                Body = @{ id = 42; status = 'active'; hasprivatekey = ($script:statusChecks -gt 1) }
            }
        } -ParameterFilter { $Uri -like '*/monitoredsslcertificate/42' }
        (Invoke-TrustViewOrder -Request $request -Configuration $configuration).statusCode | Should -Be 200
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'does not associate a contact or checkout after readiness exhaustion' {
        Mock Invoke-TrustViewHttp {
            return @{ StatusCode = 200; Body = @{ id = 42; status = 'pending'; hasprivatekey = $false } }
        } -ParameterFilter { $Uri -like '*/monitoredsslcertificate/42' }
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.statusCode | Should -Be 504
        $result.body.error | Should -Be 'certificate_not_ready'
        Should -Invoke Invoke-TrustViewHttp -Times 30 -Exactly -ParameterFilter {
            $Uri -like '*/monitoredsslcertificate/42'
        }
        Should -Invoke Invoke-TrustViewHttp -Times 0 -ParameterFilter { $Uri -like '*/api/v1/contact' }
    }

    It 'rejects unexpected order success responses without checking out' {
        Mock Invoke-TrustViewHttp {
            return @{ StatusCode = 200; Body = @{ id = 42 } }
        } -ParameterFilter { $Uri -eq $configuration.OrderUrl }
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.body.error | Should -Be 'unexpected_order_response'
        Should -Invoke Invoke-TrustViewHttp -Times 0 -ParameterFilter { $Uri -like '*/checkout' }
    }

    It 'rejects an empty downloaded PFX' {
        $request.deliveryMethod = 'download'
        Mock Invoke-TrustViewHttp {
            return @{ StatusCode = 200; Body = @{ fullchainkey_pfx = '' } }
        } -ParameterFilter { $Uri -like '*/checkout' }
        (Invoke-TrustViewOrder -Request $request -Configuration $configuration).statusCode | Should -Be 502
    }

    It 'redacts upstream failures and does not retry a mutation' {
        Mock Invoke-TrustViewHttp { throw 'upstream diagnostic containing sensitive data' } `
            -ParameterFilter { $Uri -like '*/checkout' }
        $result = Invoke-TrustViewOrder -Request $request -Configuration $configuration
        $result.statusCode | Should -Be 502
        ($result | ConvertTo-Json -Depth 20) | Should -Not -Match 'sensitive data|not-a-real-key|pfxPassword'
        $result.body.certificateId | Should -Be 42
        Should -Invoke Invoke-TrustViewHttp -Times 1 -Exactly -ParameterFilter { $Uri -like '*/checkout' }
    }
}

Describe 'Secure result transport' {
    It 'uploads results using storage managed identity, not stdout or a SAS URL' {
        Mock Get-TrustViewManagedIdentityToken { 'not-a-real-token' } `
            -ParameterFilter { $Resource -eq 'https://storage.azure.com/' }
        Mock Invoke-WebRequest {}
        $result = @{ statusCode = 200; body = @{ pfxBase64 = ('A' * 20000); pfxPassword = 'test-only-value' } }
        $output = @(Send-TrustViewResult -Result $result -CorrelationId 'test-run-123' -Configuration $configuration)
        $output.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://exampleresults.blob.core.windows.net/trustview-results/test-run-123.json' -and
            $Method -eq 'Put' -and $Headers.Authorization -eq ('Bearer ' + 'not-a-real-token') -and
            $Headers['x-ms-blob-type'] -eq 'BlockBlob' -and
            ([Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json).body.pfxBase64.Length -eq 20000
        }
    }

    It 'disables HTTP redirects and serializes request data as UTF-8 JSON' {
        Mock Invoke-WebRequest {
            return @{ StatusCode = 201; Content = '{"id":42}' }
        }
        $response = Invoke-TrustViewHttp -Uri $configuration.OrderUrl -Method Post -Headers @{} -Body @{
            comment = "Quotation: '; Unicode: ø"
        }
        $response.StatusCode | Should -Be 201
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $MaximumRedirection -eq 0 -and $TimeoutSec -eq 30 -and
            ([Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json).comment -eq "Quotation: '; Unicode: ø"
        }
    }

    It 'uses an already obtained storage token without requesting another one' {
        Mock Get-TrustViewManagedIdentityToken { throw 'Unexpected second token request' }
        Mock Invoke-WebRequest {}
        Send-TrustViewResult -Result @{ statusCode = 502; body = @{} } `
            -CorrelationId 'test-run-123' -Configuration $configuration -Token 'test-only-storage-token'
        Should -Invoke Get-TrustViewManagedIdentityToken -Times 0
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $Headers.Authorization -eq ('Bearer ' + 'test-only-storage-token')
        }
    }
}

Describe 'Worker diagnostics' {
    BeforeEach {
        $script:workerConfiguration = $configuration.Clone()
        $script:workerResult = @{
            statusCode = 200
            body = @{ correlationId = 'test-run-123'; pfxPassword = 'test-only-sensitive-result' }
        }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{
            domains = @('example.internal')
            contactEmail = 'owner@example.internal'
            deliveryMethod = 'email'
            correlationId = 'test-run-123'
        } | ConvertTo-Json)))
        Mock Get-TrustViewConfiguration { $script:workerConfiguration }
        Mock Invoke-TrustViewOrder { $script:workerResult }
        Mock Get-TrustViewManagedIdentityToken { 'test-only-storage-token' }
        Mock Send-TrustViewResult {}
        Mock Invoke-WebRequest { throw 'Unexpected network call during validation' }
    }

    It 'validates configuration and request without any network calls or orders' {
        $output = @(Invoke-TrustViewWorker -EncodedRequest $encoded -ValidateOnly)
        $output.Count | Should -Be 1
        $output[0] | Should -Be 'Configuration and request validation passed; no network calls or orders were made.'
        Should -Invoke Get-TrustViewConfiguration -Times 1 -Exactly
        Should -Invoke Invoke-TrustViewOrder -Times 0
        Should -Invoke Get-TrustViewManagedIdentityToken -Times 0
        Should -Invoke Send-TrustViewResult -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
    }

    It 'identifies invalid request data without attempting an order' {
        { Invoke-TrustViewWorker -EncodedRequest '!invalid-base64!' -ValidateOnly } |
            Should -Throw '*request_validation*'
        Should -Invoke Invoke-TrustViewOrder -Times 0
        Should -Invoke Get-TrustViewManagedIdentityToken -Times 0
        Should -Invoke Send-TrustViewResult -Times 0
    }

    It 'reports <Stage> without returning raw upstream diagnostics' -ForEach @(
        @{ Function = 'Get-TrustViewConfiguration'; Stage = 'configuration_validation' }
        @{ Function = 'Invoke-TrustViewOrder'; Stage = 'order_processing' }
        @{ Function = 'Get-TrustViewManagedIdentityToken'; Stage = 'storage_identity' }
        @{ Function = 'Send-TrustViewResult'; Stage = 'result_upload' }
    ) {
        Mock -CommandName $Function { throw 'upstream-sensitive-token-and-password' }
        $failure = $null
        try { Invoke-TrustViewWorker -EncodedRequest $encoded }
        catch { $failure = $_ }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Exception.Message | Should -Match ([regex]::Escape("during $Stage."))
        ($failure | Out-String) | Should -Not -Match 'upstream-sensitive|test-only-storage-token|test-only-sensitive-result'
    }

    It 'preserves only a numeric HTTP status from <Wrapped> upload exceptions' -ForEach @(
        @{ Wrapped = $false }
        @{ Wrapped = $true }
    ) {
        Mock Send-TrustViewResult {
            $errorObject = New-Object System.Exception('upstream-sensitive-error-body')
            $errorObject | Add-Member NoteProperty Response ([pscustomobject]@{
                StatusCode = [Net.HttpStatusCode]::Forbidden
            })
            if ($Wrapped) {
                throw (New-Object System.Exception('upstream-sensitive-wrapper', $errorObject))
            }
            throw $errorObject
        }
        { Invoke-TrustViewWorker -EncodedRequest $encoded } | Should -Throw '*result_upload (HTTP 403)*'
    }

    It 'does not echo unrecognized response status data' {
        Mock Send-TrustViewResult {
            $errorObject = New-Object System.Exception('upstream-sensitive-error-body')
            $errorObject | Add-Member NoteProperty Response ([pscustomobject]@{
                StatusCode = 'upstream-sensitive-non-numeric-status'
            })
            throw $errorObject
        }
        $failure = $null
        try { Invoke-TrustViewWorker -EncodedRequest $encoded }
        catch { $failure = $_ }
        $failure.Exception.Message | Should -Match 'during result_upload\.'
        $failure.Exception.Message | Should -Not -Match 'HTTP'
        ($failure | Out-String) | Should -Not -Match 'upstream-sensitive'
    }

    It 'still publishes the order result once and emits only the completion message' {
        $output = @(Invoke-TrustViewWorker -EncodedRequest $encoded)
        $output.Count | Should -Be 1
        $output[0] | Should -Be 'TrustView processing finished; the result was stored for the workflow.'
        Should -Invoke Invoke-TrustViewOrder -Times 1 -Exactly
        Should -Invoke Get-TrustViewManagedIdentityToken -Times 1 -Exactly -ParameterFilter {
            $Resource -eq 'https://storage.azure.com/'
        }
        Should -Invoke Send-TrustViewResult -Times 1 -Exactly -ParameterFilter {
            $Token -eq 'test-only-storage-token' -and $Result -eq $script:workerResult -and
            $CorrelationId -eq 'test-run-123'
        }
    }
}

Describe 'Consumption workflow contract' {
    It 'uses the Code View envelope rather than an ARM deployment template' {
        @($workflow.PSObject.Properties.Name).Count | Should -Be 2
        $workflow.PSObject.Properties.Name | Should -Contain 'definition'
        $workflow.PSObject.Properties.Name | Should -Contain 'parameters'
        $workflow.definition.'$schema' | Should -Be (
            'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
        )
        ($workflow | ConvertTo-Json -Depth 100) | Should -Not -Match (
            '"defaultValue"|"workflowName"|"resources"|\[parameters\(|\[resourceGroup\(|\[subscription\(|\[format\('
        )
    }

    It 'provides a literal runtime value for every declared workflow parameter' {
        @($workflow.parameters.PSObject.Properties.Name).Count |
            Should -Be @($workflow.definition.parameters.PSObject.Properties.Name).Count
        foreach ($parameter in $workflow.definition.parameters.PSObject.Properties) {
            $workflow.definition.parameters.($parameter.Name).type | Should -Be 'String'
            $runtimeParameter = $workflow.parameters.($parameter.Name)
            @($runtimeParameter.PSObject.Properties.Name).Count | Should -Be 1
            $runtimeParameter.PSObject.Properties.Name | Should -Contain 'value'
            $runtimeParameter.value | Should -BeOfType [string]
            $runtimeParameter.value | Should -Not -BeNullOrEmpty
            $runtimeParameter.value | Should -Not -Match '^\[|^@'
        }
    }

    It 'preserves the complete ARM workflow definition in Code View' {
        $workflow.definition | ConvertTo-Json -Depth 100 -Compress |
            Should -Be ($template.resources[0].properties.definition | ConvertTo-Json -Depth 100 -Compress)
    }

    It 'deploys a Consumption resource with an assigned identity and a required caller allowlist' {
        $template.resources[0].type | Should -Be 'Microsoft.Logic/workflows'
        $template.resources[0].identity.type | Should -Be 'SystemAssigned'
        $template.parameters.allowedCallerIpRanges.minLength | Should -Be 1
        $template.resources[0].properties.accessControl.triggers.allowedCallerIpAddresses |
            Should -Be "[parameters('allowedCallerIpRanges')]"
        ($template | ConvertTo-Json -Depth 100) | Should -Not -Match 'appsetting\(|Microsoft.Web/sites|TrustViewOrderUrl'
    }

    It 'preserves the original trigger schema' {
        $template.resources[0].properties.definition.triggers.When_an_HTTP_request_is_received.inputs.schema |
            ConvertTo-Json -Depth 20 -Compress |
            Should -Be ($original.definition.triggers.When_an_HTTP_request_is_received.inputs.schema |
                ConvertTo-Json -Depth 20 -Compress)
    }

    It 'pins remote execution to dkmant0-01 and a locally staged worker' {
        $submit = $template.resources[0].properties.definition.actions.Run_private_TrustView_order.actions.Submit_VM_Run_Command
        $submit.inputs.uri | Should -Match '/virtualMachines/dkmant0-01/runCommands/'
        $submit.inputs.body.properties.source.script | Should -Match (
            [regex]::Escape("& 'C:\TrustView\Invoke-TrustViewOrder.ps1' -RequestBase64 `$RequestBase64 *> `$null")
        )
        $submit.inputs.body.properties.source.script | Should -Match (
            [regex]::Escape("`$ProgressPreference = 'SilentlyContinue'")
        )
        $submit.inputs.body.properties.parameters[0].value | Should -Match '^@base64\('
        $submit.inputs.retryPolicy.type | Should -Be 'none'
        $submit.inputs.body.properties.asyncExecution | Should -BeTrue
        $submit.runtimeConfiguration.secureData.properties | Should -Contain 'outputs'
    }

    It 'returns asynchronous results and hides PFX-bearing actions from run history' {
        $actions = $template.resources[0].properties.definition.actions
        $actions.Respond_VM_result.operationOptions | Should -Be 'Asynchronous'
        $actions.Respond_VM_result.runtimeConfiguration.secureData.properties | Should -Contain 'inputs'
        $actions.Run_private_TrustView_order.actions.Parse_VM_result.runtimeConfiguration.secureData.properties |
            Should -Contain 'inputs'
        $actions.Run_private_TrustView_order.actions.Parse_VM_result.inputs.content |
            Should -Match "equals\(body\('Get_VM_result'\)\?\['body'\]\?\['correlationId'\], workflow\(\)\.run\.name\)"
        $actions.Run_private_TrustView_order.actions.Parse_VM_result.inputs.schema.properties.body.required |
            Should -Contain 'correlationId'
        $actions.Run_private_TrustView_order.actions.Wait_for_VM_result.actions.Get_VM_result.runtimeConfiguration.secureData.properties |
            Should -Contain 'outputs'
        $actions.Run_private_TrustView_order.actions.Wait_for_VM_result.operationOptions | Should -Be 'FailWhenLimitsReached'
        $actions.Cleanup_remote_artifacts.actions.Delete_VM_result.inputs.method | Should -Be 'DELETE'
        $actions.Cleanup_remote_artifacts.actions.Delete_VM_result.operationOptions | Should -Be 'DisableAsyncPattern'
        $actions.Cleanup_remote_artifacts.actions.Delete_VM_Run_Command.inputs.method | Should -Be 'DELETE'
    }
}
