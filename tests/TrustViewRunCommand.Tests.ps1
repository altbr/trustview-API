BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $root 'Invoke-TrustViewOrder.ps1') -RequestBase64 'unused-when-dot-sourced'
    $template = Get-Content (Join-Path $root 'Trustview_Order_Checkout_RunCommand.json') -Raw | ConvertFrom-Json
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
}

Describe 'Consumption workflow contract' {
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
        $submit.inputs.body.properties.source.script | Should -Be (
            "param([string]`$RequestBase64)`n& 'C:\TrustView\Invoke-TrustViewOrder.ps1' -RequestBase64 `$RequestBase64"
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
            Should -Contain 'outputs'
        $actions.Run_private_TrustView_order.actions.Wait_for_VM_result.actions.Get_VM_result.runtimeConfiguration.secureData.properties |
            Should -Contain 'outputs'
        $actions.Run_private_TrustView_order.actions.Wait_for_VM_result.operationOptions | Should -Be 'FailWhenLimitsReached'
        $actions.Cleanup_remote_artifacts.actions.Delete_VM_result.inputs.method | Should -Be 'DELETE'
        $actions.Cleanup_remote_artifacts.actions.Delete_VM_Run_Command.inputs.method | Should -Be 'DELETE'
    }
}
