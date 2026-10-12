# trustview-API

## Private API access through an Azure Arc server

`Trustview_Order_Checkout.json` is the existing Standard Logic App workflow and
is unchanged. `Trustview_Order_Checkout_RunCommand.json` can be pasted directly
into a **Consumption** Logic App's **Logic app code view**. The optional ARM
deployment template is `Trustview_Order_Checkout_RunCommand.arm.json`. Both
versions accept the same certificate request, but all TrustView calls run on
the configured **Azure Arc-enabled Windows server**, not in the Logic App:

1. The Logic App validates the request and uses its managed identity to create
   an Arc Run Command on the operator-configured machine.
2. Run Command invokes the locally installed `Invoke-TrustViewOrder.ps1`.
3. The worker retrieves the API key from Key Vault using the **Arc machine's** identity,
   orders the certificate, waits for an active certificate with a private key,
   finds exactly one contact by email, associates that contact, and checks out
   the certificate for email delivery or download.
4. The worker writes its JSON result to a restricted Blob container using
   managed identity. The Logic App reads it, returns the result, and attempts
   to delete both the blob and the Run Command resource.

TrustView needs only a private HTTPS endpoint reachable from the server. No inbound
TrustView API exposure, Standard Logic App, API key in the workflow, storage
account key, or SAS token is required. The request endpoint still needs caller
authentication and network restrictions; Run Command does not replace those.

### Prerequisites and identities

This version targets an **Azure Arc-enabled Windows server**, not an Azure VM
or Linux server. Use a healthy, currently supported Connected Machine agent;
Arc Run Command requires agent **1.33 or later** and is currently documented as
**preview**. Run Command is built into the agent; do not deploy a separate
`machines/extensions` resource for it. The workflow uses
`Microsoft.HybridCompute/machines/<name>/runCommands` with API `2025-01-13`.
Ensure the `himds` and `ExtensionService` services are healthy. Local Arc
security controls must permit `Microsoft.Cplat.Core/RunCommandHandlerWindows`;
disabled extensions, handler blocklists, or monitor mode can prevent execution.
Do not weaken those controls without your security team's approval.

The worker runs as **Local System** with Windows PowerShell 5.1 or later. Its
path and target machine cannot be supplied by certificate callers. No RunAs
password is required.

Arc onboarding creates the machine's system-assigned managed identity. Enable
the new Logic App's system-assigned identity separately and use the Arc
machine's principal ID for server permissions, not an Azure VM principal.
Provision Key Vault, a storage account, and an existing container before use.
Grant these permissions:

| Identity | Scope | Permissions |
| --- | --- | --- |
| Logic App | Only the configured Arc machine resource | Custom role with `Microsoft.HybridCompute/machines/read` and `Microsoft.HybridCompute/machines/runcommands/read`, `/write`, `/delete` |
| Arc machine | Only the TrustView API-key secret | Key Vault Secrets User, or an equivalent secret `get` access policy |
| Arc machine | Only the result container | Custom storage data role with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write` |
| Logic App | Only the result container | Custom storage data role with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` and `/delete` |

The blob permissions above are **DataActions**, not management-plane Actions.
Custom role definitions also need an assignable subscription/resource-group
scope; role **assignments** should use the narrower scopes in the table.
Storage Blob Data Contributor at container scope works for initial deployment,
but grants more access than these custom roles.

Run Command write permission allows arbitrary privileged execution on that server,
even though this workflow submits only a fixed worker invocation. Protect the
Logic App identity, workflow editing permissions, and server administrators
accordingly. Do not assign subscription-wide Contributor or Owner.

Allow the server outbound access to the required Arc services, Key Vault,
result storage, and the private TrustView endpoint. Arc identity uses local
HIMDS at **`http://localhost:40342`**, not Azure VM IMDS (`169.254.169.254`).
The agent installs the machine-level `IDENTITY_ENDPOINT` setting; the worker
requires `http://localhost:40342/metadata/identity/oauth2/token` and authenticates
through its token-file challenge. Do not set this to a remote endpoint.
Manual token callers need an elevated local Administrators session or membership
in **Hybrid Agent Extension Applications**. Do not relax the ACL on
`%ProgramData%\AzureConnectedMachineAgent\Tokens` or expose the local identity port
externally. The worker bypasses proxies and rejects redirects for HIMDS.
Use trusted HTTPS certificates; the worker does not disable certificate
validation or follow HTTP redirects.

**Consumption networking limitation:** the Logic App must reach the storage
account's HTTPS Blob endpoint. A private container is not the same as a
private-endpoint-only storage account. Consumption does not provide Standard's
outbound VNet integration. Configure a supported storage firewall exception or
allow the documented regional Consumption outbound IP addresses, while
retaining managed-identity authorization. A storage account accessible only
through a private endpoint is incompatible with this workflow as written.
TrustView and Key Vault can remain server-private regardless.

Disable anonymous blob access and require TLS 1.2 or later. Use a dedicated
result container with no unrelated readers. Download results temporarily
contain **both the PFX private key and its password**. Configure a short
lifecycle expiry as a fallback for failed/cancelled runs, and account for
soft-delete, versions, snapshots, backups, and diagnostic retention: deleting
a blob does not necessarily remove retained copies. Do not enable request-body
logging on the workflow, worker, or client. Protect the Logic App's retained
asynchronous responses and run-history access as sensitive data too.

### Install the worker

On the target Arc server, install the checked-in worker as:

```text
C:\TrustView\Invoke-TrustViewOrder.ps1
```

Restrict write access to that directory and file to SYSTEM and trusted
administrators. Follow your organization's PowerShell signing/execution policy;
the workflow does not bypass it. Do not accept a script URL or script contents
from certificate callers.

Set these **machine-level** environment variables on the server:

| Setting | Value |
| --- | --- |
| `TrustViewOrderUrl` | `https://<private-trustview-host>/api/v1/monitoredobject/monitoredsslcertificate/order` |
| `TrustViewTemplateOid` | Your ADCS template OID |
| `KeyVaultName` | Vault name, not a URL |
| `TrustViewSecretName` | Secret name containing the TrustView API key |
| `ResultsBlobServiceUri` | `https://<storage-account>.blob.core.windows.net` without a trailing slash |
| `ResultsContainerName` | The dedicated result container name |

Use `[Environment]::SetEnvironmentVariable('<name>', '<value>', 'Machine')` in
an administrator PowerShell session. The worker reads machine settings directly;
do not set only your interactive user's environment. No API key is stored in
these settings. Both workflow versions and the worker target the Azure public cloud.

### Test the PowerShell worker manually

Run this test **on the target Arc server**, in an elevated administrator Windows PowerShell 5.1
or later session, after installing the worker, setting all six machine-level
environment variables above, and granting the **Arc machine identity** its Key Vault
secret-read and result-container write permissions. You do not need to trigger
the Logic App or sign in to Azure PowerShell: the worker uses the server's managed
identity through local HIMDS. Running it on your workstation will not use that identity.

Keep the Logic App disabled during this test. **This is a real certificate order,
not a dry run**, and email delivery sends real emails. Use a test ADCS template,
a test domain, and an existing TrustView contact that uniquely matches an email
address you control. Do not bypass your organization's execution policy or
enable PowerShell transcription/debug logging.

In the same PowerShell session, build the request; replace the example domain
and email before running it:

```powershell
$ErrorActionPreference = 'Stop'
$correlationId = 'manual-' + [guid]::NewGuid().ToString('N')
$request = @{
    domains = @('service.example.internal')
    contactEmail = 'owner@example.internal'
    deliveryMethod = 'email'
    keyspec = 'RSA:2048'
    ip_sans = @()
    comment = 'Manual Arc worker test'
    correlationId = $correlationId
}
$requestJson = $request | ConvertTo-Json -Depth 10 -Compress
$requestBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($requestJson))
$blobName = $correlationId + '.json'
```

`correlationId` is required when calling the worker directly; the Logic App
normally adds it for you. Generate a new ID for each attempt, but check TrustView
before retrying a failed attempt to avoid duplicate orders.

Invoke the installed worker with the **call operator `&`**, not dot-sourcing
(`.`), which only loads its functions:

```powershell
& 'C:\TrustView\Invoke-TrustViewOrder.ps1' -RequestBase64 $requestBase64
```

Allow several minutes for issuance. The normal console output is:

```text
TrustView processing finished; the result was stored for the workflow.
```

This confirms result publication, **not successful checkout**. Both successful
orders and handled API failures are stored as JSON in:

```text
<ResultsBlobServiceUri>/<ResultsContainerName>/<correlationId>.json
```

To verify the result, use Azure Portal's Storage browser with **Microsoft Entra
user authentication** and your own authorized operator account. That account
needs blob read/delete permissions on the result container (for example,
Storage Blob Data Contributor at container scope), portal resource visibility,
and a permitted storage network path. Do not add blob-read permissions to the
write-only Arc machine identity just to inspect this test.

Locate the exact blob named by `$blobName` and inspect it in a secure viewer:

- Check that `body.correlationId` matches `$correlationId`.
- `statusCode: 200` with
  `body.status: "order_created_contact_added_and_delivery_requested"` means
  TrustView accepted the email checkout. Confirm receipt of the certificate
  and separate password email at your test address.
- `422` means contact matching failed, `504` means issuance readiness timed
  out, and `502` means processing/API failure. Check `body.error`,
  `body.message`, and any `body.certificateId`; inspect TrustView before retrying.
- A thrown error with no result blob points to request/configuration validation
  or result-publication failure. Check the six machine settings, Arc identity,
  Key Vault/storage RBAC, and network/TLS connectivity; do not print tokens or
  the API key while troubleshooting.

#### Diagnose a worker exception without another order

If all six presence checks are `True` but the worker still throws, presence
does not prove that the values or request payload are valid. Replace the
installed worker with the latest checked-in version; keep
`Get-TrustViewConfiguration` unchanged, with environment **names**, not URLs or
other setting values, passed to `GetEnvironmentVariable`.

Run this safe check using your prepared request in the same session:

```powershell
& 'C:\TrustView\Invoke-TrustViewOrder.ps1' -RequestBase64 $requestBase64 -ValidateOnly
```

It validates machine configuration and decodes/validates the request, but makes
**no network calls, uploads, or certificate orders**. Successful output is:

```text
Configuration and request validation passed; no network calls or orders were made.
```

This is not a connectivity, identity, Key Vault permission, or storage-write
test. A validation failure now reports a fixed stage name instead of the old
catch-all publication message. Normal worker execution also reports these
stages, with a numeric HTTP status when available:

| Stage | What to check |
| --- | --- |
| `configuration_validation` | Machine-level settings, exact URL/OID/name formats above, and unmodified environment-variable names in the worker |
| `request_validation` | Rebuild the UTF-8 base64 request; ensure the required unique `correlationId` is present and pass the encoded string, not a JSON object |
| `order_processing` | An unexpected worker execution failure; inspect TrustView before retrying |
| `storage_identity` | Connected Machine agent/HIMDS health, machine-level `IDENTITY_ENDPOINT`, and local token-file permissions; an Azure sign-in under your user does not supply the worker's token |
| `result_upload` | Existing result container, Arc machine blob-write DataAction, storage firewall/network access, DNS, and TLS; HTTP 403 can indicate authorization or a network restriction, while HTTP 404 can indicate a missing container |

The last two stages happen **after** order processing; an order or email
delivery may already exist even when publication fails. Do not retry the
normal worker just to obtain a diagnostic. First inspect TrustView and any
existing result, then share only the sanitized stage/status message when
requesting help. Never share raw exception dumps, access tokens, API keys,
passwords, PFX contents, or `$requestBase64` (base64 is not encryption).

#### Check Arc identity without placing an order

After replacing the installed worker with this Arc version, run the following
on the Arc server in an elevated administrator session. It requests tokens for
Key Vault and Storage but does **not** read secrets, write blobs, call TrustView,
or place orders. It prints no tokens or challenge-file contents:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    . 'C:\TrustView\Invoke-TrustViewOrder.ps1' -RequestBase64 'unused-when-dot-sourced'
    try {
        $null = Get-TrustViewManagedIdentityToken -Resource 'https://vault.azure.net'
        $null = Get-TrustViewManagedIdentityToken -Resource 'https://storage.azure.com/'
        Write-Output 'Arc identity token checks passed for Key Vault and Storage.'
    }
    catch { Write-Output 'Arc identity token check failed; check agent health, IDENTITY_ENDPOINT, and local token-file permissions.' }
}
```

Successful token acquisition does **not** validate Key Vault/storage RBAC or
network access to those services. Keep normal processing paused until those
permissions are confirmed and earlier TrustView orders have been inspected.
Arc's built-in Run Command Blob output does not support managed-identity
authentication; this workflow instead keeps the worker's direct authenticated
Blob PUT. Never use command output to transfer the PFX or its password.

For a separate download test, set `deliveryMethod = 'download'` in the request
and rerun the preparation block to generate a **new** correlation ID and encoded
payload before invoking the worker. A successful result has
`body.status: "order_created_contact_added_and_downloaded"` plus `pfxBase64`
and `pfxPassword`. Treat the entire result as a secret: do not print it,
paste it into a PR, or store it in an unprotected download location.

**Clean up manually:** delete the exact test result blob after inspection;
the Logic App will not clean up this direct invocation. Securely remove any
local copies and account for the storage retention caveats above. No Run
Command resource is created by this local test. Passing it validates the worker
and server dependencies, not Logic App permissions, Run Command's SYSTEM execution
context, or the asynchronous client path; test those separately afterward.

### Publish through Logic App Code View

1. Create or open a **Consumption** Logic App in Azure Portal. Keep it disabled
   until the worker, identity permissions, networking, and caller restrictions
   are configured.
2. Under **Identity**, enable the **System assigned** identity and save. Assign
   the Logic App and Arc machine permissions from the table above.
3. Under **Workflow settings**, configure the trigger's allowed inbound IP
   addresses to include only approved caller ranges. Do not allow `0.0.0.0/0`.
   Code View does **not** configure this resource-level access control or the
   managed identity.
4. Open **Logic app code view** and replace its contents with the entire
   `Trustview_Order_Checkout_RunCommand.json` file.
5. Replace the placeholder strings in the **top-level `parameters`** section
   using the values below, then **Save**.
6. Confirm the server worker and all prerequisites are ready before enabling the
   Logic App and sending a test request.

| Runtime parameter | Value to supply |
| --- | --- |
| `ArcSubscriptionId` | Subscription ID containing the Arc machine resource |
| `ArcResourceGroup` | Resource group containing the Arc machine resource |
| `ArcMachineName` | Exact Arc **machine resource name** from Azure Portal; confirm `dkmant0-01` (zero) versus `dkmanto-01` (letter o) |
| `ArcLocation` | Arc resource's Azure region, such as `westeurope`, not necessarily the Logic App region or the server's physical location |
| `ResultsBlobServiceUri` | `https://<storage-account>.blob.core.windows.net` without a trailing slash |
| `ResultsContainerName` | Existing result container; defaults to `trustview-results` |

The result store must match the server's machine-level settings. The JSON contains
only `definition` and runtime `parameters` with **`value`** entries. Keep the
parameter type declarations inside `definition.parameters`. Do not paste ARM
fields such as `resources`, `workflowName`, or deployment parameter
`defaultValue` into Code View: they cause the reported `FlowTemplateParameter`
save error. Code View does not create resources, install the worker, or assign
permissions.

If you published the earlier Azure VM version, replace both the installed worker
and the entire Code View JSON. Retain the six server configuration settings and
storage values, but replace `VmSubscriptionId`, `VmResourceGroup`, and `VmLocation`
with the `Arc...` bindings above and supply `ArcMachineName`. Copy the values from
the parent `Microsoft.HybridCompute/machines/<name>` resource, **not** its
`/extensions/<name>` child. Assign the new HybridCompute permissions to the
Logic App; Compute VM permissions do not authorize Arc Run Command.

### Optional ARM deployment

Deploy `Trustview_Order_Checkout_RunCommand.arm.json` as an ARM resource-group
deployment, supplying:

- `arcResourceGroup` and `arcMachineName`: exact target Arc resource group/name.
- `arcLocation`: that Arc resource's Azure region, not necessarily the Logic App region.
- `resultsStorageAccountName` and `resultsContainerName`: the server's result store.
- `allowedCallerIpRanges`: a nonempty array of objects such as
  `[{"addressRange":"198.51.100.10/32"}]`, replaced with actual approved caller IPs.
  Do not use an unrestricted range.
- Optionally `workflowName`, `location`, and `arcSubscriptionId` (defaults to the
  deployment subscription).

The template creates only the workflow and its identity. It does **not** create
the Arc machine, Key Vault, container, role definitions/assignments, or install the
worker. After deployment, assign the identity permissions above and allow time
for RBAC propagation before sending requests.

Do not paste the `.arm.json` file into Logic App Code View.

Retrieve the Request trigger's callback URL through your normal secured Azure
deployment process. Treat its signature and asynchronous polling URLs as
credentials; do not commit them or include them in logs. The required IP
allowlist (configured separately for Code View) adds a network restriction,
not user-level authorization. Configure
Entra ID authorization or an authenticated gateway if callers need individual
authorization rather than a shared signed callback URL.

### Request and asynchronous response

The request schema is the same as the existing workflow:

```json
{
  "domains": ["service.example.internal"],
  "contactEmail": "owner@example.internal",
  "deliveryMethod": "email",
  "keyspec": "RSA:2048",
  "ip_sans": [],
  "comment": "Certificate request"
}
```

Use `deliveryMethod: "download"` for a response containing `pfxBase64` and
`pfxPassword`. Email delivery uses TrustView's `mail-mail` checkout, with the
certificate and password sent in separate emails. The contact must already
exist and match uniquely after trimming and case normalization; this workflow
associates the existing contact with the certificate, not edits its profile.

**Client change:** Consumption responses are asynchronous. Expect HTTP `202`
with a `Location` polling URL, follow that URL using the returned retry guidance,
and consume the final status/body when processing completes. Do not interpret
`202` as a completed certificate checkout. The completed success payload
preserves the original certificate/contact details and delivery fields.
Validation can reject malformed requests before execution; completed failures
include `422` for a missing/ambiguous contact, `504` for readiness timeout,
and `502` for execution/API/result-storage failures.

Run Command stdout is unsuitable for PFX delivery because output is limited and
is retained in Azure execution diagnostics. Only a fixed, nonsensitive completion
message is printed; the bootstrap suppresses the worker's output streams. API
keys, generated passwords, PFX data, and raw upstream
errors are never printed or passed as Run Command parameters. The parameter
contains only base64-encoded request data and a generated correlation ID:
**base64 is not encryption**, and request/contact data can be visible to
administrators reading the Run Command resource until cleanup.

The worker checks readiness up to 30 times over five minutes; managed Run
Command has a ten-minute execution limit here. The workflow polls results for
up to 90 attempts, bounded by twenty minutes, and serializes workflow runs.
Ordering, contact association, checkout, and command submission are not retried
automatically. A failed response does not undo an existing order: inspect
TrustView and correlate the Logic App run before retrying to avoid duplicate
orders or deliveries. Monitor failed cleanup actions and enforce result expiry
even when a run is cancelled.

The worker publishes its terminal result once, without upload retries; the
workflow requires HTTP 200 and a matching correlation ID before using it.
`asyncExecution` acknowledges worker startup, not successful checkout. Managed
Run Command deletion can terminate a still-running worker, so cleanup runs only
after result retrieval or workflow failure/timeout and allows Azure's asynchronous
deletion polling before deleting the result blob. Monitor failed or cancelled
cleanup; deletion does not undo a certificate order.

### Validation

With the existing PowerShell/Pester/PSScriptAnalyzer tools installed:

```powershell
Invoke-Pester -Path ./tests/TrustViewRunCommand.Tests.ps1 -Output Detailed
Invoke-ScriptAnalyzer -Path ./Invoke-TrustViewOrder.ps1 -Severity Error,Warning
```

Tests mock network calls; they cover request validation, injection-safe data
handling, readiness limits, contact matching, email/download behavior, error
redaction, large PFX transport, and the workflow contract. They do not replace
an Azure deployment test. They also check the Code View envelope, literal
runtime parameters, Arc challenge authentication/path validation, and parity
with the ARM workflow definition. Save the
Code View version or validate the optional ARM deployment in your subscription,
then exercise email and download requests against a test ADCS template,
including missing contacts, delayed issuance, denied permissions, and cleanup.

Azure references:

- [Run Command on Azure Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)
- [Azure Arc managed-identity authentication](https://learn.microsoft.com/en-us/azure/azure-arc/servers/managed-identity-authentication)
- [HybridCompute RBAC operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/hybrid-multicloud#microsofthybridcompute)
- [Consumption Request/Response and asynchronous replies](https://learn.microsoft.com/en-us/azure/connectors/connectors-native-reqres)
- [Logic Apps managed-identity authentication](https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity)
- [Secure Logic Apps inputs and outputs](https://learn.microsoft.com/en-us/azure/logic-apps/set-up-security-permissions#secure-run-history)