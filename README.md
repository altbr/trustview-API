# trustview-API

## Private API access through dkmant0-01

`Trustview_Order_Checkout.json` is the existing Standard Logic App workflow and
is unchanged. `Trustview_Order_Checkout_RunCommand.json` is an ARM template for
a separate **Consumption** Logic App. It accepts the same certificate request,
but all TrustView calls run on **dkmant0-01**, not in the Logic App:

1. The Logic App validates the request and uses its managed identity to create
   a managed Azure VM Run Command on the fixed VM.
2. Run Command invokes the locally installed `Invoke-TrustViewOrder.ps1`.
3. The worker retrieves the API key from Key Vault using the **VM's** identity,
   orders the certificate, waits for an active certificate with a private key,
   finds exactly one contact by email, associates that contact, and checks out
   the certificate for email delivery or download.
4. The worker writes its JSON result to a restricted Blob container using
   managed identity. The Logic App reads it, returns the result, and attempts
   to delete both the blob and the Run Command resource.

TrustView needs only a private HTTPS endpoint reachable from the VM. No inbound
TrustView API exposure, Standard Logic App, API key in the workflow, storage
account key, or SAS token is required. The request endpoint still needs caller
authentication and network restrictions; Run Command does not replace those.

### Prerequisites and identities

This version targets an **Azure Windows VM**, not an Azure Arc-enabled server.
`dkmant0-01` must have a healthy Azure VM Agent and a supported managed Run
Command OS (for example, Windows Server 2016 or later; Server 2012/R2 is not
listed as supported).
The worker runs under the agent's default privileged account with Windows
PowerShell 5.1 or later. Its path and the target VM cannot be supplied by callers.
If this server is Linux or Arc-enabled, the command and identity integration
must be adapted before deployment.

Enable a system-assigned managed identity on both the VM and the new Logic App.
Provision Key Vault, a storage account, and an existing container before use.
Grant these permissions:

| Identity | Scope | Permissions |
| --- | --- | --- |
| Logic App | Only the `dkmant0-01` VM resource | Custom role with `Microsoft.Compute/virtualMachines/read` and `Microsoft.Compute/virtualMachines/runCommands/read`, `/write`, `/delete` |
| VM | Only the TrustView API-key secret | Key Vault Secrets User, or an equivalent secret `get` access policy |
| VM | Only the result container | Custom storage data role with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write` |
| Logic App | Only the result container | Custom storage data role with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` and `/delete` |

The blob permissions above are **DataActions**, not management-plane Actions.
Custom role definitions also need an assignable subscription/resource-group
scope; role **assignments** should use the narrower scopes in the table.
Storage Blob Data Contributor at container scope works for initial deployment,
but grants more access than these custom roles.

Run Command write permission allows arbitrary privileged execution on that VM,
even though this template submits only a fixed worker invocation. Protect the
Logic App identity, workflow editing permissions, and VM administrators
accordingly. Do not assign subscription-wide VM Contributor or Owner.

Allow the VM outbound access to Azure VM Agent/Run Command services, IMDS
(`169.254.169.254`), Key Vault, result storage, and the private TrustView endpoint.
Use trusted HTTPS certificates; the worker does not disable certificate
validation or follow HTTP redirects.

**Consumption networking limitation:** the Logic App must reach the storage
account's HTTPS Blob endpoint. A private container is not the same as a
private-endpoint-only storage account. Consumption does not provide Standard's
outbound VNet integration. Configure a supported storage firewall exception or
allow the documented regional Consumption outbound IP addresses, while
retaining managed-identity authorization. A storage account accessible only
through a private endpoint is incompatible with this workflow as written.
TrustView and Key Vault can remain VM-private regardless.

Disable anonymous blob access and require TLS 1.2 or later. Use a dedicated
result container with no unrelated readers. Download results temporarily
contain **both the PFX private key and its password**. Configure a short
lifecycle expiry as a fallback for failed/cancelled runs, and account for
soft-delete, versions, snapshots, backups, and diagnostic retention: deleting
a blob does not necessarily remove retained copies. Do not enable request-body
logging on the workflow, worker, or client. Protect the Logic App's retained
asynchronous responses and run-history access as sensitive data too.

### Install the worker

On `dkmant0-01`, install the checked-in worker as:

```text
C:\TrustView\Invoke-TrustViewOrder.ps1
```

Restrict write access to that directory and file to SYSTEM and trusted
administrators. Follow your organization's PowerShell signing/execution policy;
the workflow does not bypass it. Do not accept a script URL or script contents
from certificate callers.

Set these **machine-level** environment variables on the VM:

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
these settings. This template and worker target the Azure public cloud.

### Deploy the Consumption template

Deploy `Trustview_Order_Checkout_RunCommand.json` as an ARM resource-group
deployment, supplying:

- `vmResourceGroup`: resource group containing `dkmant0-01`.
- `vmLocation`: that VM's Azure region, not necessarily the Logic App region.
- `resultsStorageAccountName` and `resultsContainerName`: the VM's result store.
- `allowedCallerIpRanges`: a nonempty array of objects such as
  `[{"addressRange":"198.51.100.10/32"}]`, replaced with actual approved caller IPs.
  Do not use an unrestricted range.
- Optionally `workflowName`, `location`, and `vmSubscriptionId` (defaults to the
  deployment subscription).

The template creates only the workflow and its identity. It does **not** create
the VM, Key Vault, container, role definitions/assignments, or install the
worker. After deployment, assign the identity permissions above and allow time
for RBAC propagation before sending requests.

Retrieve the Request trigger's callback URL through your normal secured Azure
deployment process. Treat its signature and asynchronous polling URLs as
credentials; do not commit them or include them in logs. The required IP
allowlist adds a network restriction, not user-level authorization. Configure
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
after result retrieval or workflow failure/timeout.

### Validation

With the existing PowerShell/Pester/PSScriptAnalyzer tools installed:

```powershell
Invoke-Pester -Path ./tests/TrustViewRunCommand.Tests.ps1 -Output Detailed
Invoke-ScriptAnalyzer -Path ./Invoke-TrustViewOrder.ps1 -Severity Error,Warning
```

Tests mock network calls; they cover request validation, injection-safe data
handling, readiness limits, contact matching, email/download behavior, error
redaction, large PFX transport, and the workflow contract. They do not replace
an Azure deployment test. Validate the ARM deployment in your subscription,
then exercise email and download requests against a test ADCS template,
including missing contacts, delayed issuance, denied permissions, and cleanup.

Azure references:

- [Managed Run Command on Windows VMs](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/run-command-managed)
- [Consumption Request/Response and asynchronous replies](https://learn.microsoft.com/en-us/azure/connectors/connectors-native-reqres)
- [Logic Apps managed-identity authentication](https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity)
- [Secure Logic Apps inputs and outputs](https://learn.microsoft.com/en-us/azure/logic-apps/set-up-security-permissions#secure-run-history)