# Requires: Az.KeyVault, Az.Accounts, Microsoft.Graph.Applications

# --------------------------
# Variables (edit these)
# --------------------------
$vault         = "AppRegSec"
$kvCertName    = "access-package-control-v2"      # <-- KV object name (letters/digits/hyphens ONLY)
$subjectCN     = "CN=Access_Package_Control_V2"   # <-- Subject CN
$appId         = "241d4049-a9b9-459a-893f-e44acfd01316"  # Application (client) ID
$objectId      = "8728095c-bb62-4e75-a16d-75ad0a4c25bd"  #Service Principal Object ID 
$outDir        = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --------------------------
# 1) Create (or reuse) KV certificate
# --------------------------
$policy = New-AzKeyVaultCertificatePolicy `
  -SubjectName $subjectCN `
  -IssuerName "Self" `
  -SecretContentType "application/x-pkcs12" `
  -ValidityInMonths 24 `
  -KeyType RSA -KeySize 2048

$existing = Get-AzKeyVaultCertificate -VaultName $vault -Name $kvCertName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Creating Key Vault certificate '$kvCertName' in vault '$vault'..."
    Add-AzKeyVaultCertificate -VaultName $vault -Name $kvCertName -CertificatePolicy $policy -ErrorAction Stop | Out-Null
}
# --------------------------
# 2) Wait for cert to be fully materialized (secret + public cert)
# --------------------------
Write-Host "Waiting for Key Vault secret & public certificate to be ready..."
$deadline = (Get-Date).AddMinutes(3)

$kvCert = $null
$secretValueB64 = $null

do {
    Start-Sleep -Seconds 10

    # Try operation first (nice-to-have status)
    $op = Get-AzKeyVaultCertificateOperation -VaultName $vault -Name $kvCertName -ErrorAction SilentlyContinue
    if ($op) { Write-Host "  Operation status: $($op.Status)" }

    # Check if cert & secret are present
    $kvCert = Get-AzKeyVaultCertificate -VaultName $vault -Name $kvCertName -ErrorAction SilentlyContinue
    $secretValueB64 = Get-AzKeyVaultSecret -VaultName $vault -Name $kvCertName -AsPlainText -ErrorAction SilentlyContinue

    $hasSecret = -not [string]::IsNullOrWhiteSpace($secretValueB64)
    $hasCer    = ($kvCert -and $kvCert.Cer -and $kvCert.Cer.Length -gt 0)

    if ($hasSecret -and $hasCer) { break }
} while ((Get-Date) -lt $deadline)

if (-not $hasSecret) {
    throw "Key Vault PFX secret for '$kvCertName' is not ready."
}

# --------------------------
# 3) Download .pfx and .cer (with fallback for CER)
# --------------------------
# Save PFX
$pfxBytes = [Convert]::FromBase64String($secretValueB64)
$pfxPath  = Join-Path $outDir "$($kvCertName).pfx"
[IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
Write-Host "Saved PFX -> $pfxPath"

# Try CER from KV; if missing, derive from PFX
$cerPath = Join-Path $outDir "$($kvCertName).cer"
if ($kvCert -and $kvCert.Cer -and $kvCert.Cer.Length -gt 0) {
    [IO.File]::WriteAllBytes($cerPath, $kvCert.Cer)
    Write-Host "Saved CER (from Key Vault) -> $cerPath"
}
else {
    # Fallback: extract public cert from the PFX we just saved
    Write-Host "Key Vault CER not present yet; deriving CER from PFX..."
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $collection.Import($pfxPath, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    # pick the most recent leaf
    $leaf = $collection | Sort-Object NotBefore -Descending | Select-Object -First 1
    if (-not $leaf) { throw "Could not read certificate from PFX." }
    $cerBytes = $leaf.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [IO.File]::WriteAllBytes($cerPath, $cerBytes)
    Write-Host "Saved CER (derived from PFX) -> $cerPath"
}

# optional: clear the operation record once we know we’re good
try { if ($op) { Stop-AzKeyVaultCertificateOperation -VaultName $vault -Name $kvCertName -ErrorAction Stop | Out-Null } } catch {}

# --------------------------
# 4) Import PFX into CurrentUser\My
# --------------------------
# Do NOT pass -Password when PFX is unprotected (most KV exports are).
$importParams = @{
    FilePath          = $pfxPath
    CertStoreLocation = 'Cert:\CurrentUser\My'
    Exportable        = $true
}
$cert = Import-PfxCertificate @importParams
if (-not $cert) { throw "Import-PfxCertificate failed. The PFX may be invalid or password-protected." }
Write-Host "Installed PFX into Cert:\CurrentUser\My with thumbprint $($cert.Thumbprint)"

# --------------------------
# 5) Upload CER to App Registration via Microsoft Graph
# --------------------------
function Add-AppCert-WithGraph {
    param(
        [Parameter(Mandatory)][string] $AppId,        # Application (client) ID
        [Parameter(Mandatory)][string] $CerFilePath,
        [string] $DisplayName = $kvCertName
    )

    if (-not (Get-Module Microsoft.Graph.Applications -ListAvailable)) {
        Write-Host "Installing Microsoft.Graph..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    Import-Module Microsoft.Graph.Applications

    if (-not (Get-MgContext)) { Connect-MgGraph -Scopes "Application.ReadWrite.All" }

    # Resolve app by AppId (clientId)
    $app = Get-MgApplication -ApplicationId $objectId -ErrorAction Stop
    $cer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)

    # Build a typed KeyCredential object
    $keyObj = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential]::new()
    $keyObj.Type                = "AsymmetricX509Cert"
    $keyObj.Usage               = "Verify"
    $keyObj.Key                 = $cer.GetRawCertData()
    $keyObj.CustomKeyIdentifier = $cer.GetCertHash()
    $keyObj.DisplayName         = $subjectCN
    $keyObj.StartDateTime       = Get-Date
    $keyObj.EndDateTime         = $cer.NotAfter

    # Append to existing keys (don’t wipe them!)
    $allKeys = @()
    if ($app.KeyCredentials) { $allKeys += $app.KeyCredentials }
    $allKeys += $keyObj

    Update-MgApplication -ApplicationId $objectId -KeyCredentials $allKeys
    Write-Host "✅ Certificate added via Update-MgApplication."

}

Add-AppCert-WithGraph -AppId $objectId -CerFilePath $cerPath -DisplayName $subjectCN


#Veridy Cert Exists in app Registration 
(Get-MgContext) | Format-List Account, TenantId, Scopes

# Get the app by client ID and list its current certs
$app = Get-MgApplication -ApplicationId $objectId -Property id,displayName,keyCredentials
$app.DisplayName, $app.Id
$app.KeyCredentials | Select DisplayName, Type, Usage, StartDateTime, EndDateTime, CustomKeyIdentifier |
    Format-Table -Auto