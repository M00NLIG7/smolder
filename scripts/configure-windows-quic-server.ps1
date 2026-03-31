[CmdletBinding()]
param(
    [string]$ServerName = "files.lab.example",
    [string]$ShareName = "smolder",
    [string]$SharePath = "C:\Shares\smolder",
    [string]$LocalUsername = "smolder",
    [string]$LocalPassword = "Passw0rd!",
    [string]$CertificateFriendlyName = "Smolder SMB over QUIC",
    [string]$CertificateExportPath = "C:\Users\Public\smolder-smb-quic.cer",
    [int]$QuicPort = 443
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Administrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Ensure-LocalUser {
    param(
        [string]$Username,
        [string]$Password
    )

    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        return
    }

    $secure = ConvertTo-SecureString -AsPlainText -Force -String $Password
    New-LocalUser `
        -Name $Username `
        -Password $secure `
        -PasswordNeverExpires `
        -AccountNeverExpires `
        -UserMayNotChangePassword `
        -FullName "Smolder QUIC Test User" `
        -Description "Local user for Smolder SMB over QUIC interop"
}

function Ensure-SharePath {
    param(
        [string]$Path,
        [string]$Username
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    & icacls.exe $Path /grant "Administrators:(OI)(CI)F" | Out-Null
    & icacls.exe $Path /grant "${env:COMPUTERNAME}\${Username}:(OI)(CI)M" | Out-Null
}

function Ensure-SmbShare {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Username
    )

    $share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $share) {
        New-SmbShare `
            -Name $Name `
            -Path $Path `
            -FullAccess "Administrators" `
            -ChangeAccess "${env:COMPUTERNAME}\${Username}" | Out-Null
        return
    }

    Grant-SmbShareAccess -Name $Name -AccountName "${env:COMPUTERNAME}\${Username}" -AccessRight Change -Force -ErrorAction SilentlyContinue | Out-Null
}

function Ensure-QuicCertificate {
    param(
        [string]$Name,
        [string]$FriendlyName,
        [string]$ExportPath
    )

    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -match "CN=${Name}$" } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($null -eq $cert) {
        $cert = New-SelfSignedCertificate `
            -DnsName $Name `
            -FriendlyName $FriendlyName `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(3) `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
    }

    Export-Certificate -Cert $cert -FilePath $ExportPath -Force | Out-Null
    return $cert
}

function Ensure-QuicMapping {
    param(
        [string]$Name,
        [string]$Thumbprint
    )

    $existing = Get-SmbServerCertificateMapping -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $Name }

    foreach ($mapping in @($existing)) {
        if ($mapping.Thumbprint -ne $Thumbprint) {
            Remove-SmbServerCertificateMapping -Name $mapping.Name -Thumbprint $mapping.Thumbprint -Force -ErrorAction SilentlyContinue
        }
    }

    $current = Get-SmbServerCertificateMapping -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $Name -and $_.Thumbprint -eq $Thumbprint }

    if ($null -eq $current) {
        New-SmbServerCertificateMapping -Name $Name -Thumbprint $Thumbprint -StoreName My | Out-Null
    }
}

function Ensure-QuicFirewall {
    param([int]$Port)

    $ruleName = "Smolder SMB over QUIC ${Port}"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($null -eq $rule) {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol UDP `
            -LocalPort $Port `
            -Action Allow | Out-Null
    }
}

Ensure-Administrator
Ensure-LocalUser -Username $LocalUsername -Password $LocalPassword
Ensure-SharePath -Path $SharePath -Username $LocalUsername
Ensure-SmbShare -Name $ShareName -Path $SharePath -Username $LocalUsername

$serverCert = Ensure-QuicCertificate `
    -Name $ServerName `
    -FriendlyName $CertificateFriendlyName `
    -ExportPath $CertificateExportPath

Ensure-QuicMapping -Name $ServerName -Thumbprint $serverCert.Thumbprint
Set-SmbServerConfiguration -EnableSMBQUIC $true -Force | Out-Null

if ($QuicPort -ne 443 -and (Get-Command Get-SmbServerAlternativePort -ErrorAction SilentlyContinue)) {
    $portMapping = Get-SmbServerAlternativePort -ErrorAction SilentlyContinue |
        Where-Object { $_.TransportType -eq "QUIC" -and $_.Port -eq $QuicPort }
    if ($null -eq $portMapping) {
        New-SmbServerAlternativePort -TransportType QUIC -Port $QuicPort -EnableInstances Default | Out-Null
    }
}

Ensure-QuicFirewall -Port $QuicPort

Write-Host ""
Write-Host "SMB over QUIC server configuration complete."
Write-Host "Server name      : $ServerName"
Write-Host "Share name       : $ShareName"
Write-Host "Share path       : $SharePath"
Write-Host "Local user       : ${env:COMPUTERNAME}\$LocalUsername"
Write-Host "QUIC port        : $QuicPort"
Write-Host "Certificate path : $CertificateExportPath"
Write-Host ""
Write-Host "Next steps on the host:"
Write-Host "1. Copy $CertificateExportPath to the macOS host and trust it in the System keychain."
Write-Host "2. Add a hosts entry for $ServerName pointing at the VM's QUIC-forwarded address."
Write-Host "3. Export:"
Write-Host "   SMOLDER_WINDOWS_QUIC_SERVER=$ServerName"
Write-Host "   SMOLDER_WINDOWS_QUIC_USERNAME=$LocalUsername"
Write-Host "   SMOLDER_WINDOWS_QUIC_PASSWORD=$LocalPassword"
Write-Host "   SMOLDER_WINDOWS_QUIC_SHARE=$ShareName"
Write-Host "4. Run scripts/run-windows-quic-interop.sh from the repo."
