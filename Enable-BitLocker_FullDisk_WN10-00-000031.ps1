<#
.SYNOPSIS
    Enables BitLocker full disk encryption on all fixed drives using password protectors (compliant with WN10-00-000031).

.DESCRIPTION
    This script enables BitLocker encryption on all unencrypted fixed drives using a password protector,
    compliant with the DISA STIG requirement WN10-00-000031 for full disk encryption.

.NOTES
    Author          : Prabhjot Singh
    LinkedIn        : linkedin.com/in/prabhjot-singh-032186294  
    GitHub          : github.com/prinxenadana
    Date Created    : 2025-05-23
    Last Modified   : 2025-05-23
    Version         : 1.0
    STIG-ID         : WN10-00-000031

.TESTED ON
    Date(s) Tested  : 2025-05-23
    Tested By       : Prabhjot Singh
    Systems Tested  : Windows 10 Pro, Windows 11 Pro
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\Enable-BitLocker_FullDisk_WN10-00-000031.ps1
#>

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You must run this script as Administrator."
    exit 1
}

$keyFolder = "C:\BitLockerKeys"
if (-not (Test-Path $keyFolder)) {
    New-Item -Path $keyFolder -ItemType Directory | Out-Null
}

$volumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'FixedData' -or $_.VolumeType -eq 'OperatingSystem' }

foreach ($volume in $volumes) {
    $drive = $volume.MountPoint
    $status = $volume.ProtectionStatus

    if ($status -eq 'On') {
        Write-Host "BitLocker already enabled on $drive"
        continue
    }

    try {
        Write-Host "Enabling BitLocker on $drive..."

        $securePassword = Read-Host -AsSecureString -Prompt "Enter BitLocker password for $drive (min 8 chars)"
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        )

        if ($plainPassword.Length -lt 8) {
            Write-Warning "Password too short. Skipping $drive."
            continue
        }

        # Add password protector if not present
        $existingProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Password' }
        if (-not $existingProtector) {
            Add-BitLockerKeyProtector -MountPoint $drive -PasswordProtector -Password $securePassword | Out-Null
        }

        # Enable BitLocker
        Enable-BitLocker -MountPoint $drive -EncryptionMethod XtsAes256 -UsedSpaceOnly -PasswordProtector

        # Save recovery key
        $recoveryProtector = (Get-BitLockerVolume -MountPoint $drive).KeyProtector |
            Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1

        $keyFile = Join-Path $keyFolder "BitLockerKey_$($drive.TrimEnd(':')).txt"
        @(
            "Drive: $drive"
            "Recovery Key: $($recoveryProtector.RecoveryPassword)"
            "Date: $(Get-Date -Format u)"
        ) | Out-File -FilePath $keyFile -Encoding UTF8

        Write-Host "BitLocker enabled on $drive. Recovery key saved to $keyFile"
    } catch {
        Write-Error "Failed to enable BitLocker on ${drive}: $_"
    }
}
