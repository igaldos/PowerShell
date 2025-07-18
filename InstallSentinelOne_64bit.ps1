<#
.SYNOPSIS
    Installs the SentinelOne agent silently, with detailed logging and optional download.

.AUTHOR
    Ignacio Galdos

.NOTES
    Date: July 18, 2025
    - Creates or verifies the install directory.
    - Uses Start-Transcript for unified logging to install.log.
    - Downloads the installer only if not already present.
    - Checks for 64‑bit OS before proceeding.
#>

function Install-SentinelOne {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteToken,

        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$DownloadUrl = '', # Add your 64-bit Agent.exe download url here (version 22.2+), should look like 'https://mypublic-url.com'

        [Parameter(Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$InstallDir = 'C:\temp\SentinelOneInstaller'
    )

    Begin {
        if ($PSCmdlet.ShouldProcess("Create or verify directory $InstallDir")) {
            New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
            if ($PSBoundParameters.Verbose) {
                Start-Transcript -Path (Join-Path $InstallDir 'install.log') -Append
            }
        }
    }

    Process {
        # OS architecture check
        $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        Write-Verbose "Detected OS Architecture: $arch"
        if ($arch -ne '64-bit') {
            Write-Warning "Unsupported OS architecture: $arch"
            return
        }

        # Download installer if not present
        $installer = Join-Path $InstallDir 'SentinelOneInstaller.exe'
        if (-not (Test-Path $installer)) {
            Write-Verbose "Downloading installer from $DownloadUrl"
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $installer -UseBasicParsing
        }
        else {
            Write-Verbose "Installer already exists; skipping download"
        }

        # Run installer
        $args = "--qn", "-t", $SiteToken
        Write-Verbose "Running: $installer $($args -join ' ')"
        $p = Start-Process -FilePath $installer -ArgumentList $args -PassThru -Wait
        if ($p.ExitCode -ne 0) {
            Throw "Installation failed with exit code $($p.ExitCode)"
        }
        Write-Verbose "Installation succeeded"
    }

    End {
        if ($PSBoundParameters.Verbose) {
            Stop-Transcript
        }
    }
}
