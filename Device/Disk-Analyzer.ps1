<# 
.SYNOPSIS
  Safe disk "waste" analyzer for Windows. Produces an HTML report and (optionally) a -WhatIf cleanup plan.
.DESCRIPTION
  Read-only scan for common reclaimable space: temp folders, browser caches, Windows Update cache, Recycle Bin, Windows.old,
  crash dumps, thumbnail caches, large/old files, optional DISM analysis, optional duplicate scan, and optional parity with
  Disk Cleanup "system files" (Delivery Optimization cache, WER, Panther/CBS logs, upgrade leftovers, ESD packages; DriverStore/Defender reported only).

.NOTES
  Analyzer never deletes; plan is preview-only with -WhatIf. Prefer elevated session for full visibility.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]] $Drives = @([System.IO.Path]::GetPathRoot($env:SystemDrive)),

    [ValidateRange(1,3650)]
    [int] $AgeDays = 30,

    [ValidateRange(1,524288)] # up to 512GB
    [int] $LargeFileMinMB = 512,

    [switch] $IncludeDupScan,
    [switch] $IncludeDismAnalysis,
    [switch] $IncludeSystemFileParity,

    [string] $ReportPath,

    [switch] $GenerateCleanupPlan,
    [string] $PlanPath
)

#region Helpers
function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    elseif ($Bytes -lt 1MB) { return "{0:N2} KB" -f ($Bytes/1KB) }
    elseif ($Bytes -lt 1GB) { return "{0:N2} MB" -f ($Bytes/1MB) }
    elseif ($Bytes -lt 1TB) { return "{0:N2} GB" -f ($Bytes/1GB) }
    else { return "{0:N2} TB" -f ($Bytes/1TB) }
}

function Try-MeasurePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$OlderThanDays = 0,
        [string[]]$Include = @('*'),
        [switch]$Recurse
    )
    # Ensure -Include is effective by defaulting to recurse when caller didn’t specify
    if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

    $result = [PSCustomObject]@{
        Path   = $Path
        Exists = $false
        Count  = 0
        Bytes  = 0L
        Error  = $null
    }
    try {
        if (Test-Path -LiteralPath $Path) {
            $result.Exists = $true

            # Use -Include when recursing; otherwise use -Filter to avoid full enumeration cost
            if ($Recurse) {
                $items = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop -Include $Include -Recurse
            } else {
                $filter = ($Include -and $Include.Count -eq 1) ? $Include[0] : $null
                if ($filter) {
                    $items = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop -Filter $filter
                } else {
                    $items = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop
                }
            }

            if ($OlderThanDays -gt 0) {
                $cutoff = (Get-Date).AddDays(-$OlderThanDays)
                $items = $items | Where-Object { $_.LastWriteTime -lt $cutoff }
            }
            $m = $items | Measure-Object -Sum Length
            $result.Count = $m.Count
            $result.Bytes = [long]$m.Sum
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-UserProfileRoots {
    Get-ChildItem "C:\Users" -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer -and $_.Name -notin @('Public','Default','Default User','All Users') } |
        Select-Object -Expand FullName
}

function New-Finding {
    param(
        [string]$Category,
        [string]$Path,
        [string]$Item,
        [long]$SizeBytes,
        [int]$Age,
        [string]$RecommendedAction,
        [string]$PlanCommand,
        [ValidateSet('High','Medium','Low')][string]$Confidence = 'High',
        [string]$Notes
    )
    [PSCustomObject]@{
        Category          = $Category
        Path              = $Path
        Item              = $Item
        SizeBytes         = $SizeBytes
        Size              = Format-Size $SizeBytes
        AgeDays           = $Age
        RecommendedAction = $RecommendedAction
        Confidence        = $Confidence
        PlanCommand       = $PlanCommand
        Notes             = $Notes
    }
}

# Safely add to findings and plan
function Add-Finding {
    param([Parameter(Mandatory)][psobject]$Finding)
    $script:findings.Add($Finding) | Out-Null
    if ($Finding.PlanCommand -and $Finding.PlanCommand.Trim().Length -gt 0) {
        $script:PlanCommands.Add($Finding.PlanCommand) | Out-Null
    }
}

# More accurate Recycle Bin size (no admin required)
function Get-RecycleBinBytes {
    try {
        $shell = New-Object -ComObject Shell.Application
        $rb    = $shell.Namespace(10)  # Recycle Bin
        if (-not $rb) { return 0L }
        $bytes = 0L
        $rb.Items() | ForEach-Object {
            $sz = $_.ExtendedProperty("Size")
            if ($sz -is [ValueType]) { $bytes += [int64]$sz }
        }
        return $bytes
    } catch { return 0L }
}
#endregion Helpers

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[object]
$now = Get-Date
$admin = Test-Admin

# Validate drives and determine Windows system drive
$validDrives = $Drives | ForEach-Object { ($_ -replace '[\\/]*$','') + '\' } | Where-Object { Test-Path $_ } | Select-Object -Unique
if (-not $validDrives) { $validDrives = @([System.IO.Path]::GetPathRoot($env:SystemDrive)) }
$windowsDrive = Split-Path -Path $env:WINDIR -Qualifier

# Report path with fallback
if (-not $ReportPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $publicDocs = Join-Path "$env:PUBLIC\Documents" .
    $baseDir = (Test-Path $publicDocs) ? $publicDocs : [Environment]::GetFolderPath('MyDocuments')
    $ReportPath = Join-Path $baseDir ("DiskWasteReport_{0}_{1}.html" -f $env:COMPUTERNAME, $ts)
}
if ($GenerateCleanupPlan -and -not $PlanPath) {
    $PlanPath = [System.IO.Path]::ChangeExtension($ReportPath, ".plan.ps1")
}
$PlanCommands = New-Object System.Collections.Generic.List[string]

Write-Verbose "Admin: $admin"
Write-Host "Scanning... (read-only) This may take a few minutes."

#region Categories

# 1) Temp folders (Windows + per-user)
$globalTempTargets = @((Join-Path $windowsDrive "Windows\Temp"), (Join-Path $windowsDrive "ProgramData\Temp"))
foreach ($t in $globalTempTargets) {
    $res = Try-MeasurePath -Path $t -OlderThanDays $AgeDays
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Temp (System)' -Path $t -Item 'Files older than threshold' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear older temp files." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -File -Force -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $t,$AgeDays) `
            -Confidence High)
    }
}

# Per-user Temp
foreach ($u in Get-UserProfileRoots) {
    $t = Join-Path $u "AppData\Local\Temp"
    $res = Try-MeasurePath -Path $t -OlderThanDays $AgeDays
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Temp (User)' -Path $t -Item 'Files older than threshold' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear older temp files for this user." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -File -Force -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $t,$AgeDays) `
            -Confidence High)
    }
}

# 2) Browser caches (Chrome/Edge/Firefox)
$browserTargets = @()
foreach ($u in Get-UserProfileRoots) {
    $local = Join-Path $u "AppData\Local"
    $roam  = Join-Path $u "AppData\Roaming"
    $browserTargets += @(
        Join-Path $local "Google\Chrome\User Data\*\Cache\*"
        Join-Path $local "Google\Chrome\User Data\*\Code Cache\*"
        Join-Path $local "Microsoft\Edge\User Data\*\Cache\*"
        Join-Path $local "Microsoft\Edge\User Data\*\Code Cache\*"
        Join-Path $roam  "Mozilla\Firefox\Profiles\*\cache2\*"
    )
}
$browserTargets = $browserTargets | Select-Object -Unique
foreach ($mask in $browserTargets) {
    foreach ($path in (Resolve-Path $mask -ErrorAction SilentlyContinue)) {
        $res = Try-MeasurePath -Path $path.Path
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Browser Cache' -Path $path.Path -Item 'Cache content' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Usually safe to clear; browsers will recreate." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf -ErrorAction SilentlyContinue" -f $path.Path) `
                -Confidence High)
        }
    }
}

# 3) Windows Update cache (Windows volume only)
$wu = Join-Path $windowsDrive "Windows\SoftwareDistribution\Download"
$res = Try-MeasurePath -Path $wu
if ($res.Exists -and $res.Bytes -gt 0) {
    $planWU = @"
# Stop services to safely clear Windows Update cache
Stop-Service DoSvc -Force -ErrorAction SilentlyContinue
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service bits -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-ChildItem -LiteralPath '$wu' -Force -Recurse | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue
# Restart services
Start-Service bits -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue
Start-Service DoSvc -ErrorAction SilentlyContinue
"@
    Add-Finding (New-Finding -Category 'Windows Update Cache' -Path $wu -Item 'Cached update payloads' `
        -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear when Windows Update is stopped." `
        -PlanCommand $planWU -Confidence High)
}

# 4) Recycle Bin (per machine – accurate shell size)
$rbBytes = Get-RecycleBinBytes
if ($rbBytes -gt 0) {
    Add-Finding (New-Finding -Category 'Recycle Bin' -Path 'Recycle Bin' -Item 'Deleted items' `
        -SizeBytes $rbBytes -Age 0 -RecommendedAction "Empty Recycle Bin to reclaim space." `
        -PlanCommand "Clear-RecycleBin -Force -WhatIf" -Confidence High)
} else {
    Add-Finding (New-Finding -Category 'Recycle Bin' -Path 'Recycle Bin' -Item 'No measurable items or access denied' `
        -SizeBytes 0 -Age 0 -RecommendedAction "If you expect items, run from an interactive user session." `
        -PlanCommand "Clear-RecycleBin -Force -WhatIf" -Confidence Medium)
}

# 5) Windows.old (Windows volume only)
$wo = Join-Path $windowsDrive "Windows.old"
$res = Try-MeasurePath -Path $wo
if ($res.Exists -and $res.Bytes -gt 0) {
    Add-Finding (New-Finding -Category 'Previous Windows (Windows.old)' -Path $wo -Item 'Previous installation' `
        -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Use Disk Cleanup/Storage Sense to remove safely." `
        -PlanCommand "# Recommended via Settings > System > Storage > Temporary files (Windows.old)" `
        -Confidence High -Notes 'Manual removal can be blocked; use built-in cleanup')
}

# 6) Crash dumps
$memDump = Join-Path $windowsDrive "Windows\MEMORY.DMP"
if (Test-Path $memDump) {
    try {
        $fi = Get-Item $memDump -Force
        Add-Finding (New-Finding -Category 'Crash Dumps' -Path $memDump -Item 'Kernel memory dump' `
            -SizeBytes $fi.Length -Age ([int]((New-TimeSpan -Start $fi.LastWriteTime -End $now).TotalDays)) `
            -RecommendedAction "Usually safe to delete if no longer needed for analysis." `
            -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf -ErrorAction SilentlyContinue" -f $memDump) -Confidence High)
    } catch {}
}
$miniDump = Join-Path $windowsDrive "Windows\Minidump"
$res = Try-MeasurePath -Path $miniDump
if ($res.Exists -and $res.Bytes -gt 0) {
    Add-Finding (New-Finding -Category 'Crash Dumps' -Path $miniDump -Item 'Minidumps' `
        -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to delete if no longer needed." `
        -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf -ErrorAction SilentlyContinue" -f $miniDump) -Confidence High)
}

# 7) Thumbnail caches
foreach ($u in Get-UserProfileRoots) {
    $thumb = Join-Path $u "AppData\Local\Microsoft\Windows\Explorer"
    $res = Try-MeasurePath -Path $thumb -Include @('thumbcache*')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Thumbnail Cache' -Path $thumb -Item 'thumbcache*' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear; Windows will regenerate." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Filter 'thumbcache*' | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $thumb) -Confidence High)
    }
}

# 8) Large/old files in common user locations
$profileSets = @('Downloads','Desktop','Documents','Videos')
foreach ($u in Get-UserProfileRoots) {
    foreach ($set in $profileSets) {
        $p = Join-Path $u $set
        if (Test-Path $p) {
            try {
                $cutoff = (Get-Date).AddDays(-$AgeDays)
                $files = Get-ChildItem -LiteralPath $p -File -Force -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge ($LargeFileMinMB * 1MB) -and $_.LastWriteTime -lt $cutoff }
                foreach ($f in $files) {
                    Add-Finding (New-Finding -Category "Large/Old Files ($set)" -Path $f.DirectoryName -Item $f.Name `
                        -SizeBytes $f.Length -Age ([int]((New-TimeSpan -Start $f.LastWriteTime -End $now).TotalDays)) `
                        -RecommendedAction "Review & delete/move/archive if not needed." `
                        -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf -ErrorAction SilentlyContinue" -f $f.FullName) -Confidence Medium)
                }
            } catch {}
        }
    }
}

# 9) Old installers in Downloads (.iso/.msi/.exe/.zip/.7z)
foreach ($u in Get-UserProfileRoots) {
    $dl = Join-Path $u "Downloads"
    if (Test-Path $dl) {
        $cutoff = (Get-Date).AddDays(-$AgeDays)
        $exts = @('*.iso','*.msi','*.exe','*.zip','*.7z')
        try {
            $files = Get-ChildItem -LiteralPath $dl -File -Force -Recurse -Include $exts -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff }
            foreach ($f in $files) {
                Add-Finding (New-Finding -Category 'Old Installers (Downloads)' -Path $f.DirectoryName -Item $f.Name `
                    -SizeBytes $f.Length -Age ([int]((New-TimeSpan -Start $f.LastWriteTime -End $now).TotalDays)) `
                    -RecommendedAction "Review & delete if no longer needed." `
                    -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf -ErrorAction SilentlyContinue" -f $f.FullName) -Confidence Medium)
            }
        } catch {}
    }
}

# 10) DISM Component Store analysis (WinSxS) – estimate only
if ($IncludeDismAnalysis) {
    if ($admin) {
        try {
            $tmpOut = [IO.Path]::GetTempFileName()
            Start-Process -FilePath dism.exe -ArgumentList "/Online","/Cleanup-Image","/AnalyzeComponentStore" `
                -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -Wait | Out-Null
            $out = Get-Content -LiteralPath $tmpOut -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue

            $recoLine = ($out | Select-String -Pattern 'Recommended Cleanup\s*:\s*(Yes|No)' -AllMatches | Select-Object -Last 1).Matches.Value
            $wxsSize  = ($out | Select-String -Pattern 'WinSxS Directory Size\s*:\s*(.+)$' | Select-Object -Last 1).Matches.Groups[1].Value
            $notes = "Recommended: $recoLine; WinSxS size: $wxsSize"

            Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path (Join-Path $windowsDrive 'Windows\WinSxS') -Item 'DISM analysis' `
                -SizeBytes 0 -Age 0 -RecommendedAction "If recommended, run 'DISM /Online /Cleanup-Image /StartComponentCleanup'." `
                -PlanCommand "# DISM cleanup (preview-only): DISM /Online /Cleanup-Image /StartComponentCleanup" `
                -Confidence High -Notes $notes)
        } catch {
            Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path (Join-Path $windowsDrive 'Windows\WinSxS') -Item 'DISM analysis failed' `
                -SizeBytes 0 -Age 0 -RecommendedAction "Run elevated PowerShell/Terminal and retry." `
                -PlanCommand "" -Confidence Low -Notes $_.Exception.Message)
        }
    } else {
        Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path (Join-Path $windowsDrive 'Windows\WinSxS') -Item 'Admin required' `
            -SizeBytes 0 -Age 0 -RecommendedAction "Run elevated to analyze with DISM." `
            -PlanCommand "" -Confidence Medium)
    }
}

# 11) System Restore / VSS usage (estimate)
if ($admin) {
    try {
        $vss = (vssadmin list shadowstorage) 2>$null
        if ($vss) {
            $used = ($vss | Select-String -Pattern 'Used Shadow Copy Storage space:').Line -join '; '
            $alloc= ($vss | Select-String -Pattern 'Allocated Shadow Copy Storage space:').Line -join '; '
            $max  = ($vss | Select-String -Pattern 'Maximum Shadow Copy Storage space:').Line -join '; '
            Add-Finding (New-Finding -Category 'System Restore (VSS)' -Path 'ShadowStorage' -Item 'Allocated space' `
                -SizeBytes 0 -Age 0 -RecommendedAction "Consider reducing System Protection size if very large." `
                -PlanCommand "# Adjust via System Protection GUI; not scripted here for safety." `
                -Confidence Medium -Notes ("{0}; {1}; {2}" -f $used,$alloc,$max))
        }
    } catch {}
} else {
    Add-Finding (New-Finding -Category 'System Restore (VSS)' -Path 'ShadowStorage' -Item 'Admin recommended' `
        -SizeBytes 0 -Age 0 -RecommendedAction "Run elevated to query VSS usage." `
        -PlanCommand "" -Confidence Low)
}

# 12) Optional duplicate scan (size-grouped, then hash)
if ($IncludeDupScan) {
    $contentRoots = @()
    foreach ($u in Get-UserProfileRoots) {
        $contentRoots += @(
            Join-Path $u 'Documents'
            Join-Path $u 'Desktop'
            Join-Path $u 'Downloads'
            Join-Path $u 'Pictures'
            Join-Path $u 'Videos'
        )
    }
    $contentRoots = $contentRoots | Where-Object { Test-Path $_ } | Select-Object -Unique
    Write-Host "Duplicate scan: hashing files >= $LargeFileMinMB MB. This may take a while..."

    $files = foreach ($root in $contentRoots) {
        Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -ge ($LargeFileMinMB * 1MB) }
    }

    $byLen = $files | Group-Object Length | Where-Object { $_.Count -gt 1 }

    $hashTable = @{}
    foreach ($grp in $byLen) {
        foreach ($f in $grp.Group) {
            try {
                # SHA1 is adequate and faster for dedupe
                $h = Get-FileHash -Algorithm SHA1 -LiteralPath $f.FullName -ErrorAction Stop
                if (-not $hashTable.ContainsKey($h.Hash)) { $hashTable[$h.Hash] = New-Object System.Collections.Generic.List[object] }
                $hashTable[$h.Hash].Add($f)
            } catch {}
        }
    }
    foreach ($k in $hashTable.Keys) {
        $filesDup = $hashTable[$k]
        if ($filesDup.Count -gt 1) {
            $ordered = $filesDup | Sort-Object Length -Descending
            $savings = ($ordered | Select-Object -Skip 1 | Measure-Object -Sum Length).Sum
            if ($savings -gt 0) {
                $list = ($ordered | ForEach-Object { $_.FullName }) -join "`n"
                Add-Finding (New-Finding -Category 'Duplicates (hash match)' -Path 'various' -Item ("{0} duplicates" -f $filesDup.Count) `
                    -SizeBytes $savings -Age 0 -RecommendedAction "Review duplicates and remove extras." `
                    -PlanCommand "# Manually review duplicates:`n# $list" -Confidence Medium)
            }
        }
    }
}

# 13) Disk Cleanup / Storage Sense "system files" parity (read-only)
if ($IncludeSystemFileParity) {
    # Delivery Optimization cache
    $doCache = Join-Path $windowsDrive "ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"
    $res = Try-MeasurePath -Path $doCache
    if ($res.Exists -and $res.Bytes -gt 0) {
        $planDO = @"
Stop-Service DoSvc -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '$doCache' -Recurse -Force -WhatIf -ErrorAction SilentlyContinue
Start-Service DoSvc -ErrorAction SilentlyContinue
"@
        Add-Finding (New-Finding -Category 'Delivery Optimization' -Path $doCache -Item 'DO cache' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Usually safe to clear; Windows will re-fetch." `
            -PlanCommand $planDO -Confidence High)
    }

    # Windows Error Reporting (WER)
    $werPaths = @(
        (Join-Path $windowsDrive "ProgramData\Microsoft\Windows\WER\ReportArchive"),
        (Join-Path $windowsDrive "ProgramData\Microsoft\Windows\WER\ReportQueue")
    )
    foreach ($p in $werPaths) {
        $res = Try-MeasurePath -Path $p
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows Error Reporting' -Path $p -Item 'WER reports' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear error report archives." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf -ErrorAction SilentlyContinue" -f $p) -Confidence High)
        }
    }

    # Windows upgrade leftovers ($WINDOWS.~BT / $WINDOWS.~WS) and Panther logs
    $upgradeRoots = @((Join-Path $windowsDrive '$WINDOWS.~BT'), (Join-Path $windowsDrive '$WINDOWS.~WS'))
    foreach ($p in $upgradeRoots) {
        $res = Try-MeasurePath -Path $p -OlderThanDays $AgeDays
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows Upgrade Leftovers' -Path $p -Item 'Old setup files' `
                -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to remove if no upgrade is pending." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf -ErrorAction SilentlyContinue" -f $p) -Confidence Medium `
                -Notes 'Ensure no pending upgrades / rollback needed')
        }
    }
    $panther = Join-Path $windowsDrive "Windows\Panther"
    $res = Try-MeasurePath -Path $panther -OlderThanDays $AgeDays -Include @('*.log','*.etl','*.cab')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Setup Logs (Panther)' -Path $panther -Item 'Old setup logs' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear old setup logs." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.log,*.etl,*.cab | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $panther,$AgeDays) `
            -Confidence High)
    }

    # CBS logs (Windows servicing)
    $cbs = Join-Path $windowsDrive "Windows\Logs\CBS"
    $res = Try-MeasurePath -Path $cbs -OlderThanDays $AgeDays -Include @('*.log','*.cab')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Servicing Logs (CBS)' -Path $cbs -Item 'Old CBS logs' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear old CBS logs when not troubleshooting." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.log,*.cab | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $cbs,$AgeDays) `
            -Confidence High)
    }

    # ESD installation files
    $esdRoots = @((Join-Path $windowsDrive 'ESD'), (Join-Path $windowsDrive '$WINDOWS.~BT\Sources'))
    foreach ($p in $esdRoots) {
        $res = Try-MeasurePath -Path $p -Include @('*.esd')
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows ESD Packages' -Path $p -Item '*.esd' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Review before removal; used for repair/upgrade." `
                -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.esd | Remove-Item -Force -WhatIf -ErrorAction SilentlyContinue" -f $p) `
                -Confidence Medium -Notes 'Only remove if you have media or won’t need in-place repair')
        }
    }

    # Defender definitions cache (report-only)
    $defCache = Join-Path $windowsDrive "ProgramData\Microsoft\Windows Defender\Definition Updates"
    $res = Try-MeasurePath -Path $defCache
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Defender Definitions' -Path $defCache -Item 'Definition cache' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Let Defender manage; avoid manual deletion." `
            -PlanCommand "" -Confidence Low -Notes 'Managed by platform updates; informational only')
    }

    # Device driver packages (DriverStore) – report-only; removal is risky
    $driverStore = Join-Path $windowsDrive "Windows\System32\DriverStore\FileRepository"
    $res = Try-MeasurePath -Path $driverStore
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'DriverStore' -Path $driverStore -Item 'Driver packages' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Use Disk Cleanup or vendor tools; do not delete manually." `
            -PlanCommand "# To review third-party drivers: pnputil /enum-drivers | more" -Confidence Low)
    }
}
#endregion Categories

# Aggregate & output
$totalBytes = ($findings | Measure-Object -Sum SizeBytes).Sum
if (-not $totalBytes) { $totalBytes = 0 }

$style = @'
<style>
body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
h1,h2 { font-weight: 600; }
.summary { margin: 12px 0 24px 0; padding: 12px 16px; border-left: 4px solid #4b8; background: #f6fffa; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f4f6; text-align: left; }
tr:nth-child(even) { background: #fafafa; }
.code { font-family: Consolas, monospace; white-space: pre-wrap; background: #f8f8f8; padding: 8px; border-radius: 6px; }
.note { color: #555; font-size: 0.95em; }
.badge { display:inline-block; padding:2px 8px; border-radius:12px; background:#eef; font-size:0.85em; }
</style>
'@

$header = @"
<h1>Safe Disk Waste Analyzer</h1>
<div class='summary'>
  <div><b>Computer:</b> $env:COMPUTERNAME</div>
  <div><b>Run time:</b> $now</div>
  <div><b>Admin:</b> $admin</div>
  <div><b>Parameters:</b> Drives=$($validDrives -join ', '); AgeDays=$AgeDays; LargeFileMinMB=$LargeFileMinMB; Duplicates=$IncludeDupScan; DISM=$IncludeDismAnalysis; SystemParity=$IncludeSystemFileParity</div>
  <div><b>Potentially reclaimable (estimate):</b> $(Format-Size $totalBytes)</div>
</div>
"@

$reportTable = $findings |
    Select-Object Category, Path, Item, Size, AgeDays, Confidence, RecommendedAction, Notes,
                  @{n='PlanCommand';e={ $_.PlanCommand -replace '<','&lt;' -replace '>','&gt;' }} |
    ConvertTo-Html -As Table -Fragment

$html = ConvertTo-Html -Head $style -Body ($header + $reportTable)

# Write report
$html | Out-File -LiteralPath $ReportPath -Encoding UTF8
Write-Output "Report written to: $ReportPath"

# Optional cleanup plan (all -WhatIf)
if ($GenerateCleanupPlan) {
    $planHeader = @"
# Cleanup Plan (Preview-Only)
# Generated: $(Get-Date)
# Computer: $env:COMPUTERNAME
# All commands below include -WhatIf for safety. Review first; remove -WhatIf if/when you decide to execute.
# Recommended: Create a Restore Point and close apps before running any cleanup.
"@
    $planContent = ($PlanCommands | Where-Object { $_ } | Select-Object -Unique) -join "`r`n"
    ($planHeader + "`r`n" + $planContent + "`r`n") | Out-File -LiteralPath $PlanPath -Encoding UTF8
    Write-Output "Preview cleanup plan written to: $PlanPath"
}

# Final console summary
("{0} findings. Estimated reclaimable: {1}" -f $findings.Count, (Format-Size $totalBytes)) | Write-Output

# Emit pipeline object for automation/testing
$result = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    RunAt        = $now
    IsAdmin      = $admin
    Parameters   = [PSCustomObject]@{
        Drives               = $validDrives
        AgeDays              = $AgeDays
        LargeFileMinMB       = $LargeFileMinMB
        IncludeDupScan       = [bool]$IncludeDupScan
        IncludeDismAnalysis  = [bool]$IncludeDismAnalysis
        IncludeSystemFileParity = [bool]$IncludeSystemFileParity
    }
    Findings     = $findings
    TotalBytes   = $totalBytes
    ReportPath   = $ReportPath
    PlanPath     = $GenerateCleanupPlan ? $PlanPath : $null
}
$result