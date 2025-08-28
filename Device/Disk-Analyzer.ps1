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

    [int] $AgeDays = 30,
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
            $items = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop -Include $Include -Recurse:$Recurse
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
#endregion Helpers

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[object]
$now = Get-Date
$admin = Test-Admin

if (-not $ReportPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path "$env:PUBLIC\Documents" ("DiskWasteReport_{0}_{1}.html" -f $env:COMPUTERNAME, $ts)
}
if ($GenerateCleanupPlan -and -not $PlanPath) {
    $PlanPath = [System.IO.Path]::ChangeExtension($ReportPath, ".plan.ps1")
}
$PlanCommands = New-Object System.Collections.Generic.List[string]

Write-Verbose "Admin: $admin"
Write-Host "Scanning... (read-only) This may take a few minutes."

#region Categories

# 1) Temp folders (Windows + per-user)
$globalTempTargets = @("C:\Windows\Temp","$env:ProgramData\Temp")
foreach ($t in $globalTempTargets) {
    $res = Try-MeasurePath -Path $t -OlderThanDays $AgeDays -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Temp (System)' -Path $t -Item 'Files older than threshold' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear older temp files." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -File -Force -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf" -f $t,$AgeDays) `
            -Confidence High)
    }
}

# Per-user Temp
foreach ($u in Get-UserProfileRoots) {
    $t = Join-Path $u "AppData\Local\Temp"
    $res = Try-MeasurePath -Path $t -OlderThanDays $AgeDays -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Temp (User)' -Path $t -Item 'Files older than threshold' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear older temp files for this user." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -File -Force -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf" -f $t,$AgeDays) `
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
        $res = Try-MeasurePath -Path $path.Path -Recurse
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Browser Cache' -Path $path.Path -Item 'Cache content' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Usually safe to clear; browsers will recreate." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf" -f $path.Path) `
                -Confidence High)
        }
    }
}

# 3) Windows Update cache
foreach ($d in $Drives) {
    $wu = Join-Path $d "Windows\SoftwareDistribution\Download"
    $res = Try-MeasurePath -Path $wu -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        $planWU = ("Stop-Service wuauserv,bits -Force -ErrorAction SilentlyContinue`n" +
                   ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse | Remove-Item -Force -WhatIf`n" -f $wu) +
                   "Start-Service wuauserv,bits")
        Add-Finding (New-Finding -Category 'Windows Update Cache' -Path $wu -Item 'Cached update payloads' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear when Windows Update is stopped." `
            -PlanCommand $planWU -Confidence High)
    }
}

# 4) Recycle Bin (per drive)
if ($admin) {
    foreach ($d in $Drives) {
        try {
            $rb = Join-Path $d '$Recycle.Bin'
            $res = Try-MeasurePath -Path $rb -Recurse
            if ($res.Exists -and $res.Bytes -gt 0) {
                Add-Finding (New-Finding -Category 'Recycle Bin' -Path $rb -Item 'Deleted items' `
                    -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Empty Recycle Bin to reclaim space." `
                    -PlanCommand "Clear-RecycleBin -Force -WhatIf" -Confidence High)
            }
        } catch {}
    }
} else {
    Add-Finding (New-Finding -Category 'Recycle Bin' -Path 'N/A' -Item 'Admin recommended' `
        -SizeBytes 0 -Age 0 -RecommendedAction "Run elevated to estimate and empty Recycle Bin." `
        -PlanCommand "Clear-RecycleBin -Force -WhatIf" -Confidence Medium -Notes 'Admin rights needed for accurate size')
}

# 5) Windows.old
foreach ($d in $Drives) {
    $wo = Join-Path $d "Windows.old"
    $res = Try-MeasurePath -Path $wo -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Previous Windows (Windows.old)' -Path $wo -Item 'Previous installation' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Use Disk Cleanup/Storage Sense to remove safely." `
            -PlanCommand "# Recommended via Settings > System > Storage > Temporary files (Windows.old)" `
            -Confidence High -Notes 'Manual removal can be blocked; use built-in cleanup')
    }
}

# 6) Crash dumps
$memDump = "C:\Windows\MEMORY.DMP"
if (Test-Path $memDump) {
    try {
        $fi = Get-Item $memDump -Force
        Add-Finding (New-Finding -Category 'Crash Dumps' -Path $memDump -Item 'Kernel memory dump' `
            -SizeBytes $fi.Length -Age ([int]((New-TimeSpan -Start $fi.LastWriteTime -End $now).TotalDays)) `
            -RecommendedAction "Usually safe to delete if no longer needed for analysis." `
            -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf" -f $memDump) -Confidence High)
    } catch {}
}
$miniDump = "C:\Windows\Minidump"
$res = Try-MeasurePath -Path $miniDump -Recurse
if ($res.Exists -and $res.Bytes -gt 0) {
    Add-Finding (New-Finding -Category 'Crash Dumps' -Path $miniDump -Item 'Minidumps' `
        -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to delete if no longer needed." `
        -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf" -f $miniDump) -Confidence High)
}

# 7) Thumbnail caches
foreach ($u in Get-UserProfileRoots) {
    $thumb = Join-Path $u "AppData\Local\Microsoft\Windows\Explorer"
    $res = Try-MeasurePath -Path $thumb -Recurse -Include @('thumbcache*')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Thumbnail Cache' -Path $thumb -Item 'thumbcache*' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear; Windows will regenerate." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Filter 'thumbcache*' | Remove-Item -Force -WhatIf" -f $thumb) -Confidence High)
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
                        -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf" -f $f.FullName) -Confidence Medium)
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
                    -PlanCommand ("Remove-Item -LiteralPath '{0}' -Force -WhatIf" -f $f.FullName) -Confidence Medium)
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

            $potential = ($out | Select-String -Pattern 'Recommended Cleanup\s*:\s*(Yes|No)').Matches.Value -join '; '
            $sizeLine  = ($out | Select-String -Pattern 'WinSxS Directory Size|Cache.*Size|Size\s*:\s*').Line -join '; '
            Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path 'C:\Windows\WinSxS' -Item 'DISM analysis' `
                -SizeBytes 0 -Age 0 -RecommendedAction "If recommended, run 'DISM /Online /Cleanup-Image /StartComponentCleanup'." `
                -PlanCommand "# DISM cleanup (preview-only): DISM /Online /Cleanup-Image /StartComponentCleanup" `
                -Confidence High -Notes ("{0}; {1}" -f $potential,$sizeLine))
        } catch {
            Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path 'C:\Windows\WinSxS' -Item 'DISM analysis failed' `
                -SizeBytes 0 -Age 0 -RecommendedAction "Run elevated PowerShell/Terminal and retry." `
                -PlanCommand "" -Confidence Low -Notes $_.Exception.Message)
        }
    } else {
        Add-Finding (New-Finding -Category 'Component Store (WinSxS)' -Path 'C:\Windows\WinSxS' -Item 'Admin required' `
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

# 12) Optional duplicate scan (hash-based)
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
    $hashTable = @{}
    foreach ($root in $contentRoots) {
        try {
            Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -ge ($LargeFileMinMB * 1MB) } |
                ForEach-Object {
                    try {
                        $h = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName -ErrorAction Stop
                        if (-not $hashTable.ContainsKey($h.Hash)) { $hashTable[$h.Hash] = New-Object System.Collections.Generic.List[object] }
                        $hashTable[$h.Hash].Add($_)
                    } catch {}
                }
        } catch {}
    }
    foreach ($k in $hashTable.Keys) {
        $files = $hashTable[$k]
        if ($files.Count -gt 1) {
            $ordered = $files | Sort-Object Length -Descending
            $savings = ($ordered | Select-Object -Skip 1 | Measure-Object -Sum Length).Sum
            if ($savings -gt 0) {
                $list = ($ordered | ForEach-Object { $_.FullName }) -join "`n"
                Add-Finding (New-Finding -Category 'Duplicates (hash match)' -Path 'various' -Item ("{0} duplicates" -f $files.Count) `
                    -SizeBytes $savings -Age 0 -RecommendedAction "Review duplicates and remove extras." `
                    -PlanCommand "# Manually review duplicates:`n# $list" -Confidence Medium)
            }
        }
    }
}

# 13) Disk Cleanup / Storage Sense "system files" parity (read-only)
if ($IncludeSystemFileParity) {
    # Delivery Optimization cache
    $doCache = "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"
    $res = Try-MeasurePath -Path $doCache -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        $planDO = ("Stop-Service DoSvc -Force -ErrorAction SilentlyContinue`n" +
                   ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf`n" -f $doCache) +
                   "Start-Service DoSvc -ErrorAction SilentlyContinue")
        Add-Finding (New-Finding -Category 'Delivery Optimization' -Path $doCache -Item 'DO cache' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Usually safe to clear; Windows will re-fetch." `
            -PlanCommand $planDO -Confidence High)
    }

    # Windows Error Reporting (WER)
    $werPaths = @("C:\ProgramData\Microsoft\Windows\WER\ReportArchive","C:\ProgramData\Microsoft\Windows\WER\ReportQueue")
    foreach ($p in $werPaths) {
        $res = Try-MeasurePath -Path $p -Recurse
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows Error Reporting' -Path $p -Item 'WER reports' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Safe to clear error report archives." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf" -f $p) -Confidence High)
        }
    }

    # Windows upgrade leftovers ($WINDOWS.~BT / $WINDOWS.~WS) and Panther logs
    $upgradeRoots = @('C:\$WINDOWS.~BT','C:\$WINDOWS.~WS')
    foreach ($p in $upgradeRoots) {
        $res = Try-MeasurePath -Path $p -OlderThanDays $AgeDays -Recurse
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows Upgrade Leftovers' -Path $p -Item 'Old setup files' `
                -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to remove if no upgrade is pending." `
                -PlanCommand ("Remove-Item -LiteralPath '{0}' -Recurse -Force -WhatIf" -f $p) -Confidence Medium `
                -Notes 'Ensure no pending upgrades / rollback needed')
        }
    }
    $panther = "C:\Windows\Panther"
    $res = Try-MeasurePath -Path $panther -OlderThanDays $AgeDays -Recurse -Include @('*.log','*.etl','*.cab')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Setup Logs (Panther)' -Path $panther -Item 'Old setup logs' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear old setup logs." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.log,*.etl,*.cab | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf" -f $panther,$AgeDays) `
            -Confidence High)
    }

    # CBS logs (Windows servicing)
    $cbs = "C:\Windows\Logs\CBS"
    $res = Try-MeasurePath -Path $cbs -OlderThanDays $AgeDays -Recurse -Include @('*.log','*.cab')
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Servicing Logs (CBS)' -Path $cbs -Item 'Old CBS logs' `
            -SizeBytes $res.Bytes -Age $AgeDays -RecommendedAction "Safe to clear old CBS logs when not troubleshooting." `
            -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.log,*.cab | Where-Object LastWriteTime -lt (Get-Date).AddDays(-{1}) | Remove-Item -Force -WhatIf" -f $cbs,$AgeDays) `
            -Confidence High)
    }

    # ESD installation files
    $esdRoots     = @('C:\ESD','C:\$WINDOWS.~BT\Sources')
    foreach ($p in $esdRoots) {
        $res = Try-MeasurePath -Path $p -Recurse -Include @('*.esd')
        if ($res.Exists -and $res.Bytes -gt 0) {
            Add-Finding (New-Finding -Category 'Windows ESD Packages' -Path $p -Item '*.esd' `
                -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Review before removal; used for repair/upgrade." `
                -PlanCommand ("Get-ChildItem -LiteralPath '{0}' -Force -Recurse -Include *.esd | Remove-Item -Force -WhatIf" -f $p) `
                -Confidence Medium -Notes 'Only remove if you have media or won’t need in-place repair')
        }
    }

    # Defender definitions cache (report-only)
    $defCache = "C:\ProgramData\Microsoft\Windows Defender\Definition Updates"
    $res = Try-MeasurePath -Path $defCache -Recurse
    if ($res.Exists -and $res.Bytes -gt 0) {
        Add-Finding (New-Finding -Category 'Defender Definitions' -Path $defCache -Item 'Definition cache' `
            -SizeBytes $res.Bytes -Age 0 -RecommendedAction "Let Defender manage; avoid manual deletion." `
            -PlanCommand "" -Confidence Low -Notes 'Managed by platform updates; informational only')
    }

    # Device driver packages (DriverStore) – report-only; removal is risky
    $driverStore = "C:\Windows\System32\DriverStore\FileRepository"
    $res = Try-MeasurePath -Path $driverStore -Recurse
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
th, td { border: 1px solid #ddd; padding: 8px; }
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
  <div><b>Parameters:</b> Drives=$($Drives -join ', '); AgeDays=$AgeDays; LargeFileMinMB=$LargeFileMinMB; Duplicates=$IncludeDupScan; DISM=$IncludeDismAnalysis; SystemParity=$IncludeSystemFileParity</div>
  <div><b>Potentially reclaimable (estimate):</b> $(Format-Size $totalBytes)</div>
</div>
"@

$reportTable = $findings | Select-Object Category, Path, Item, Size, AgeDays, Confidence, RecommendedAction, Notes, PlanCommand |
    ConvertTo-Html -As Table -Fragment

$html = ConvertTo-Html -Head $style -Body ($header + $reportTable)

# Write report
$html | Out-File -LiteralPath $ReportPath -Encoding UTF8
Write-Host "Report written to: $ReportPath"

# Optional cleanup plan (all -WhatIf)
if ($GenerateCleanupPlan) {
    $planHeader = @"
# Cleanup Plan (Preview-Only)
# Generated: $(Get-Date)
# Computer: $env:COMPUTERNAME
# All commands below include -WhatIf for safety. Review first; remove -WhatIf if/when you decide to execute.
# Recommended: Create a Restore Point and close apps before running any cleanup.
"@
    $planContent = ($PlanCommands | Select-Object -Unique) -join "`r`n"
    ($planHeader + "`r`n" + $planContent + "`r`n") | Out-File -LiteralPath $PlanPath -Encoding UTF8
    Write-Host "Preview cleanup plan written to: $PlanPath"
}

# Final console summary
("{0} findings. Estimated reclaimable: {1}" -f $findings.Count, (Format-Size $totalBytes)) | Write-Host
