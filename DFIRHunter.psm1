# DFIR-Hunter Module

# ------------------
# Module Manifest:
# =================
# []  Hunt-All
# [X] Hunt-Logs
# [X] Hunt-Files
# []  Hunt-Persistence
# []  Hunt-Browser
# []  Hunt-Tasks
# []  Hunt-AMSI
# []  Hunt-ETW
# []  Hunt-Registry
# []  Hunt-Export
# -------------------

# Script Variables
$script:IOCLogStrings = @("placeholder")

# HUNT-LOGS
Function Hunt-Logs {
    param (
        [Parameter(Mandatory=$false)]
        $StartDate,
        [Parameter(Mandatory=$false)]
        $EndDate="Now",
        [Parameter(Mandatory=$false)]
        [string[]]$IncludeStrings = @(),
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeStrings = @(),
        [Parameter(Mandatory=$false)]
        [int[]]$EventId = @(),
        [Parameter(Mandatory=$false)]
        [int[]]$ExcludeEventId = @(),
        [Parameter(Mandatory=$false)]
        [string[]]$LogNames = @(),
        [Parameter(Mandatory=$false)]
        [ValidateSet("OldestFirst","NewestFirst")]
        [string]$SortOrder = "NewestFirst",
        [Parameter(Mandatory=$false)]
        [int]$XML = 1250,
        [Parameter(Mandatory=$false)]
        [int]$MSG = 1000,
        [Parameter(Mandatory=$false)]
        [int]$MaxPrint = 0,
        [Parameter(Mandatory=$false)]
        [string]$Timezone = "",
        [Parameter(Mandatory=$false)]
        [switch]$StopLogging,
        [Parameter(Mandatory=$false)]
        [string]$Export,
        [Parameter(Mandatory=$false)]
        [string]$FolderPath,
        [Parameter(Mandatory=$false)]
        [string]$Aggressive,
        [Parameter(Mandatory=$false)]
        [ValidateSet(1,2,3)]
        [int]$Auto
    )

    # Define global IOC list if not already defined
    if (-not (Get-Variable -Name "IOCLogStrings" -Scope Global -ErrorAction SilentlyContinue)) {
        Write-Warning "IOCLogStrings not found. Defining default IOC list."
        $script:IOCLogStrings = @("")
    }

    # Handle Auto mode
    if ($PSBoundParameters.ContainsKey('Auto')) {
        Write-Host "Running in Auto Mode (Level $Auto)..." -ForegroundColor Cyan
        
        # Define baseline parameters for each auto level
        $baselineParams = @{}
        $baselineLogNames = @()
        $baselineAggressive = $false
        
        switch ($Auto) {
            1 {
                $baselineParams.StartDate = "14D"
                $baselineParams.EndDate = "Now"
                $baselineLogNames = @("PowerShell", "Microsoft-Windows-PowerShell/Operational", "System", "Security", "Application")
                Write-Host "Auto Level 1: 14-day search with core log focus" -ForegroundColor Yellow
            }
            2 {
                $baselineParams.StartDate = "30D"
                $baselineParams.EndDate = "Now"
                Write-Host "Auto Level 2: 30-day comprehensive search" -ForegroundColor Yellow
            }
            3 {
                $baselineParams.StartDate = "30D"
                $baselineParams.EndDate = "Now"
                $baselineAggressive = $true
                Write-Host "Auto Level 3: 30-day search with filesystem analysis" -ForegroundColor Yellow
            }
        }
        
        # Validate user parameters don't reduce scope (only allow additions)
        if ($PSBoundParameters.ContainsKey('StartDate')) {
            $userStartDate = ConvertTo-DateTime -InputValue $StartDate -TargetTimeZone ([System.TimeZoneInfo]::Local)
            $baselineStartDate = ConvertTo-DateTime -InputValue $baselineParams.StartDate -TargetTimeZone ([System.TimeZoneInfo]::Local)
            if ($userStartDate -gt $baselineStartDate) {
                throw "Auto Mode Error: Cannot reduce search scope. StartDate '$StartDate' is more recent than baseline '$($baselineParams.StartDate)'. Use a date equal to or earlier than the baseline."
            }
        }
        
        if ($PSBoundParameters.ContainsKey('EndDate')) {
            $userEndDate = ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone ([System.TimeZoneInfo]::Local)
            $baselineEndDate = ConvertTo-DateTime -InputValue $baselineParams.EndDate -TargetTimeZone ([System.TimeZoneInfo]::Local)
            if ($userEndDate -lt $baselineEndDate) {
                throw "Auto Mode Error: Cannot reduce search scope. EndDate '$EndDate' is earlier than baseline '$($baselineParams.EndDate)'. Use a date equal to or later than the baseline."
            }
        }
        
        # Validate LogNames are additive (baseline logs must be included)
        if ($PSBoundParameters.ContainsKey('LogNames') -and $baselineLogNames.Count -gt 0) {
            foreach ($baseLog in $baselineLogNames) {
                if ($LogNames -notcontains $baseLog) {
                    # Check for partial matches (case insensitive)
                    $foundMatch = $false
                    foreach ($userLog in $LogNames) {
                        if ($userLog -like "*$baseLog*" -or $baseLog -like "*$userLog*") {
                            $foundMatch = $true
                            break
                        }
                    }
                    if (-not $foundMatch) {
                        throw "Auto Mode Error: Cannot reduce search scope. Required baseline log '$baseLog' not found in user-specified LogNames. Add baseline logs to your list or remove -LogNames to use defaults."
                    }
                }
            }
        }
        
        # Validate Aggressive parameter (Level 3 requires it)
        if ($Auto -eq 3 -and $PSBoundParameters.ContainsKey('Aggressive') -and [string]::IsNullOrWhiteSpace($Aggressive)) {
            throw "Auto Mode Error: Cannot disable Aggressive mode in Level 3. Remove -Aggressive parameter to use default, or specify a custom path."
        }
        
        # Build final parameters by combining baseline with user additions
        $finalParams = @{
            StartDate = if ($PSBoundParameters.ContainsKey('StartDate')) { $StartDate } else { $baselineParams.StartDate }
            EndDate = if ($PSBoundParameters.ContainsKey('EndDate')) { $EndDate } else { $baselineParams.EndDate }
            IncludeStrings = @($script:IOCLogStrings) + $IncludeStrings  # Combine baseline IOCs with user additions
            SortOrder = $SortOrder
            XML = $XML
            MSG = $MSG
            MaxPrint = $MaxPrint
            Timezone = $Timezone
        }
        
        # Add LogNames (combine baseline with user additions)
        if ($baselineLogNames.Count -gt 0) {
            $finalParams.LogNames = $baselineLogNames + $LogNames | Select-Object -Unique
        } elseif ($LogNames.Count -gt 0) {
            $finalParams.LogNames = $LogNames
        }
        
        # Add other optional parameters
        if ($ExcludeStrings.Count -gt 0) { $finalParams.ExcludeStrings = $ExcludeStrings }
        if ($EventId.Count -gt 0) { $finalParams.EventId = $EventId }
        if ($ExcludeEventId.Count -gt 0) { $finalParams.ExcludeEventId = $ExcludeEventId }
        if ($PSBoundParameters.ContainsKey('FolderPath')) { $finalParams.FolderPath = $FolderPath }
        if ($PSBoundParameters.ContainsKey('Export')) { $finalParams.Export = $Export }
        
        # Handle Aggressive parameter for Auto Level 3
        if ($baselineAggressive) {
            if ($PSBoundParameters.ContainsKey('Aggressive') -and ![string]::IsNullOrWhiteSpace($Aggressive)) {
                $finalParams.Aggressive = $Aggressive  # User specified custom path
            } else {
                $finalParams.Aggressive = ""  # Default aggressive search
            }
        } elseif ($PSBoundParameters.ContainsKey('Aggressive')) {
            $finalParams.Aggressive = $Aggressive  # User added aggressive search
        }
        
        Write-Host "Baseline IOCs: $($script:IOCLogStrings.Count)" -ForegroundColor Green
        if ($IncludeStrings.Count -gt 0) {
            Write-Host "Additional User IOCs: $($IncludeStrings.Count)" -ForegroundColor Green
        }
        Write-Host "Total Search Strings: $($finalParams.IncludeStrings.Count)" -ForegroundColor Green
        
        # Recursively call Hunt-Logs with final parameters
        return Hunt-Logs @finalParams
    }

    # Validate Aggressive parameter requires IncludeStrings
    if ($PSBoundParameters.ContainsKey('Aggressive') -and $IncludeStrings.Count -eq 0) {
        throw "The -Aggressive parameter requires -IncludeStrings to be specified."
    }

    # Handle StopLogging switch
    if ($StopLogging) {
        Write-Host "Attempting to stop event logging services to prevent log overwrites during forensics..." -ForegroundColor Yellow
        
        try {
            # Check for admin privileges
            if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                throw "Administrator privileges required to stop event logging services."
            }

            $eventLogService = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
            if ($null -ne $eventLogService -and $eventLogService.Status -eq "Running") {
                Stop-Service -Name "EventLog" -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped Windows Event Log service." -ForegroundColor Green
            }

            $logNameList = @("Application", "System", "Security", "Setup")
            $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
            if (Test-Path $eventLogPath) {
                $additionalLogs = Get-ChildItem $eventLogPath | Select-Object -ExpandProperty PSChildName
                $logNameList += $additionalLogs | Where-Object { $_ -notin @("Application", "System", "Security", "Setup") }
            }

            foreach ($logName in $logNameList) {
                try {
                    $logPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
                    if (Test-Path $logPath) {
                        Set-ItemProperty -Path $logPath -Name "AutoBackupLogFiles" -Value 1 -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $logPath -Name "MaxSize" -Value 536870912 -ErrorAction SilentlyContinue
                        Write-Host "Configured $logName log to archive mode (no overwrite, 512MB max)." -ForegroundColor Green
                    }
                } catch {
                    Write-Warning "Could not configure $logName log: $($_.Exception.Message)"
                }
            }

            Write-Host "Event logging has been paused. Remember to restart the EventLog service when forensics is complete." -ForegroundColor Cyan
            Write-Host "To restart: Start-Service -Name 'EventLog'" -ForegroundColor Cyan
            
        } catch {
            Write-Error "Error stopping event logging: $($_.Exception.Message)"
        }
        
        return
    }
    # Handle Export parameter - supports switch or path input
    if ($Export) {
        Write-Host "Starting EVTX export process..." -ForegroundColor Yellow
        
        try {
            # Check for admin privileges first
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if (-not $isAdmin) {
                Write-Warning "Administrator privileges recommended for complete EVTX export. Some logs may be inaccessible."
            }

            $machineName = $env:COMPUTERNAME
            $datetime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $tempDir = [System.IO.Path]::GetTempPath()
            
            # Create safe filename without problematic characters
            $safeFilename = "EVTX_${machineName}_$datetime.zip"
            
            # Handle different export path scenarios
            try {
                if ($Export -eq $true -or [string]::IsNullOrWhiteSpace($Export)) {
                    # Just -Export with no path specified - use temp directory
                    $exportFullPath = Join-Path $tempDir $safeFilename
                    Write-Host "No export path specified, using default: $exportFullPath" -ForegroundColor Cyan
                } elseif ($Export -match '\.zip$') {
                    # Contains .zip extension
                    if ([System.IO.Path]::IsPathRooted($Export)) {
                        # Full absolute path with .zip extension
                        $exportFullPath = $Export
                    } else {
                        # Relative path with .zip extension - treat as file in current directory
                        $currentDir = Get-Location -ErrorAction Stop
                        $exportFullPath = Join-Path $currentDir.Path $Export
                    }
                } else {
                    # No .zip extension - treat as directory path
                    if ([System.IO.Path]::IsPathRooted($Export)) {
                        # Full absolute directory path
                        $exportFullPath = Join-Path $Export $safeFilename
                    } else {
                        # Relative directory path
                        $currentDir = Get-Location -ErrorAction Stop
                        $targetDir = Join-Path $currentDir.Path $Export
                        $exportFullPath = Join-Path $targetDir $safeFilename
                    }
                }
            } catch {
                throw "Failed to determine export path: $($_.Exception.Message)"
            }

            # Validate and create export directory
            $exportDir = Split-Path $exportFullPath -Parent
            if ([string]::IsNullOrWhiteSpace($exportDir)) {
                throw "Invalid export path: Cannot determine parent directory for '$exportFullPath'"
            }
            
            if (-not (Test-Path $exportDir)) {
                try {
                    Write-Host "Creating export directory: $exportDir" -ForegroundColor Yellow
                    New-Item -Path $exportDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                } catch {
                    throw "Cannot create export directory '$exportDir': $($_.Exception.Message)"
                }
            }
            
            # Verify directory is writable
            try {
                $testFile = Join-Path $exportDir "test_write_$(Get-Random).tmp"
                New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            } catch {
                throw "Export directory '$exportDir' is not writable: $($_.Exception.Message)"
            }

            Write-Host "Export path: $exportFullPath" -ForegroundColor Cyan

            # Create temporary export directory
            $tempEvtxDir = Join-Path $tempDir "EVTX_Export_$datetime"
            try {
                New-Item -Path $tempEvtxDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            } catch {
                throw "Cannot create temporary directory '$tempEvtxDir': $($_.Exception.Message)"
            }

            # Enhanced EVTX file discovery - focus on the main logs directory
            $evtxPaths = @(
                "$env:SystemRoot\System32\winevt\Logs"
            )

            # Add additional paths only if they exist and contain EVTX files
            $additionalPaths = @(
                "$env:SystemRoot\System32\config",
                "$env:SystemRoot\System32\LogFiles\WMI"
            )

            foreach ($path in $additionalPaths) {
                if (Test-Path $path) {
                    try {
                        $testFiles = Get-ChildItem -Path $path -Filter *.evtx -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($null -ne $testFiles) {
                            $evtxPaths += $path
                        }
                    } catch {
                        Write-Verbose "Cannot access path: $path"
                    }
                }
            }

            $evtxFileList = @()
            $accessDeniedCount = 0
            
            # Loop through each directory in $evtxPaths
            foreach ($basePath in $evtxPaths) {
                if (Test-Path $basePath) {
                    try {
                        $files = Get-ChildItem -Path $basePath -Filter *.evtx -ErrorAction SilentlyContinue
                        foreach ($file in $files) {
                            # Don't test file access - just check if file exists and add to list
                            # Windows will handle locked files during copy operation
                            if (Test-Path $file.FullName -PathType Leaf) {
                                $evtxFileList += $file
                            }
                        }
                    } catch {
                        Write-Verbose "Cannot enumerate path: $basePath - $($_.Exception.Message)"
                    }
                } else {
                    Write-Warning "Path does not exist: $basePath"
                }
            }

            if ($evtxFileList.Count -eq 0) {
                Write-Warning "No EVTX files found to export."
                return
            }

            Write-Host "Found $($evtxFileList.Count) event log files to process." -ForegroundColor Green

            $copiedCount = 0
            $totalSize = 0
            $copyErrors = 0
            
            # Use wevtutil to export logs when possible, fall back to file copy
            foreach ($file in $evtxFileList) {
                if ($null -eq $file -or [string]::IsNullOrWhiteSpace($file.Name)) {
                    continue
                }
                
                $logName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $destPath = Join-Path $tempEvtxDir $file.Name
                $exported = $false
                
                try {
                    # Try wevtutil first for active logs (more reliable)
                    $null = & wevtutil.exe epl $logName $destPath 2>$null
                    if ($LASTEXITCODE -eq 0 -and (Test-Path $destPath)) {
                        $fileSize = (Get-Item $destPath -ErrorAction SilentlyContinue).Length
                        if ($null -ne $fileSize -and $fileSize -gt 0) {
                            $copiedCount++
                            $totalSize += $fileSize
                            $exported = $true
                        }
                    }
                } catch {
                    # wevtutil failed, will try file copy
                }
                
                if (-not $exported) {
                    try {
                        # Fall back to file copy for archived/inactive logs
                        if (Test-Path $file.FullName -PathType Leaf) {
                            Copy-Item $file.FullName $destPath -ErrorAction Stop
                            $copiedCount++
                            $totalSize += $file.Length
                        } else {
                            Write-Verbose "Source file no longer exists: $($file.FullName)"
                            $copyErrors++
                        }
                    } catch [UnauthorizedAccessException] {
                        Write-Verbose "Access denied copying $($file.Name)"
                        $accessDeniedCount++
                    } catch [System.IO.IOException] {
                        Write-Verbose "File in use, skipping $($file.Name)"
                        $copyErrors++
                    } catch {
                        Write-Verbose "Could not copy $($file.Name): $($_.Exception.Message)"
                        $copyErrors++
                    }
                }
            }

            Write-Host "Successfully exported $copiedCount event log files." -ForegroundColor Green
            if ($copyErrors -gt 0) {
                Write-Host "$copyErrors files failed to copy (likely in use by system)." -ForegroundColor Yellow
            }
            if ($accessDeniedCount -gt 0) {
                Write-Host "$accessDeniedCount files inaccessible due to permissions." -ForegroundColor Yellow
            }

            # Create system info
            $sysInfoPath = Join-Path $tempEvtxDir "SystemInfo.txt"
            try {
                $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                $osVersion = if ($null -ne $osInfo) { "$($osInfo.Caption) $($osInfo.Version)" } else { "Unknown" }
                $architecture = if ($null -ne $osInfo) { $osInfo.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
                $sysInfo = @"
EVTX Export Information
=======================
Machine Name: $machineName
Export Date: $(Get-Date)
User: $env:USERNAME
Domain: $env:USERDOMAIN
OS: $osVersion
Architecture: $architecture
Admin Rights: $isAdmin
Files Exported: $copiedCount
Copy Errors: $copyErrors
Access Denied: $accessDeniedCount
Total Raw Size: $([math]::Round($totalSize / 1MB, 2)) MB
"@
                $sysInfo | Out-File -FilePath $sysInfoPath -Encoding UTF8
            } catch {
                Write-Verbose "Could not create system information file."
            }

            if ($copiedCount -eq 0) {
                Write-Warning "No files were successfully exported. Archive creation skipped."
                # Clean up empty temp directory
                Remove-Item $tempEvtxDir -Recurse -Force -ErrorAction SilentlyContinue
                return
            }

            Write-Host "Creating ZIP archive..." -ForegroundColor Yellow
            
            try {
                # PowerShell 5.1 compatible compression
                if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
                    Compress-Archive -Path "$tempEvtxDir\*" -DestinationPath $exportFullPath -CompressionLevel Optimal -Force
                } else {
                    # Fallback for older PowerShell versions
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempEvtxDir, $exportFullPath)
                }
            } catch {
                throw "Failed to create ZIP archive: $($_.Exception.Message)"
            }

            # Clean up temporary directory
            try {
                Remove-Item $tempEvtxDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Verbose "Could not clean up temporary directory: $tempEvtxDir"
            }

            # Get final archive information
            if (Test-Path $exportFullPath) {
                $exportItem = Get-Item $exportFullPath
                $exportSize = $exportItem.Length
                $exportSizeMB = [math]::Round($exportSize / 1MB, 2)
                $compressionRatio = if ($totalSize -gt 0) { 
                    [math]::Round((1 - ($exportSize / $totalSize)) * 100, 1) 
                } else { 
                    0 
                }
                
                Write-Host ""
                Write-Host "EVTX Export Complete!" -ForegroundColor Green
                Write-Host "Location: $exportFullPath" -ForegroundColor Cyan
                Write-Host "Archive Size: $exportSizeMB MB" -ForegroundColor Cyan
                Write-Host "Original Size: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Cyan
                Write-Host "Compression: $compressionRatio%" -ForegroundColor Cyan
                Write-Host "Files: $copiedCount event logs" -ForegroundColor Cyan
                
                if ($accessDeniedCount -gt 0 -or $copyErrors -gt 0) {
                    Write-Host ""
                    Write-Host "Note: $($accessDeniedCount + $copyErrors) files could not be exported." -ForegroundColor Yellow
                    Write-Host "Run as Administrator for better access to system logs." -ForegroundColor Yellow
                }
            } else {
                throw "Export file was not created successfully."
            }

        } catch {
            Write-Error "Error during EVTX export: $($_.Exception.Message)"
        }
        
        return
    }

    # Initialize timezone handling
    $systemTimeZone = [System.TimeZoneInfo]::Local

    # Function to get timezone info by name/abbreviation
    function Get-TimezoneInfo {
        param($TimezoneName)
        
        $TimezoneName = $TimezoneName.ToUpper()
        
        $timezoneMap = @{
            'UTC' = 'UTC'
            'GMT' = 'GMT Standard Time'
            'EST' = 'Eastern Standard Time'
            'CST' = 'Central Standard Time' 
            'MST' = 'Mountain Standard Time'
            'PST' = 'Pacific Standard Time'
            'EDT' = 'Eastern Standard Time'
            'CDT' = 'Central Standard Time'
            'MDT' = 'Mountain Standard Time'
            'PDT' = 'Pacific Standard Time'
        }
        
        $mappedName = if ($timezoneMap.ContainsKey($TimezoneName)) { $timezoneMap[$TimezoneName] } else { $TimezoneName }
        
        try {
            if ($mappedName -eq 'UTC') {
                return [System.TimeZoneInfo]::Utc
            } else {
                return [System.TimeZoneInfo]::FindSystemTimeZoneById($mappedName)
            }
        } catch {
            throw "Invalid timezone: $TimezoneName"
        }
    }

    $targetTimeZone = if ([string]::IsNullOrWhiteSpace($Timezone)) { $systemTimeZone } else { Get-TimezoneInfo -TimezoneName $Timezone }

    # Function to parse time strings and convert to target timezone for search queries
    function ConvertTo-DateTime {
        param($InputValue, $TargetTimeZone)
        
        if ($InputValue -is [datetime]) {
            # Convert to target timezone for internal processing, then back to system time for search
            if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                $convertedTime = [System.TimeZoneInfo]::ConvertTime($InputValue, $TargetTimeZone, $systemTimeZone)
                return $convertedTime
            }
            return $InputValue
        }
        
        if ($InputValue -is [string]) {
            $InputValue = $InputValue.Trim()
            
            if ($InputValue.ToLower() -eq 'now') {
                return Get-Date
            }
            
            if ($InputValue -match '^(\d+)([DHMdhm])$') {
                $number = [int]$matches[1]
                $unit = $matches[2].ToUpper()
                
                $currentTime = Get-Date
                switch ($unit) {
                    'D' { return $currentTime.AddDays(-$number) }
                    'H' { return $currentTime.AddHours(-$number) }
                    'M' { return $currentTime.AddMinutes(-$number) }
                }
            } else {
                try {
                    $parsedDate = [datetime]$InputValue
                    # If user specified a timezone, interpret the input date as being in that timezone
                    if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                        # Convert from target timezone to system timezone for search
                        $convertedTime = [System.TimeZoneInfo]::ConvertTime($parsedDate, $TargetTimeZone, $systemTimeZone)
                        return $convertedTime
                    }
                    return $parsedDate
                } catch {
                    throw "Invalid date format: $InputValue. Use datetime, 'now', or relative format like '1D', '4H', or '10m'"
                }
            }
        }
        
        throw "Invalid date input: $InputValue"
    }

    # Function to format datetime with timezone for display
    function Format-DateTimeWithTimeZone {
        param($DateTime, $TargetTimeZone)
        
        # Convert from system time to target timezone for display
        if ($TargetTimeZone.Id -eq $systemTimeZone.Id) {
            $convertedTime = $DateTime
            $tzAbbrev = $systemTimeZone.StandardName.Split(' ')[0]
        } else {
            $convertedTime = [System.TimeZoneInfo]::ConvertTime($DateTime, $systemTimeZone, $TargetTimeZone)
            
            $tzAbbrev = if ($TargetTimeZone.Id -eq 'UTC') { 
                'UTC' 
            } elseif ($TargetTimeZone.StandardName -like "*Eastern*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'EDT' } else { 'EST' } 
            } elseif ($TargetTimeZone.StandardName -like "*Central*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'CDT' } else { 'CST' } 
            } elseif ($TargetTimeZone.StandardName -like "*Mountain*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'MDT' } else { 'MST' } 
            } elseif ($TargetTimeZone.StandardName -like "*Pacific*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'PDT' } else { 'PST' } 
            } else { 
                $TargetTimeZone.StandardName.Split(' ')[0] 
            }
        }
        
        return $convertedTime.ToString("yyyy-MM-dd HH:mm:ss") + " $tzAbbrev"
    }

    # For search mode, make dates optional with sensible defaults
    if ($null -eq $StartDate -and $null -eq $EndDate) {
        $StartDate = (Get-Date).AddDays(-7)  # Default to last 7 days
        $EndDate = Get-Date
        Write-Host "No date range specified, using default: Last 7 days" -ForegroundColor Cyan
    } elseif ($null -eq $StartDate) {
        throw "EndDate specified but StartDate is missing. Please provide both dates or neither."
    } elseif ($null -eq $EndDate) {
        throw "StartDate specified but EndDate is missing. Please provide both dates or neither."
    }

    # Handle parameter logic for XML and MSG truncation
    $xmlTruncateLength = $XML
    $msgTruncateLength = $MSG
    
    if ($PSBoundParameters.ContainsKey('XML') -and $null -eq $XML) {
        $xmlTruncateLength = -1
    }
    if ($PSBoundParameters.ContainsKey('MSG') -and $null -eq $MSG) {
        $msgTruncateLength = -1
    }

    # Function to format XML
    function Format-EventXml {
        param($XmlString, $TruncateLength)
        
        try {
            if ([string]::IsNullOrWhiteSpace($XmlString)) { return "[No XML Data]" }
            
            if ($TruncateLength -eq 0) { return "[XML Display Disabled]" }
            
            $xmlDoc = [xml]$XmlString
            $outputLines = @()
            
            if ($xmlDoc.Event.System) {
                $system = $xmlDoc.Event.System
                $outputLines += "  System:"
                if ($system.Provider.Name) { $outputLines += "    Provider: $($system.Provider.Name)" }
                if ($system.EventID) { $outputLines += "    EventID: $($system.EventID)" }
                if ($system.Level) { $outputLines += "    Level: $($system.Level)" }
                if ($system.Task) { $outputLines += "    Task: $($system.Task)" }
                if ($system.Keywords) { $outputLines += "    Keywords: $($system.Keywords)" }
                if ($system.TimeCreated.SystemTime) { $outputLines += "    TimeCreated: $($system.TimeCreated.SystemTime)" }
                if ($system.EventRecordID) { $outputLines += "    RecordID: $($system.EventRecordID)" }
                if ($system.Execution.ProcessID) { $outputLines += "    ProcessID: $($system.Execution.ProcessID)" }
                if ($system.Execution.ThreadID) { $outputLines += "    ThreadID: $($system.Execution.ThreadID)" }
                if ($system.Channel) { $outputLines += "    Channel: $($system.Channel)" }
                if ($system.Computer) { $outputLines += "    Computer: $($system.Computer)" }
            }
            
            if ($xmlDoc.Event.EventData -and $xmlDoc.Event.EventData.Data) {
                $outputLines += "  EventData:"
                foreach ($data in $xmlDoc.Event.EventData.Data) {
                    if ($data -is [System.Xml.XmlElement]) {
                        $name = if ($data.Name) { $data.Name } else { "Data" }
                        $value = if ($data.InnerText) { $data.InnerText } else { $data.'#text' }
                        if (![string]::IsNullOrWhiteSpace($value)) {
                            $outputLines += "    $name`: $value"
                        }
                    } elseif ($data -is [string] -and ![string]::IsNullOrWhiteSpace($data)) {
                        $outputLines += "    Data: $data"
                    }
                }
            }
            
            if ($xmlDoc.Event.UserData) {
                $outputLines += "  UserData:"
                foreach ($child in $xmlDoc.Event.UserData.ChildNodes) {
                    if ($child.InnerText) {
                        $outputLines += "    $($child.Name): $($child.InnerText)"
                    } elseif ($child.HasChildNodes) {
                        $outputLines += "    $($child.Name):"
                        foreach ($subChild in $child.ChildNodes) {
                            if ($subChild.InnerText) {
                                $outputLines += "      $($subChild.Name): $($subChild.InnerText)"
                            }
                        }
                    }
                }
            }
            
            $result = ($outputLines -join "`n")
            
            if ($TruncateLength -gt 0 -and $result.Length -gt $TruncateLength) {
                $result = $result.Substring(0, $TruncateLength) + "..."
            }
            
            return $result
            
        } catch {
            $rawResult = "  [XML Parse Error] Raw: $XmlString"
            if ($TruncateLength -gt 0 -and $rawResult.Length -gt $TruncateLength) {
                $rawResult = $rawResult.Substring(0, $TruncateLength) + "..."
            }
            return $rawResult
        }
    }

    # Function to test if strings match
    function Test-EventMatches {
        param($Event, $IncludeStrings, $ExcludeStrings)
        
        $message = if ([string]::IsNullOrWhiteSpace($Event.Message)) { "" } else { $Event.Message }
        $xmlContent = ""
        try {
            $xmlContent = $Event.ToXml()
        } catch {
            $xmlContent = ""
        }
        
        $searchContent = "$message $xmlContent"
        
        if ($ExcludeStrings.Count -gt 0) {
            foreach ($excludeStr in $ExcludeStrings) {
                if ($searchContent -like "*$excludeStr*") {
                    return $false
                }
            }
        }
        
        if ($IncludeStrings.Count -gt 0) {
            foreach ($includeStr in $IncludeStrings) {
                if ($searchContent -like "*$includeStr*") {
                    return $true
                }
            }
            return $false
        }
        
        return $true
    }

    # Function to create hash key for deduplication
    function Get-EventHashKey {
        param($Event)
        
        $messagePreview = ""
        if (![string]::IsNullOrWhiteSpace($Event.Message)) {
            $messagePreview = ($Event.Message -replace '\s+', ' ').Trim()
            if ($messagePreview.Length -gt 100) {
                $messagePreview = $messagePreview.Substring(0, 100)
            }
        }
        
        $keyComponents = @(
            $Event.LogName,
            $Event.Id,
            $Event.TimeCreated.Ticks,
            $Event.RecordId,
            $messagePreview
        )
        return ($keyComponents -join '|')
    }

    # Function to find matching include strings
    function Get-MatchedStrings {
        param($Event, $IncludeStrings)
        
        $matchList = @()
        $message = if ([string]::IsNullOrWhiteSpace($Event.Message)) { "" } else { $Event.Message }
        $xmlContent = ""
        try {
            $xmlContent = $Event.ToXml()
        } catch {
            $xmlContent = ""
        }
        
        foreach ($includeStr in $IncludeStrings) {
            $foundIn = @()
            if ($message -like "*$includeStr*") { $foundIn += "MSG" }
            if ($xmlContent -like "*$includeStr*") { $foundIn += "XML" }
            
            if ($foundIn.Count -gt 0) {
                $matchStr = if ($includeStr.Length -gt 50) { $includeStr.Substring(0, 47) + "..." } else { $includeStr }
                $location = $foundIn -join ","
                $matchList += "$matchStr  [$location]"
            }
        }
        return ($matchList -join ", ")
    }

    # Function to perform aggressive log file search
    function Search-AggressiveLogFiles {
        param($SearchPath, $IncludeStrings, $MsgTruncateLength)
        
        $logMatches = @()
        $maxFileSizeMB = 100  # Safety limit - don't scan files larger than 100MB
        
        # Check if we've already scanned C:\ and have cached results
        if ($SearchPath -eq "C:\" -and $global:HuntLogs_SystemScanComplete -and $global:HuntLogs_LogFilePaths) {
            Write-Host "Using cached log file paths from previous system scan..." -ForegroundColor Cyan
            Write-Host "Cached paths: $($global:HuntLogs_LogFilePaths.Count) .log files" -ForegroundColor Green
            $logFileList = $global:HuntLogs_LogFilePaths | ForEach-Object { 
                if (Test-Path $_) { Get-Item $_ -ErrorAction SilentlyContinue }
            } | Where-Object { $null -ne $_ }
        } else {
            Write-Host "Starting aggressive log file search in: $SearchPath" -ForegroundColor Yellow
            Write-Progress -Activity "Aggressive Log Search" -Status "Scanning for .log files..." -PercentComplete 0
            
            try {
                $logFileList = Get-ChildItem -Path $SearchPath -Filter "*.log" -Recurse -File -ErrorAction SilentlyContinue -Force
                
                # Display discovered log file paths
                Write-Host "Discovered .log files:" -ForegroundColor Cyan
                $logFileList | ForEach-Object { Write-Host "  $($_.FullName) ($([math]::Round($_.Length / 1MB, 2)) MB)" -ForegroundColor Gray }
                
                # Cache results if scanning C:\
                if ($SearchPath -eq "C:\") {
                    $global:HuntLogs_SystemScanComplete = $true
                    $global:HuntLogs_LogFilePaths = $logFileList | Select-Object -ExpandProperty FullName
                    Write-Host "Cached $($logFileList.Count) log file paths for future searches." -ForegroundColor Green
                }
            } catch {
                Write-Warning "Error during log file discovery: $($_.Exception.Message)"
                return @()
            }
        }

        if ($logFileList.Count -eq 0) {
            Write-Host "No .log files found in: $SearchPath" -ForegroundColor Yellow
            return @()
        }

        Write-Host "Found $($logFileList.Count) log files. Applying safety filters..." -ForegroundColor Green
        
        # Apply safety filter for file size
        $safeLogFiles = @()
        $skippedLargeFiles = 0
        foreach ($logFile in $logFileList) {
            $fileSizeMB = $logFile.Length / 1MB
            if ($fileSizeMB -gt $maxFileSizeMB) {
                $skippedLargeFiles++
                Write-Verbose "Skipping large file: $($logFile.FullName) (Size: $([math]::Round($fileSizeMB, 2)) MB > $maxFileSizeMB MB limit)"
            } else {
                $safeLogFiles += $logFile
            }
        }
        
        if ($skippedLargeFiles -gt 0) {
            Write-Host "Safety filter: Skipped $skippedLargeFiles large files (>$maxFileSizeMB MB) to prevent timeouts" -ForegroundColor Yellow
        }
        
        if ($safeLogFiles.Count -eq 0) {
            Write-Host "No safe-sized log files to scan after applying safety filters." -ForegroundColor Yellow
            return @()
        }
        
        Write-Host "Scanning $($safeLogFiles.Count) safe-sized files for matches..." -ForegroundColor Green

        $currentFileIndex = 0
        foreach ($logFile in $safeLogFiles) {
            $currentFileIndex++
            $percentComplete = [math]::Min(($currentFileIndex / $safeLogFiles.Count) * 100, 100)
            Write-Progress -Activity "Aggressive Log Search" -Status "Processing $($logFile.Name) ($currentFileIndex of $($safeLogFiles.Count))" -PercentComplete $percentComplete
            
            try {
                $content = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue
                if ($null -eq $content) { continue }
                
                foreach ($line in $content) {
                    foreach ($searchString in $IncludeStrings) {
                        if ($line -like "*$searchString*") {
                            $truncatedText = $line
                            if ($MsgTruncateLength -gt 0 -and $line.Length -gt $MsgTruncateLength) {
                                $truncatedText = $line.Substring(0, [math]::Max(1, $MsgTruncateLength)) + "..."
                            }
                            
                            $logMatches += [PSCustomObject]@{
                                FilePath = $logFile.FullName
                                CreationDate = $logFile.CreationTime
                                LastModifiedDate = $logFile.LastWriteTime
                                Match = $searchString
                                Text = $truncatedText
                            }
                            break # Only add one match per line
                        }
                    }
                }
            } catch {
                Write-Verbose "Error processing file $($logFile.FullName): $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Aggressive Log Search" -Completed
        return $logMatches
    }

    # Convert input dates
    try {
        $parsedStartDate = ConvertTo-DateTime -InputValue $StartDate -TargetTimeZone $targetTimeZone
        $parsedEndDate = ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone $targetTimeZone
    } catch {
        throw "Date parsing error: $($_.Exception.Message)"
    }

    # Handle Aggressive search first (will be displayed last)
    $aggressiveResults = @()
    if ($PSBoundParameters.ContainsKey('Aggressive')) {
        $searchPath = if ([string]::IsNullOrWhiteSpace($Aggressive)) { "C:\" } else { $Aggressive }
        
        if (-not (Test-Path $searchPath)) {
            throw "Aggressive search path does not exist: $searchPath"
        }
        
        $aggressiveResults = Search-AggressiveLogFiles -SearchPath $searchPath -IncludeStrings $IncludeStrings -MsgTruncateLength $msgTruncateLength
    }

    Write-Progress -Activity "Initializing Hunt-Logs" -Status "Getting log list..." -PercentComplete 0

    $allEvents = @{}
    $eventCount = 0
    $filteredCount = 0

    # Determine processing mode
    if (![string]::IsNullOrWhiteSpace($FolderPath)) {
        # EVTX File Mode
        if (-not (Test-Path $FolderPath)) {
            throw "EVTX path does not exist: $FolderPath"
        }

        $evtxFileList = @()
        if (Test-Path $FolderPath -PathType Container) {
            $evtxFileList = Get-ChildItem -Path $FolderPath -Filter "*.evtx" -File -ErrorAction SilentlyContinue
        } else {
            if ($FolderPath -like "*.evtx") {
                $evtxFileList = @(Get-Item $FolderPath -ErrorAction SilentlyContinue)
            } else {
                throw "Specified file is not an EVTX file: $FolderPath"
            }
        }

        if ($evtxFileList.Count -eq 0) {
            Write-Warning "No EVTX files found in: $FolderPath"
            return
        }

        Write-Progress -Activity "Hunt-Logs Search" -Status "Found $($evtxFileList.Count) EVTX files to process" -PercentComplete 15

        if ($LogNames.Count -gt 0) {
            $filteredEvtxFiles = @()
            foreach ($evtxFile in $evtxFileList) {
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($evtxFile.Name)
                foreach ($logName in $LogNames) {
                    if ($fileName -like "*$logName*" -or $logName -like "*$fileName*") {
                        $filteredEvtxFiles += $evtxFile
                        break
                    }
                }
            }
            $evtxFileList = $filteredEvtxFiles
        }

        # Display timezone context for EVTX files
        if ($targetTimeZone.Id -ne $systemTimeZone.Id) {
            Write-Host "EVTX Timezone Note: Search range converted from $($targetTimeZone.DisplayName) to system time" -ForegroundColor Cyan
            Write-Host "Log timestamps will be converted to $($targetTimeZone.DisplayName) for display" -ForegroundColor Cyan
        }

        $currentFileIndex = 0
        foreach ($evtxFile in $evtxFileList) {
            $currentFileIndex++
            $percentComplete = [math]::Min(25 + (($currentFileIndex / $evtxFileList.Count) * 60), 85)
            Write-Progress -Activity "Hunt-Logs Search" -Status "Processing EVTX file $currentFileIndex of $($evtxFileList.Count): $($evtxFile.Name) (Found: $eventCount events)" -PercentComplete $percentComplete

            try {
                $filterHash = @{
                    Path = $evtxFile.FullName
                    StartTime = $parsedStartDate
                    EndTime = $parsedEndDate
                }

                if ($EventId.Count -gt 0) { $filterHash.Id = $EventId }

                $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($eventItem in $events) {
                        if ($ExcludeEventId.Count -gt 0 -and $ExcludeEventId -contains $eventItem.Id) { 
                            $filteredCount++
                            continue 
                        }
                        
                        if (-not (Test-EventMatches -Event $eventItem -IncludeStrings $IncludeStrings -ExcludeStrings $ExcludeStrings)) {
                            $filteredCount++
                            continue
                        }

                        $hashKey = Get-EventHashKey -Event $eventItem
                        if (-not $allEvents.ContainsKey($hashKey)) {
                            if ($IncludeStrings.Count -gt 0) {
                                $matchInfo = Get-MatchedStrings -Event $eventItem -IncludeStrings $IncludeStrings
                                $eventItem | Add-Member -MemberType NoteProperty -Name "MatchedStrings" -Value $matchInfo -Force
                            }
                            $allEvents[$hashKey] = $eventItem
                            $eventCount++
                        }
                    }
                }
            } catch {
                Write-Warning "Error processing EVTX file '$($evtxFile.Name)': $($_.Exception.Message)"
            }
        }

    } else {
        # Live Log Mode
        $logsToQuery = @()
        $currentQueryIndex = 0

        try {
            $availableLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordCount -gt 0 -and $_.RecordCount -lt 1000000 -and $_.LastWriteTime -ge $parsedStartDate.AddDays(-30) }

            if ($LogNames.Count -gt 0) {
                $availableLogsLower = @{}
                foreach ($logItem in $availableLogs) { 
                    $availableLogsLower[$logItem.LogName.ToLower()] = $logItem.LogName 
                }
                
                foreach ($logName in $LogNames) {
                    $nameLower = $logName.ToLower()
                    if ($availableLogsLower.ContainsKey($nameLower)) {
                        $logsToQuery += $availableLogsLower[$nameLower]
                    } else {
                        $logsToQuery += $logName
                    }
                }
            } else {
                $logsToQuery = $availableLogs | Select-Object -ExpandProperty LogName
            }
        } catch {
            Write-Verbose "Error getting log list: $($_.Exception.Message)"
        }

        $totalQueries = $logsToQuery.Count
        Write-Progress -Activity "Hunt-Logs Search" -Status "Found $totalQueries logs to search" -PercentComplete 15

        if ($totalQueries -eq 0) { 
            Write-Warning "No logs found to search."
            if ($aggressiveResults.Count -eq 0) { return }
        }

        foreach ($logName in $logsToQuery) {
            $currentQueryIndex++
            $percentComplete = [math]::Min(25 + (($currentQueryIndex / $totalQueries) * 60), 85)
            Write-Progress -Activity "Hunt-Logs Search" -Status "Processing log $currentQueryIndex of $totalQueries`: $logName (Found: $eventCount events)" -PercentComplete $percentComplete

            try {
                $filterHash = @{ 
                    LogName = $logName
                    StartTime = $parsedStartDate
                    EndTime = $parsedEndDate 
                }

                if ($EventId.Count -gt 0) { $filterHash.Id = $EventId }

                $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($eventItem in $events) {
                        if ($ExcludeEventId.Count -gt 0 -and $ExcludeEventId -contains $eventItem.Id) { 
                            $filteredCount++
                            continue 
                        }
                        
                        if (-not (Test-EventMatches -Event $eventItem -IncludeStrings $IncludeStrings -ExcludeStrings $ExcludeStrings)) {
                            $filteredCount++
                            continue
                        }

                        $hashKey = Get-EventHashKey -Event $eventItem
                        if (-not $allEvents.ContainsKey($hashKey)) {
                            if ($IncludeStrings.Count -gt 0) {
                                $matchInfo = Get-MatchedStrings -Event $eventItem -IncludeStrings $IncludeStrings
                                $eventItem | Add-Member -MemberType NoteProperty -Name "MatchedStrings" -Value $matchInfo -Force
                            }
                            $allEvents[$hashKey] = $eventItem
                            $eventCount++
                        }
                    }
                }
            } catch {
                Write-Verbose "Error processing log '$logName': $($_.Exception.Message)"
            }
        }
    }

    Write-Progress -Activity "Hunt-Logs Search" -Status "Processing $($allEvents.Count) events..." -PercentComplete 90

    $uniqueEvents = $allEvents.Values
    $sortedEvents = if ($SortOrder -eq "OldestFirst") {
        $uniqueEvents | Sort-Object TimeCreated
    } else {
        $uniqueEvents | Sort-Object TimeCreated -Descending
    }

    Write-Progress -Activity "Hunt-Logs Search" -Status "Complete - Found $($sortedEvents.Count) unique events" -PercentComplete 100
    Start-Sleep -Milliseconds 500
    Write-Progress -Activity "Hunt-Logs Search" -Completed

    $totalOutputChars = 0

    # Display EVTX results
    foreach ($logEvent in $sortedEvents) {
        $message = if ([string]::IsNullOrWhiteSpace($logEvent.Message)) { "[No Message]" } else { $logEvent.Message }
        $cleanMessage = $message -replace '\r?\n',' ' -replace '\s+',' ' -replace '^\s+|\s+$',''
        
        if ($msgTruncateLength -eq 0) {
            $cleanMessage = "[Message Display Disabled]"
        } elseif ($msgTruncateLength -gt 0 -and $cleanMessage.Length -gt $msgTruncateLength) {
            $cleanMessage = $cleanMessage.Substring(0, [math]::Max(1, $msgTruncateLength)) + "..."
        }

        $formattedTime = Format-DateTimeWithTimeZone -DateTime $logEvent.TimeCreated -TargetTimeZone $targetTimeZone
        
        $formattedXml = ""
        try {
            $rawXml = $logEvent.ToXml()
            $formattedXml = Format-EventXml -XmlString $rawXml -TruncateLength $xmlTruncateLength
        } catch {
            $formattedXml = "[XML Unavailable]"
        }

        $eventOutputSize = 300 + $cleanMessage.Length + $logEvent.LogName.Length + $formattedTime.Length + $formattedXml.Length
        if ($IncludeStrings.Count -gt 0 -and $logEvent.MatchedStrings) {
            $eventOutputSize += $logEvent.MatchedStrings.Length + 50
        }

        if ($MaxPrint -gt 0 -and $totalOutputChars + $eventOutputSize -gt $MaxPrint) {
            $remainingEvents = $sortedEvents.Count - $sortedEvents.IndexOf($logEvent)
            Write-Host ""
            Write-Host "Output truncated: MaxPrint limit ($MaxPrint chars) reached. $remainingEvents more events available." -ForegroundColor DarkRed
            break
        }

        $totalOutputChars += $eventOutputSize

        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host "Time     : " -NoNewline -ForegroundColor Yellow
        Write-Host $formattedTime -ForegroundColor White
        Write-Host "Log Name : " -NoNewline -ForegroundColor Yellow
        Write-Host $logEvent.LogName -ForegroundColor Cyan
        Write-Host "Event ID : " -NoNewline -ForegroundColor Yellow
        Write-Host $logEvent.Id -ForegroundColor White
        if ($IncludeStrings.Count -gt 0 -and $logEvent.MatchedStrings) {
            Write-Host "Match    : " -NoNewline -ForegroundColor Yellow
            Write-Host $logEvent.MatchedStrings -ForegroundColor Red
        }
        Write-Host "Message  : " -NoNewline -ForegroundColor Yellow
        Write-Host $cleanMessage -ForegroundColor Green
        
        if ($xmlTruncateLength -ne 0 -and ![string]::IsNullOrWhiteSpace($formattedXml) -and $formattedXml -ne "[No XML Data]") {
            Write-Host "XML Data : " -NoNewline -ForegroundColor Yellow
            $xmlLines = $formattedXml -split "`n"
            if ($xmlLines.Count -eq 1) {
                Write-Host $formattedXml -ForegroundColor Gray
            } else {
                Write-Host ""
                foreach ($line in $xmlLines) {
                    if ($line.Trim()) {
                        Write-Host "  $line" -ForegroundColor Gray
                    }
                }
            }
        }
    }

    if (($ExcludeEventId.Count -gt 0 -or $ExcludeStrings.Count -gt 0) -and $filteredCount -gt 0) {
        Write-Host ""
        Write-Host "[INFO]: $filteredCount event logs filtered out by exclude parameters." -ForegroundColor DarkYellow
    }

    # Display Aggressive search results 
    if ($aggressiveResults.Count -gt 0) {
        Write-Host "`n`n----------------------------------------`n"
        Write-Host "[!] Aggressive File System Log Search`n" -ForegroundColor Red
        foreach ($result in $aggressiveResults) {
            Write-Host "----------------------------------------" -ForegroundColor Gray
            Write-Host "File Path        : " -NoNewline -ForegroundColor Yellow
            Write-Host $result.FilePath -ForegroundColor Cyan
            Write-Host "Creation Date    : " -NoNewline -ForegroundColor Yellow
            Write-Host $result.CreationDate.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor White
            Write-Host "Last Modified    : " -NoNewline -ForegroundColor Yellow
            Write-Host $result.LastModifiedDate.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor White
            Write-Host "Match            : " -NoNewline -ForegroundColor Yellow
            Write-Host $result.Match -ForegroundColor Red
            Write-Host "Text             : " -NoNewline -ForegroundColor Yellow
            Write-Host $result.Text -ForegroundColor Green
        }
    } elseif ($PSBoundParameters.ContainsKey('Aggressive')) {
        Write-Host "`n[X] No Filesystem Logs Found" -ForegroundColor Red
    }
    Write-Host "`n"
}

# HUNT-FILES
Function Hunt-Files {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        $StartDate,
        
        [Parameter(Mandatory=$false)]
        $EndDate="Now",
        
        [Parameter(Mandatory=$false)]
        [string[]]$Extensions = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$Content = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$Names = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$Hashes = @(),
        
        [Parameter(Mandatory=$false)]
        [int]$MaxSizeMB = 30,
        
        [Parameter(Mandatory=$false)]
        [string]$Timezone = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Path = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$AllDrives,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemFolders,
        
        [Parameter(Mandatory=$false)]
        [switch]$Hidden,
        
        [Parameter(Mandatory=$false)]
        [switch]$Recycled,
        
        [Parameter(Mandatory=$false)]
        [switch]$Streams,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxPrint = 0,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet(1,2,3)]
        [int]$Auto,
        
        [Parameter(Mandatory=$false)]
        [string]$Type = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$VerboseOutput
    )

    Write-Progress -Activity "Hunt-Files" -Status "Initializing..." -PercentComplete 0

    # Auto mode configurations
    if ($Auto) {
        $suspiciousExtensions = @(
            '.exe', '.dll', '.sys', '.scr', '.ocx', '.drv', '.com', '.pif', '.cpl',
            '.ps1', '.psm1', '.ps1xml', '.psc1', '.psd1',
            '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta',
            '.py', '.pyc', '.pyo', '.rb', '.pl', '.php', '.asp', '.aspx', '.jsp',
            '.zip', '.rar', '.7z', '.iso', '.img', '.cab', '.gz', '.tar', '.bz2',
            '.doc', '.docx', '.docm', '.dot', '.dotm', '.xls', '.xlsx', '.xlsm', 
            '.xlt', '.xltm', '.xlam', '.ppt', '.pptx', '.pptm', '.pot', '.potm',
            '.rtf', '.pub', '.one', '.odt', '.ods', '.odp',
            '.jar', '.class', '.war', '.ear',
            '.lnk', '.url', '.website',
            '.inf', '.reg', '.ini', '.xml', '.cfg', '.conf', '.config',
            '.msi', '.msp', '.mst',
            '.tmp', '.temp', '.bin', '.dat', '.log', '.dmp',
            '.db', '.sqlite', '.mdb', '.accdb',
            '.cer', '.crt', '.pem', '.p12', '.pfx', '.key',
            '.application', '.gadget', '.msc', '.ws'
        )
        
        switch ($Auto) {
            1 {
                if (!$StartDate -and $EndDate -eq "Now") {
                    $StartDate = (Get-Date).AddDays(-3)
                    $EndDate = Get-Date
                }
                $Extensions = @('.exe', '.dll', '.ps1', '.js', '.vbs', '.bat', '.cmd', '.scr')
            }
            2 {
                if (!$StartDate -and $EndDate -eq "Now") {
                    $StartDate = (Get-Date).AddDays(-7)
                    $EndDate = Get-Date
                }
                $Extensions = $suspiciousExtensions
                $IncludeSystemFolders = $true
            }
            3 {
                if (!$StartDate -and $EndDate -eq "Now") {
                    $StartDate = (Get-Date).AddDays(-30)
                    $EndDate = Get-Date
                }
                $Extensions = $suspiciousExtensions
                $IncludeSystemFolders = $true
            }
        }
    }

    # Timezone handling
    $systemTimeZone = [System.TimeZoneInfo]::Local
    
    function Get-TimezoneInfo {
        param($TimezoneName)
        
        $timezoneMap = @{
            'UTC' = 'UTC'; 'GMT' = 'GMT Standard Time'
            'EST' = 'Eastern Standard Time'; 'CST' = 'Central Standard Time'
            'MST' = 'Mountain Standard Time'; 'PST' = 'Pacific Standard Time'
            'EDT' = 'Eastern Standard Time'; 'CDT' = 'Central Standard Time'
            'MDT' = 'Mountain Standard Time'; 'PDT' = 'Pacific Standard Time'
        }
        
        $mappedName = if ($timezoneMap.ContainsKey($TimezoneName.ToUpper())) { 
            $timezoneMap[$TimezoneName.ToUpper()] 
        } else { 
            $TimezoneName 
        }
        
        try {
            if ($mappedName -eq 'UTC') {
                return [System.TimeZoneInfo]::Utc
            } else {
                return [System.TimeZoneInfo]::FindSystemTimeZoneById($mappedName)
            }
        } catch {
            throw "Invalid timezone: $TimezoneName"
        }
    }

    $targetTimeZone = if ([string]::IsNullOrWhiteSpace($Timezone)) { 
        $systemTimeZone 
    } else { 
        Get-TimezoneInfo -TimezoneName $Timezone 
    }

    # Date conversion function
    function ConvertTo-DateTime {
        param($InputValue, $TargetTimeZone)
        
        if ($InputValue -is [datetime]) {
            if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                return [System.TimeZoneInfo]::ConvertTime($InputValue, $TargetTimeZone, $systemTimeZone)
            }
            return $InputValue
        }
        
        if ($InputValue -is [string]) {
            $InputValue = $InputValue.Trim()
            
            if ($InputValue.ToLower() -eq 'now') {
                return Get-Date
            }
            
            # Handle relative time formats (1D, 4H, 10M)
            if ($InputValue -match '^(\d+)([DHMdhm])$') {
                $number = [int]$matches[1]
                $unit = $matches[2].ToUpper()
                
                $currentTime = Get-Date
                switch ($unit) {
                    'D' { return $currentTime.AddDays(-$number) }
                    'H' { return $currentTime.AddHours(-$number) }
                    'M' { return $currentTime.AddMinutes(-$number) }
                }
            }
            
            # Parse regular datetime strings
            try {
                $parsedDate = [datetime]$InputValue
                if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                    return [System.TimeZoneInfo]::ConvertTime($parsedDate, $TargetTimeZone, $systemTimeZone)
                }
                return $parsedDate
            } catch {
                throw "Invalid date format: $InputValue"
            }
        }
        
        throw "Invalid date input: $InputValue"
    }

    # Datetime formatting function
    function Format-DateTimeWithTimeZone {
        param($DateTime, $TargetTimeZone)
        
        if ($TargetTimeZone.Id -eq $systemTimeZone.Id) {
            $convertedTime = $DateTime
            $tzAbbrev = Get-TimezoneAbbreviation -TimeZone $systemTimeZone -DateTime $DateTime
        } else {
            $convertedTime = [System.TimeZoneInfo]::ConvertTime($DateTime, $systemTimeZone, $TargetTimeZone)
            $tzAbbrev = Get-TimezoneAbbreviation -TimeZone $TargetTimeZone -DateTime $convertedTime
        }
        
        return $convertedTime.ToString("yyyy-MM-dd HH:mm:ss") + " $tzAbbrev"
    }

    # Timezone abbreviation function
    function Get-TimezoneAbbreviation {
        param($TimeZone, $DateTime)
        
        if ($TimeZone.Id -eq 'UTC') { 
            return 'UTC' 
        }
        
        $isDST = $TimeZone.IsDaylightSavingTime($DateTime)
        
        if ($TimeZone.StandardName -like "*Eastern*") { 
            if ($isDST) { return 'EDT' } else { return 'EST' }
        }
        elseif ($TimeZone.StandardName -like "*Central*") { 
            if ($isDST) { return 'CDT' } else { return 'CST' }
        }
        elseif ($TimeZone.StandardName -like "*Mountain*") { 
            if ($isDST) { return 'MDT' } else { return 'MST' }
        }
        elseif ($TimeZone.StandardName -like "*Pacific*") { 
            if ($isDST) { return 'PDT' } else { return 'PST' }
        }
        else { 
            return $TimeZone.StandardName.Split(' ')[0] 
        }
    }

    # Stream handling function - optimized for PS5+
    function Get-FileStreams {
        param($FilePath)
        
        $streams = @()
        try {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $allStreams = @(Get-Item -Path $FilePath -Stream * -ErrorAction SilentlyContinue 2>$null)
                foreach ($stream in $allStreams) {
                    if ($stream.Stream -ne ':$DATA') {
                        $streams += [PSCustomObject]@{
                            StreamName = $stream.Stream
                            Size = $stream.Length
                        }
                    }
                }
            }
        } catch {
            # Return empty if we can't get streams
        }
        return $streams
    }

    # Content matching function - optimized
    function Get-ContentFromFile {
        param($FilePath, $StreamName = '', $MaxSize)
        
        try {
            $streamPath = if ([string]::IsNullOrEmpty($StreamName) -or $StreamName -eq ':$DATA') {
                $FilePath
            } else {
                "${FilePath}:${StreamName}"
            }
            
            $fileInfo = Get-Item -Path $FilePath -Force -ErrorAction Stop
            if ($fileInfo.Length -gt $MaxSize -or $fileInfo.Length -eq 0) { 
                return '' 
            }
            
            $content = Get-Content -Path $streamPath -Raw -Encoding UTF8 -ErrorAction Stop
            return $content
        } catch {
            return ''
        }
    }

    # Hash computation function - optimized
    function Get-FileHashCustom {
        param($FilePath, $StreamName = '', $Algorithm)
        
        try {
            $streamPath = if ([string]::IsNullOrEmpty($StreamName) -or $StreamName -eq ':$DATA') {
                $FilePath
            } else {
                "${FilePath}:${StreamName}"
            }
            
            $hash = Get-FileHash -Path $streamPath -Algorithm $Algorithm -ErrorAction Stop
            return $hash.Hash.ToLower()
        } catch {
            return ""
        }
    }

    Write-Progress -Activity "Hunt-Files" -Status "Validating parameters..." -PercentComplete 10

    # Parameter validation
    if ($MaxSizeMB -le 0) {
        Write-Error "MaxSizeMB must be greater than 0"
        return
    }

    # Normalize Type parameter - now case insensitive
    $filterType = ""
    if (![string]::IsNullOrWhiteSpace($Type)) {
        switch ($Type.ToUpper()) {
            { $_ -in @("FILE", "F") } { $filterType = "FILE" }
            { $_ -in @("DIR", "DIRECTORY", "D") } { $filterType = "DIR" }
            default { 
                Write-Error "Invalid Type parameter. Valid values: FILE, F, DIR, DIRECTORY, D (case insensitive)"
                return
            }
        }
    }

    # Determine search paths
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($AllDrives) {
            try {
                $searchPaths = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop | Where-Object { $_.Used -ge 0 } | ForEach-Object { $_.Root })
            } catch {
                Write-Error "Failed to get drive information: $($_.Exception.Message)"
                return
            }
        } else {
            $searchPaths = @("$((Get-Location).Drive.Name):\")
        }
    } else {
        $searchPath = $Path.TrimEnd('\')
        if (-not (Test-Path $searchPath)) {
            Write-Error "Specified path does not exist: $searchPath"
            return
        }
        $searchPaths = @($searchPath)
    }

    # Date range handling - simplified logic
    $hasDateRange = $null -ne $StartDate -or $EndDate -ne "Now"
    $hasOtherCriteria = $Extensions.Count -gt 0 -or $Content.Count -gt 0 -or $Names.Count -gt 0 -or $Hashes.Count -gt 0 -or $Hidden -or $Recycled -or $Streams -or $Auto
    
    if (!$hasDateRange -and !$hasOtherCriteria) {
        $StartDate = (Get-Date).AddDays(-7)
        $EndDate = Get-Date
        $hasDateRange = $true
    } elseif ($null -ne $StartDate -and $EndDate -eq "Now") {
        $EndDate = Get-Date
    } elseif ($null -eq $StartDate -and $EndDate -ne "Now") {
        throw "EndDate specified but StartDate is missing. Please provide both dates or neither."
    }

    # Convert dates
    $parsedStartDate = $null
    $parsedEndDate = $null
    
    if ($hasDateRange) {
        try {
            $parsedStartDate = if ($null -ne $StartDate) { ConvertTo-DateTime -InputValue $StartDate -TargetTimeZone $targetTimeZone } else { $null }
            $parsedEndDate = if ($EndDate -ne "Now") { ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone $targetTimeZone } else { ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone $targetTimeZone }
        } catch {
            throw "Date parsing error: $($_.Exception.Message)"
        }
    }

    # Validate search criteria
    $hasSearchCriteria = $parsedStartDate -or $parsedEndDate -or $Extensions.Count -gt 0 -or $Content.Count -gt 0 -or $Names.Count -gt 0 -or $Hashes.Count -gt 0 -or $Auto -or $Hidden -or $Recycled -or $Streams
    
    if (-not $hasSearchCriteria) {
        Write-Error "At least one search criteria must be provided"
        return
    }

    Write-Progress -Activity "Hunt-Files" -Status "Processing criteria..." -PercentComplete 20

    # Normalize search criteria
    $normalizedHashes = @{}
    foreach ($hash in $Hashes) {
        try {
            $cleanHash = $hash.Trim().ToLower() -replace '[^a-f0-9]', ''
            $hashType = switch ($cleanHash.Length) {
                32  { 'MD5' }
                40  { 'SHA1' }
                64  { 'SHA256' }
                default { 
                    Write-Warning "Invalid hash format: $hash"
                    continue 
                }
            }
            $normalizedHashes[$cleanHash] = $hashType
        } catch {
            Write-Warning "Error processing hash '$hash': $($_.Exception.Message)"
        }
    }

    # Normalize extensions and names
    if ($Extensions.Count -gt 0) {
        $Extensions = @($Extensions | ForEach-Object { 
            $ext = $_.ToLower().Trim()
            if (-not $ext.StartsWith('.')) { ".$ext" } else { $ext }
        })
    }

    if ($Names.Count -gt 0) {
        $Names = @($Names | ForEach-Object { $_.Trim() })
    }

    $maxSizeBytes = [long]$MaxSizeMB * 1MB
    $systemFolders = @("$env:windir", "$env:ProgramFiles", "${env:ProgramFiles(x86)}")

    # Initialize counters
    $filesMatched = 0
    $foldersMatched = 0
    $streamMatches = 0
    $totalStreamsFound = 0
    $results = @()
    $totalOutputChars = 0

    Write-Progress -Activity "Hunt-Files" -Status "Scanning filesystem..." -PercentComplete 30

    # Main scanning loop - optimized
    foreach ($currentSearchPath in $searchPaths) {
        try {
            $searchSubPaths = @($currentSearchPath)
            
            # Add recycle bin paths if needed
            if ($Recycled -or $currentSearchPath -match '^[A-Za-z]:\\$') {
                $driveLetter = $currentSearchPath.Substring(0, 1)
                $recycleBinPaths = @("${driveLetter}:\`$Recycle.Bin", "${driveLetter}:\RECYCLER")
                $availableRecycleBinPaths = @($recycleBinPaths | Where-Object { Test-Path $_ })
                if ($Recycled -or $availableRecycleBinPaths.Count -gt 0) {
                    $searchSubPaths += $availableRecycleBinPaths
                }
            }

            foreach ($subPath in $searchSubPaths) {
                try {
                    # Optimized file enumeration
                    $pathItems = @(Get-ChildItem -Path $subPath -Recurse -Force -ErrorAction SilentlyContinue)
                    
                    # Filter out system folders if not included - optimized check
                    if (-not $IncludeSystemFolders -and -not $Recycled) {
                        $pathItems = @($pathItems | Where-Object {
                            $itemPath = $_.FullName
                            -not ($systemFolders | Where-Object { $itemPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })
                        })
                    }

                    foreach ($item in $pathItems) {
                        try {
                            $isDirectory = $item.PSIsContainer
                            $itemMatchReasons = @()
                            $matchedContent = @()
                            $matchedNames = @()
                            $finalHash = ""
                            $sha256 = ""
                            $streamInfo = ""
                            $alternateStreams = @()

                            # Check attributes - optimized
                            $itemIsHidden = ($item.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                            $itemIsRecycleBin = ($item.FullName -like "*`$Recycle.Bin*" -or $item.FullName -like "*RECYCLER*")

                            # Get streams only when needed
                            if (-not $isDirectory -and ($Streams -or $Content.Count -gt 0)) {
                                try {
                                    $alternateStreams = @(Get-FileStreams -FilePath $item.FullName)
                                    $totalStreamsFound += $alternateStreams.Count
                                } catch {
                                    # Continue if we can't get stream info
                                }
                            }

                            # Special switches - additive logic
                            $specialSwitchMatch = $false

                            if ($Hidden -and $itemIsHidden) {
                                $itemMatchReasons += "Hidden"
                                $specialSwitchMatch = $true
                            }

                            if ($Recycled -and $itemIsRecycleBin) {
                                $itemMatchReasons += "Deleted"
                                $specialSwitchMatch = $true
                            }

                            if ($Streams -and -not $isDirectory -and $alternateStreams.Count -gt 0) {
                                $streamNames = ($alternateStreams | ForEach-Object { $_.StreamName }) -join ','
                                $itemMatchReasons += "ADS:$streamNames"
                                $streamMatches++
                                $specialSwitchMatch = $true
                                
                                $streamDetails = @()
                                foreach ($stream in $alternateStreams) {
                                    $streamDetails += "$($stream.StreamName)($($stream.Size) bytes)"
                                }
                                $streamInfo = $streamDetails -join ';'
                            }

                            # Regular search criteria
                            if (-not $specialSwitchMatch) {
                                # Date range matching - optimized
                                if ($parsedStartDate -and $parsedEndDate) {
                                    $dateMatches = @()
                                    
                                    if ($item.CreationTime -ge $parsedStartDate -and $item.CreationTime -le $parsedEndDate) {
                                        $dateMatches += "Created"
                                    }
                                    if ($item.LastWriteTime -ge $parsedStartDate -and $item.LastWriteTime -le $parsedEndDate) {
                                        $dateMatches += "Modified"
                                    }
                                    if ($item.LastAccessTime -ge $parsedStartDate -and $item.LastAccessTime -le $parsedEndDate) {
                                        $dateMatches += "Accessed"
                                    }
                                    
                                    if ($dateMatches.Count -gt 0) {
                                        $itemMatchReasons += "Date:$($dateMatches -join '/')"
                                    }
                                }

                                # Name matching - optimized
                                if ($Names.Count -gt 0) {
                                    $fileName = $item.Name
                                    $matchedNames = @($Names | Where-Object { $fileName -like "*$_*" })
                                    
                                    if ($matchedNames.Count -gt 0) {
                                        $itemMatchReasons += "Name:$($matchedNames -join ',')"
                                    }
                                }

                                # Extension matching - optimized
                                if ($Extensions.Count -gt 0 -and -not $isDirectory) {
                                    $itemExt = $item.Extension.ToLower()
                                    if ($Extensions -contains $itemExt) {
                                        $itemMatchReasons += "Ext:$itemExt"
                                    }
                                }

                                # Content matching - check file size first for performance
                                if ($Content.Count -gt 0 -and -not $isDirectory -and $item.Length -le $maxSizeBytes -and $item.Length -gt 0) {
                                    $allStreamMatches = @()
                                    
                                    try {
                                        # Check main stream
                                        $fileContent = Get-ContentFromFile -FilePath $item.FullName -MaxSize $maxSizeBytes
                                        if (![string]::IsNullOrEmpty($fileContent)) {
                                            $mainStreamMatches = @($Content | Where-Object { $fileContent -like "*$_*" })
                                            if ($mainStreamMatches.Count -gt 0) {
                                                $allStreamMatches += $mainStreamMatches | ForEach-Object { "$_(:DATA)" }
                                            }
                                        }
                                        
                                        # Check alternate streams
                                        foreach ($stream in $alternateStreams) {
                                            if ($stream.Size -le $maxSizeBytes -and $stream.Size -gt 0) {
                                                $streamContent = Get-ContentFromFile -FilePath $item.FullName -StreamName $stream.StreamName -MaxSize $maxSizeBytes
                                                if (![string]::IsNullOrEmpty($streamContent)) {
                                                    $streamContentMatches = @($Content | Where-Object { $streamContent -like "*$_*" })
                                                    if ($streamContentMatches.Count -gt 0) {
                                                        $allStreamMatches += $streamContentMatches | ForEach-Object { "$_($($stream.StreamName))" }
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if ($allStreamMatches.Count -gt 0) {
                                            $itemMatchReasons += "Content:$($allStreamMatches -join ',')"
                                            $matchedContent = $allStreamMatches
                                        }
                                    } catch {
                                        # Skip files we can't read
                                    }
                                }

                                # Hash matching - optimized
                                if ($normalizedHashes.Count -gt 0 -and -not $isDirectory) {
                                    $hashMatches = @()
                                    
                                    try {
                                        # Check main stream
                                        foreach ($hashEntry in $normalizedHashes.GetEnumerator()) {
                                            $targetHash = $hashEntry.Key
                                            $algo = $hashEntry.Value
                                            
                                            $computedHash = Get-FileHashCustom -FilePath $item.FullName -Algorithm $algo
                                            if ($computedHash -eq $targetHash) {
                                                $hashMatches += "$algo($targetHash):DATA"
                                                if ([string]::IsNullOrEmpty($finalHash)) {
                                                    $finalHash = $computedHash
                                                }
                                            }
                                        }
                                        
                                        # Check alternate streams
                                        foreach ($stream in $alternateStreams) {
                                            foreach ($hashEntry in $normalizedHashes.GetEnumerator()) {
                                                $targetHash = $hashEntry.Key
                                                $algo = $hashEntry.Value
                                                
                                                $computedHash = Get-FileHashCustom -FilePath $item.FullName -StreamName $stream.StreamName -Algorithm $algo
                                                if ($computedHash -eq $targetHash) {
                                                    $hashMatches += "$algo($targetHash):$($stream.StreamName)"
                                                    if ([string]::IsNullOrEmpty($finalHash)) {
                                                        $finalHash = $computedHash
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if ($hashMatches.Count -gt 0) {
                                            $itemMatchReasons += "Hash:$($hashMatches -join ',')"
                                        }
                                        
                                        # Always compute SHA256 for matched files if not already done
                                        if ($itemMatchReasons.Count -gt 0 -and [string]::IsNullOrEmpty($sha256)) {
                                            $sha256 = Get-FileHashCustom -FilePath $item.FullName -Algorithm 'SHA256'
                                            if ([string]::IsNullOrEmpty($finalHash)) {
                                                $finalHash = $sha256
                                            }
                                        }
                                    } catch {
                                        # Skip files we can't hash
                                    }
                                }
                            }

                            # Include item if any criteria matched
                            if ($itemMatchReasons.Count -gt 0) {
                                if ($isDirectory) {
                                    $foldersMatched++
                                } else {
                                    $filesMatched++
                                    # Compute SHA256 for files if not done yet
                                    if ([string]::IsNullOrEmpty($sha256)) {
                                        try {
                                            $sha256 = Get-FileHashCustom -FilePath $item.FullName -Algorithm 'SHA256'
                                            if ([string]::IsNullOrEmpty($finalHash)) {
                                                $finalHash = $sha256
                                            }
                                        } catch {
                                            # Skip if can't compute hash
                                        }
                                    }
                                }
                                
                                $result = [PSCustomObject]@{
                                    FullPath = $item.FullName
                                    Name = $item.Name
                                    IsDirectory = $isDirectory
                                    SizeMB = if ($isDirectory) { 0 } else { [math]::Round($item.Length / 1MB, 4) }
                                    CreationTime = $item.CreationTime
                                    LastWriteTime = $item.LastWriteTime
                                    LastAccessTime = $item.LastAccessTime
                                    Hash = $finalHash
                                    SHA256 = $sha256
                                    MatchReason = ($itemMatchReasons -join " | ")
                                    MatchedContent = ($matchedContent -join ', ')
                                    MatchedNames = ($matchedNames -join ', ')
                                    IsHidden = $itemIsHidden
                                    IsRecycleBin = $itemIsRecycleBin
                                    StreamInfo = $streamInfo
                                    AlternateStreamCount = $alternateStreams.Count
                                }
                                
                                $results += $result
                            }
                        } catch {
                            if ($VerboseOutput) {
                                Write-Warning "Error processing item $($item.FullName): $($_.Exception.Message)"
                            }
                        }
                    }
                } catch {
                    if ($VerboseOutput) {
                        Write-Warning "Error accessing path $subPath : $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            if ($VerboseOutput) {
                Write-Warning "Error accessing path $currentSearchPath : $($_.Exception.Message)"
            }
        }
    }

    Write-Progress -Activity "Hunt-Files" -Status "Displaying results..." -PercentComplete 80

    # Sort and display results
    $sortedResults = @($results | Sort-Object LastWriteTime -Descending)

    # Apply Type filter before displaying results
    if (![string]::IsNullOrWhiteSpace($filterType)) {
        if ($filterType -eq "FILE") {
            $sortedResults = @($sortedResults | Where-Object { -not $_.IsDirectory })
        } elseif ($filterType -eq "DIR") {
            $sortedResults = @($sortedResults | Where-Object { $_.IsDirectory })
        }
    }

    foreach ($result in $sortedResults) {
        $streamInfoSize = if (![string]::IsNullOrEmpty($result.StreamInfo)) { $result.StreamInfo.Length } else { 0 }
        $eventOutputSize = 500 + $result.FullPath.Length + $result.MatchReason.Length + $result.MatchedContent.Length + $streamInfoSize
        
        if ($MaxPrint -gt 0 -and ($totalOutputChars + $eventOutputSize -gt $MaxPrint)) {
            $remainingResults = $sortedResults.Count - ([array]::IndexOf($sortedResults, $result))
            Write-Host ""
            Write-Host "Output truncated: MaxPrint limit ($MaxPrint characters) reached. $remainingResults more items available." -ForegroundColor DarkRed
            break
        }

        $totalOutputChars += $eventOutputSize

        $itemType = if ($result.IsDirectory) { "[DIR]" } else { "[FILE]" }
        
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host "Type         : $itemType" -ForegroundColor Yellow
        Write-Host "Path         : $($result.FullPath)" -ForegroundColor Cyan
        Write-Host "Filename     : $($result.Name)" -ForegroundColor White
        
        if (-not $result.IsDirectory) {
            Write-Host "Size         : $($result.SizeMB) MB" -ForegroundColor White
        }
        
        Write-Host "Created      : $(Format-DateTimeWithTimeZone -DateTime $result.CreationTime -TargetTimeZone $targetTimeZone)" -ForegroundColor White
        Write-Host "Modified     : $(Format-DateTimeWithTimeZone -DateTime $result.LastWriteTime -TargetTimeZone $targetTimeZone)" -ForegroundColor White
        Write-Host "Accessed     : $(Format-DateTimeWithTimeZone -DateTime $result.LastAccessTime -TargetTimeZone $targetTimeZone)" -ForegroundColor White
        
        if (-not $result.IsDirectory -and ![string]::IsNullOrWhiteSpace($result.SHA256)) {
            Write-Host "SHA256       : $($result.SHA256)" -ForegroundColor Gray
        }
        
        Write-Host "Match        : $($result.MatchReason)" -ForegroundColor Red
        
        if (![string]::IsNullOrWhiteSpace($result.MatchedContent)) {
            Write-Host "Content Match: $($result.MatchedContent)" -ForegroundColor Green
        }
        
        if (![string]::IsNullOrWhiteSpace($result.MatchedNames)) {
            Write-Host "Name Match   : $($result.MatchedNames)" -ForegroundColor Green
        }
        
        # Show stream information
        if ($result.AlternateStreamCount -gt 0) {
            Write-Host "Streams [$($result.AlternateStreamCount)]  : $($result.StreamInfo)" -ForegroundColor Green
        }
        
        # Show special attributes
        $attributes = @()
        if ($result.IsHidden) { $attributes += "Hidden" }
        if ($result.IsRecycleBin) { $attributes += "Recycle Bin" }
        if ($attributes.Count -gt 0) {
            Write-Host "Attributes   : $($attributes -join ', ')" -ForegroundColor DarkYellow
        }
    }

    Write-Progress -Activity "Hunt-Files" -Status "Complete" -PercentComplete 100

    # Summary
    if ($results.Count -eq 0) {
        Write-Host "[!] No items found matching the specified criteria." -ForegroundColor Yellow
    } else {
        $totalMatched = $filesMatched + $foldersMatched
        $displayedCount = $sortedResults.Count
        
        $summaryParts = @()
        if (![string]::IsNullOrWhiteSpace($filterType)) {
            $filterDescription = if ($filterType -eq "FILE") { "files" } else { "directories" }
            $summaryParts += "[+] Search completed. Found $totalMatched total items ($filesMatched files, $foldersMatched folders). Showing $displayedCount $filterDescription."
        } else {
            $summaryParts += "[+] Search completed. Found $totalMatched matching items ($filesMatched files, $foldersMatched folders)."
        }
        
        if ($Streams -and $streamMatches -gt 0) {
            $summaryParts += "Files with ADS: $streamMatches. Total ADS discovered: $totalStreamsFound"
        }
        
        Write-Host "$($summaryParts -join ' ')" -ForegroundColor Green
    }

    Write-Progress -Completed -Activity "Hunt-Files"
    Write-Host ""
}