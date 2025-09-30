#requires -version 5.0

# DFIR-Hunter Module

# ------------------
# Module Manifest (Completed):
# =================
# [X] Hunt-Persistence
# [X] Hunt-Logs
# [X] Hunt-Files
# [X] Hunt-Tasks
# [X] Hunt-Browser
# [X] Hunt-Registry
# [X] Hunt-Services
# [X] Hunt-VirusTotal
#
# [...] 
#
#
#
# Get PowerShell History - Shell Console History [  "Get-Content (Get-PSReadlineOption).HistorySavePath"  ]
# Get Run MRU key
# Get-DnsClientCache
# Function for getting system info (listing if in domain, timezone, basic system info i like to use)
#
#
# Make each function be able to export to CSV, then add all to an HTML website
# 
# []  Hunt-All: Auto mode for all
# []  Hunt-All -ForensicDump.... Use each function to build a forensic report of a machine in CSV/html/JS/webpage format (i.e. all tasks, all files with their hash, all autoruns, all logs, etc.)
#
# []  *Hunt-All --------> Also add generic filename recursive searching. User can input hashtable of IOCs, and it will call the subfucntions appropriately


# Hunt-All


# -------------------

# add signatures functionality to the hunt-files feature 


#   Global Notes:
# -----------------

# - Finish the "Hunt-All" handler. Auto hunting and ForensicImaging and Output to HTML report.
# - Make Wiki
# - Review each function: Give full description for wiki page (every parameter and feature), and give examples, and make sure to LIST ANY NECESSARY ASSEMBLY IMPORTS (need this for the module manifest)
# - Compile and publish Executable as well??? (maybe for the forensic collection/exporting)
# - Rename and standardize variable names!
# - Do another review of all fucntions for critical errors (i updated the variables to match eachother)
# - For the final export forensic image--- try get an HTML with pages like ("Autoruns',"Filesystem","SystemInfo")-- and run multiple subqueries for the files tab; get things like Recyeld files, ADS files, deleted files, etc.... each tab has complete output-- use multiple subfunction runs with -PassThru...
# - Will have to spend genuine time building and tuning the IOC and string lists

# ---------------------------------------------------------
# Script Variables

# Hunt-Persistence
$script:SuspiciousStringIOCs = @(
    "client32.exe",
    "client32.ini", 
    "xmrig",
    "onestart",
    "update.js"
)
$script:AggressiveStringIOCs = @(
    "-ExecutionPolicy Bypass",
    "-ep bypass", 
    "-ex bypass",
    "-WindowStyle Hidden",
    "-w hidden",
    "-NoProfile",
    "-nop",
    "-NonInteractive", 
    "-noni",
    "-EncodedCommand",
    "-enc"
)
$script:InsaneStringIOCs = @("-e ", '\Temp\', '\AppData\', '\Users\')
$script:suspiciousFileExt = @('.vbs', '.js', '.bat', '.cmd', '.ps1', '.wsf', '.hta', '.jar', '.py', '.pl', '.conf')
$script:suspiciousPaths = @('%TEMP%', '%APPDATA%', '%USERPROFILE%')
# Shared, Already exists below --- $script:suspiciousTLDs = @('.top', '.xyz', '.shop', '.dev', '.ru', '.cn')
$script:executionBinaries = @('PowerShell.exe', 'CMD.exe', 'Node.exe', 'wscript.exe')

# Browser Related (Hunt-Browser)
$script:suspiciousBrowserStrings = @(
    'file://', 'http:', 'https:', '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', 'C:\', '://'
)

$script:aggressiveBrowserStrings = @(
    'file', 'download', 'login', 'password', 'admin', 'exploit', 'payload', 'shell', 
    'reverse', 'bypass', 'hidden', 'encoded'
)

$script:suspiciousTLDs = @(
    '.top', '.xyz', '.shop', '.dev', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf',
    '.pw', '.cc', '.click', '.download', '.work', '.link', '.site', '.online',
    '.website', '.space', '.tech', '.store', '.bid', '.win', '.review', '.trade',
    '.date', '.racing', '.cricket', '.science', '.party', '.gq', '.zip'
)

$script:PossibleTLDs = @(
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.co', '.io', '.me',
    '.tv', '.cc', '.ws', '.biz', '.info', '.name', '.pro', '.museum', '.coop',
    '.aero', '.jobs', '.mobi', '.travel', '.tel', '.asia', '.xxx', '.post',
    '.uk', '.ca', '.au', '.de', '.jp', '.fr', '.br', '.it', '.nl', '.be',
    '.es', '.pl', '.no', '.se', '.dk', '.fi', '.ch', '.at', '.cz', '.hu'
)

# Hunt Logs
$script:GlobalLogIOCs = @(
    "mimikatz", "sekurlsa", "lsadump", "kerberoast", "bloodhound", "sharphound",
    "powersploit", "invoke-mimikatz", "dump-sam", "ntds.dit", "hashdump",
    "lateral movement", "psexec", "wmiexec", "smbexec", "winrm", "dcom",
    "credential dumping", "token impersonation", "golden ticket", "silver ticket",
    "dcsync", "zerologon", "printspoofer", "juicypotato", "rottenpotatong",
    "cobalt strike", "beacon", "malleable", "stageless", "stager",
    "metasploit", "meterpreter", "payload", "shellcode", "reflective dll",
    "process hollowing", "dll injection", "thread injection", "atom bombing",
    "suspicious powershell", "encoded command", "bypass execution policy",
    "invoke-expression", "downloadstring", "webclient", "bitstransfer",
    "certutil", "regsvr32", "rundll32", "mshta", "cscript", "wscript",
    "living off the land", "lolbin", "applocker bypass", "uac bypass",
    "privilege escalation", "persistence", "startup folder", "registry run",
    "scheduled task", "wmi event", "com hijacking", "dll search order",
    "suspicious network", "c2", "command and control", "exfiltration",
    "dns tunneling", "icmp tunneling", "suspicious outbound", "tor",
    "proxy", "vpn", "anonymization", "data staging", "archive", "compression"
)


# Function Exports


function Hunt-All {
    <#
    .SYNOPSIS
    Hunt-All orchestrates comprehensive DFIR data collection using all Hunt modules.
    
    .DESCRIPTION
    Hunt-All is a master function that coordinates all Hunt-* modules for comprehensive
    forensic data collection, IOC searching, and HTML report generation. It supports
    multiple modes of operation and can generate a complete forensic dump with an
    interactive HTML report containing system info, persistence, filesystem, registry,
    browser history, event logs, services, and scheduled tasks.
    
    .PARAMETER StartDate
    Start date for searches. Accepts datetime, relative formats (3D, 24H), or 'Now'.
    
    .PARAMETER EndDate
    End date for searches. Defaults to 'Now'.
    
    .PARAMETER Auto
    Run in automatic mode with balanced detection settings.
    
    .PARAMETER Aggressive
    Run in aggressive mode with comprehensive detection settings.
    
    .PARAMETER ForensicDump
    Generate complete forensic dump with HTML report and CSV exports.
    
    .PARAMETER SystemInfo
    Display comprehensive system information.
    
    .PARAMETER Search
    Hashtable of IOC searches by type: @{browser='string';file='string';log='string';task='string';reg='string'}
    
    .PARAMETER ExportLogs
    Export all EVTX files to archive.
    
    .PARAMETER OutputDir
    Directory for forensic dump output. Default: C:\ForensicDump_[timestamp]
    
    .EXAMPLE
    Hunt-All -ForensicDump -StartDate "7D" -Auto
    
    .EXAMPLE
    Hunt-All -Search @{file='*.exe';log='powershell';reg='malware'} -Aggressive
    
    .EXAMPLE
    Hunt-All -SystemInfo
    
    .EXAMPLE
    Hunt-All -ForensicDump -ExportLogs -Search @{browser='evil.com'} -StartDate "30D"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $StartDate,
        
        [Parameter(Mandatory = $false)]
        $EndDate = "Now",
        
        [Parameter(Mandatory = $false)]
        [switch]$Auto,
        
        [Parameter(Mandatory = $false)]
        [switch]$Aggressive,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForensicDump,
        
        [Parameter(Mandatory = $false)]
        [switch]$SystemInfo,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Search = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$ExportLogs,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Timezone = ""
    )
	

    # Helper function to process Search parameter with 'all' support
    function Expand-SearchTerms {
        param([hashtable]$SearchHash)
    
        $expanded = @{}
    
        # If 'all' key exists, add it to every category
        $allTerms = @()
        if ($SearchHash.ContainsKey('all')) {
            $allTerms = @($SearchHash['all'])
        }
    
        # Process each search category
        $categories = @('browser', 'file', 'log', 'task', 'reg', 'service', 'persistence')
        foreach ($category in $categories) {
            $terms = @()
        
            # Add category-specific terms
            if ($SearchHash.ContainsKey($category)) {
                $terms += $SearchHash[$category]
            }
        
            # Add 'all' terms to every category
            $terms += $allTerms
        
            if ($terms.Count -gt 0) {
                $expanded[$category] = $terms | Select-Object -Unique
            }
        }
    
        return $expanded
    }

    $expandedSearch = Expand-SearchTerms -SearchHash $Search

    # Helper function: Get System Information
    function Get-SystemInformation {
        param(
            [string]$OutputDir,
            [switch]$ForensicDump
        )
    
        $sysInfo = @{}
    
        try {
            # Basic system info
            Write-Host "  [-] Gathering basic system info..." -ForegroundColor DarkGray
            $sysInfo.ComputerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
            $sysInfo.OSInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        
            # Domain information
            Write-Host "  [-] Checking domain status..." -ForegroundColor DarkGray
            try {
                $sysInfo.Domain = (Get-WmiObject Win32_ComputerSystem).Domain
                $sysInfo.IsDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
            }
            catch {
                $sysInfo.Domain = "WORKGROUP"
                $sysInfo.IsDomainJoined = $false
            }
        
            # PowerShell history
            Write-Host "  [-] Extracting PowerShell history..." -ForegroundColor DarkGray
            try {
                $histPath = (Get-PSReadlineOption).HistorySavePath
                if (Test-Path $histPath) {
                    $sysInfo.PSHistory = Get-Content $histPath -ErrorAction SilentlyContinue
                }
            }
            catch {}
        
            # Run MRU
            Write-Host "  [-] Getting Run MRU..." -ForegroundColor DarkGray
            try {
                $runMRU = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
                if ($runMRU) {
                    $sysInfo.RunMRU = $runMRU.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | Select-Object Name, Value
                }
            }
            catch {}
        
            # DNS Cache
            Write-Host "  [-] Getting DNS cache..." -ForegroundColor DarkGray
            try {
                $sysInfo.DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            }
            catch {}
        
            # Users and sessions
            Write-Host "  [-] Enumerating users and sessions..." -ForegroundColor DarkGray
            $sysInfo.LoggedOnUsers = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue
            $sysInfo.LocalUsers = Get-LocalUser -ErrorAction SilentlyContinue
            $sysInfo.LocalGroups = Get-LocalGroup -ErrorAction SilentlyContinue
            $sysInfo.LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            $sysInfo.UserProfiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue
        
            # Network connections
            Write-Host "  [-] Getting network connections..." -ForegroundColor DarkGray
            $sysInfo.NetworkConnections = Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue
            $sysInfo.NetworkAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
            $sysInfo.IPConfiguration = Get-NetIPConfiguration -ErrorAction SilentlyContinue
            $sysInfo.DNSServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
            $sysInfo.FirewallRules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 100
        
            # Processes
            Write-Host "  [-] Enumerating processes..." -ForegroundColor DarkGray
            $sysInfo.Processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
            Select-Object Id, ProcessName, Path, Company, Product, Description, UserName, CPU, WS, StartTime
        
            # System timing
            Write-Host "  [-] Getting system timing info..." -ForegroundColor DarkGray
            $sysInfo.BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $sysInfo.LocalTime = Get-Date
            $sysInfo.TimeZone = Get-TimeZone
            $sysInfo.Uptime = (Get-Date) - $sysInfo.BootTime

            # Volume Shadow Copy information
            Write-Host "  [-] Checking Volume Shadow Copies..." -ForegroundColor DarkGray
            try {
                $sysInfo.ShadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue | 
                Select-Object ID, InstallDate, VolumeName, @{N = 'SizeMB'; E = { [math]::Round($_.AllocatedSpace / 1MB, 2) } }
                $sysInfo.ShadowCopyCount = if ($sysInfo.ShadowCopies) { $sysInfo.ShadowCopies.Count } else { 0 }
                
                # Check if VSS service is running
                $vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue
                $sysInfo.VSSServiceStatus = if ($vssService) { $vssService.Status } else { "Not Found" }
            }
            catch {
                $sysInfo.ShadowCopies = @()
                $sysInfo.ShadowCopyCount = 0
                $sysInfo.VSSServiceStatus = "Error"
            }
        
            # Security software
            Write-Host "  [-] Checking security software..." -ForegroundColor DarkGray
            try {
                $sysInfo.AntiVirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
                $sysInfo.DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            }
            catch {}
        
            # Display or export results
            if (-not $ForensicDump) {
                # Display to console
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "         SYSTEM INFORMATION" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Cyan
            
                Write-Host ""
                Write-Host "--- Basic Info ---" -ForegroundColor Yellow
                Write-Host "Hostname         : " -NoNewline -ForegroundColor Yellow
                Write-Host $env:COMPUTERNAME -ForegroundColor White
                Write-Host "Domain           : " -NoNewline -ForegroundColor Yellow
                Write-Host "$($sysInfo.Domain) (Joined: $($sysInfo.IsDomainJoined))" -ForegroundColor White
                Write-Host "OS               : " -NoNewline -ForegroundColor Yellow
                Write-Host "$($sysInfo.OSInfo.Caption) $($sysInfo.OSInfo.Version)" -ForegroundColor White
                Write-Host "Architecture     : " -NoNewline -ForegroundColor Yellow
                Write-Host $sysInfo.OSInfo.OSArchitecture -ForegroundColor White
                Write-Host "Boot Time        : " -NoNewline -ForegroundColor Yellow
                Write-Host $sysInfo.BootTime -ForegroundColor White
                Write-Host "Uptime           : " -NoNewline -ForegroundColor Yellow
                Write-Host "$($sysInfo.Uptime.Days)d $($sysInfo.Uptime.Hours)h $($sysInfo.Uptime.Minutes)m" -ForegroundColor White
                Write-Host "Time Zone        : " -NoNewline -ForegroundColor Yellow
                Write-Host $sysInfo.TimeZone.DisplayName -ForegroundColor White

                # Display VSS info
                if ($sysInfo.ShadowCopyCount -ne $null) {
                    Write-Host ""
                    Write-Host "--- Volume Shadow Copies ---" -ForegroundColor Yellow
                    Write-Host "VSS Service      : " -NoNewline -ForegroundColor Yellow
                    $vssColor = if ($sysInfo.VSSServiceStatus -eq "Running") { "Green" } else { "Red" }
                    Write-Host $sysInfo.VSSServiceStatus -ForegroundColor $vssColor
                    Write-Host "Shadow Copies    : " -NoNewline -ForegroundColor Yellow
                    $countColor = if ($sysInfo.ShadowCopyCount -eq 0) { "Red" } else { "Green" }
                    Write-Host "$($sysInfo.ShadowCopyCount) found" -ForegroundColor $countColor
                    
                    if ($sysInfo.ShadowCopies -and $sysInfo.ShadowCopies.Count -gt 0) {
                        Write-Host ""
                        foreach ($shadow in $sysInfo.ShadowCopies) {
                            Write-Host "  ID: $($shadow.ID)" -ForegroundColor DarkGray
                            Write-Host "    Created: $($shadow.InstallDate)" -ForegroundColor DarkGray
                            Write-Host "    Volume: $($shadow.VolumeName)" -ForegroundColor DarkGray
                            Write-Host "    Size: $($shadow.SizeMB) MB" -ForegroundColor DarkGray
                        }
                    }
                }
            
                Write-Host ""
                Write-Host "--- Users ---" -ForegroundColor Yellow
                Write-Host "Local Users      : " -NoNewline -ForegroundColor Yellow
                Write-Host ($sysInfo.LocalUsers.Name -join ", ") -ForegroundColor White
                Write-Host "Local Admins     : " -NoNewline -ForegroundColor Yellow
                Write-Host ($sysInfo.LocalAdmins.Name -join ", ") -ForegroundColor White
            
                Write-Host ""
                Write-Host "--- Network ---" -ForegroundColor Yellow
                Write-Host "Active Connections: " -NoNewline -ForegroundColor Yellow
                Write-Host "$($sysInfo.NetworkConnections.Count) connections" -ForegroundColor White
                Write-Host "Network Adapters : " -NoNewline -ForegroundColor Yellow
                Write-Host ($sysInfo.NetworkAdapters | Where-Object Status -eq "Up" | ForEach-Object { $_.Name }) -join ", " -ForegroundColor White
            
                Write-Host ""
                Write-Host "--- Processes ---" -ForegroundColor Yellow
                Write-Host "Running Processes: " -NoNewline -ForegroundColor Yellow
                Write-Host "$($sysInfo.Processes.Count) processes" -ForegroundColor White
            
                # Show top 10 by memory
                $topProcs = $sysInfo.Processes | Sort-Object WS -Descending | Select-Object -First 10
                Write-Host ""
                Write-Host "Top 10 by Memory:" -ForegroundColor DarkYellow
                foreach ($proc in $topProcs) {
                    Write-Host "  $($proc.ProcessName)".PadRight(25) -NoNewline -ForegroundColor DarkGray
                    Write-Host "PID: $($proc.Id)".PadRight(15) -NoNewline -ForegroundColor DarkGray
                    Write-Host "$([math]::Round($proc.WS/1MB, 2)) MB" -ForegroundColor DarkGray
                }
            
                Write-Host ""
                Write-Host "--- Security ---" -ForegroundColor Yellow
                if ($sysInfo.DefenderStatus) {
                    Write-Host "Windows Defender : " -NoNewline -ForegroundColor Yellow
                    Write-Host "Enabled: $($sysInfo.DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor White
                }
                if ($sysInfo.AntiVirus) {
                    foreach ($av in $sysInfo.AntiVirus) {
                        Write-Host "AntiVirus        : " -NoNewline -ForegroundColor Yellow
                        Write-Host $av.displayName -ForegroundColor White
                    }
                }
            
                if ($sysInfo.PSHistory -and $sysInfo.PSHistory.Count -gt 0) {
                    Write-Host ""
                    Write-Host "--- Recent PowerShell History (Last 10) ---" -ForegroundColor Yellow
                    $sysInfo.PSHistory | Select-Object -Last 10 | ForEach-Object {
                        Write-Host "  $_" -ForegroundColor DarkGray
                    }
                }
            
                if ($sysInfo.DNSCache -and $sysInfo.DNSCache.Count -gt 0) {
                    Write-Host ""
                    Write-Host "--- DNS Cache (Sample) ---" -ForegroundColor Yellow
                    $sysInfo.DNSCache | Select-Object -First 10 | ForEach-Object {
                        Write-Host "  $($_.Name)".PadRight(50) -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($_.Type)".PadRight(10) -NoNewline -ForegroundColor DarkGray
                        Write-Host $_.Data -ForegroundColor DarkGray
                    }
                }
            }
            else {
                # Export to CSV for forensic dump
                if ($OutputDir) {
                    # Export each category to separate CSV
                    if ($sysInfo.Processes) {
                        $sysInfo.Processes | Export-Csv -Path (Join-Path $OutputDir "SystemInfo_Processes.csv") -NoTypeInformation
                    }
                    if ($sysInfo.NetworkConnections) {
                        $sysInfo.NetworkConnections | Export-Csv -Path (Join-Path $OutputDir "SystemInfo_NetworkConnections.csv") -NoTypeInformation
                    }
                    if ($sysInfo.LocalUsers) {
                        $sysInfo.LocalUsers | Export-Csv -Path (Join-Path $OutputDir "SystemInfo_LocalUsers.csv") -NoTypeInformation
                    }
                    if ($sysInfo.DNSCache) {
                        $sysInfo.DNSCache | Export-Csv -Path (Join-Path $OutputDir "SystemInfo_DNSCache.csv") -NoTypeInformation
                    }
                
                    # Export summary info
                    $summary = [PSCustomObject]@{
                        Hostname       = $env:COMPUTERNAME
                        Domain         = $sysInfo.Domain
                        IsDomainJoined = $sysInfo.IsDomainJoined
                        OS             = "$($sysInfo.OSInfo.Caption) $($sysInfo.OSInfo.Version)"
                        Architecture   = $sysInfo.OSInfo.OSArchitecture
                        BootTime       = $sysInfo.BootTime
                        CollectionTime = Get-Date
                        TimeZone       = $sysInfo.TimeZone.DisplayName
                    }
                    $summary | Export-Csv -Path (Join-Path $OutputDir "SystemInfo_Summary.csv") -NoTypeInformation
                }
            }
        }
        catch {
            Write-Warning "System information collection error: $($_.Exception.Message)"
        }
    
        return $sysInfo
    }

    # Helper function: Perform IOC Search
    function Invoke-IOCSearch {
        param(
            [hashtable]$SearchParams,
            $StartDate,
            $EndDate,
            [string]$Mode
        )
    
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "      IOC SEARCH INITIATED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Cyan
    
        # Browser search
        if ($SearchParams.ContainsKey('browser') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching browser history..." -ForegroundColor Yellow
        
            $browserParams = @{}
            if ($Mode -eq "Aggressive") { $browserParams['Aggressive'] = $true }
            else { $browserParams['Auto'] = $true }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('browser')) { $searchTerms += $SearchParams['browser'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $browserParams['Search'] = $searchTerms
            }
        
            Hunt-Browser @browserParams
        }
    
        # File search
        if ($SearchParams.ContainsKey('file') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching file system..." -ForegroundColor Yellow
        
            $fileParams = @{
                StartDate = $StartDate
                EndDate   = $EndDate
            }
        
            if ($Mode -eq "Aggressive") {
                $fileParams['Aggressive'] = $true
                $fileParams['IncludeSystemFolders'] = $true
            }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('file')) { $searchTerms += $SearchParams['file'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $fileParams['Search'] = $searchTerms
            }
        
            Hunt-Files @fileParams
        }
    
        # Log search
        if ($SearchParams.ContainsKey('log') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching event logs..." -ForegroundColor Yellow
        
            $logParams = @{
                StartDate = $StartDate
                EndDate   = $EndDate
            }
        
            if ($Mode -eq "Aggressive") {
                $logParams['Auto'] = 2
            }
            else {
                $logParams['Auto'] = 1
            }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('log')) { $searchTerms += $SearchParams['log'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $logParams['Search'] = $searchTerms
            }
        
            Hunt-Logs @logParams
        }
    
        # Task search
        if ($SearchParams.ContainsKey('task') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching scheduled tasks..." -ForegroundColor Yellow
        
            $taskParams = @{
                IncludeDisabled = $true
            }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('task')) { $searchTerms += $SearchParams['task'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $taskParams['Search'] = $searchTerms -join '*'
            }
        
            Hunt-Tasks @taskParams
        }
    
        # Registry search
        if ($SearchParams.ContainsKey('reg') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching registry..." -ForegroundColor Yellow
        
            $regParams = @{
                Type = 'All'
                Hive = 'All'
            }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('reg')) { $searchTerms += $SearchParams['reg'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $regParams['Search'] = $searchTerms
            }
        
            Hunt-Registry @regParams
        }
    
        # Service search
        if ($SearchParams.ContainsKey('service') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching services..." -ForegroundColor Yellow
        
            $serviceParams = @{}
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('service')) { $searchTerms += $SearchParams['service'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $serviceParams['Search'] = $searchTerms
            }
        
            Hunt-Services @serviceParams
        }
    
        # Persistence search
        if ($SearchParams.ContainsKey('persistence') -or $SearchParams.ContainsKey('all')) {
            Write-Host ""
            Write-Host "[+] Searching persistence mechanisms..." -ForegroundColor Yellow
        
            $persistenceParams = @{}
        
            if ($Mode -eq "Aggressive") {
                $persistenceParams['Aggressive'] = $true
            }
            else {
                $persistenceParams['Auto'] = $true
            }
        
            $searchTerms = @()
            if ($SearchParams.ContainsKey('persistence')) { $searchTerms += $SearchParams['persistence'] }
            if ($SearchParams.ContainsKey('all')) { $searchTerms += $SearchParams['all'] }
        
            if ($searchTerms.Count -gt 0) {
                $persistenceParams['Search'] = $searchTerms
            }
        
            Hunt-Persistence @persistenceParams
        }
    
        Write-Host ""
        Write-Host "[+] IOC search complete" -ForegroundColor Green
    }

    # Helper function: Get Registry Forensics
    function Get-RegistryForensics {
        param(
            [string]$OutputDir,
            [hashtable]$Search,
            [string]$Mode
        )
    
        $regData = @{}
    
        # Define registry paths to enumerate
        $regPaths = @{
            'Run Keys'      = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            'User Activity' = @(
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
                'HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs'
            )
            'Network'       = @(
                'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers',
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
            )
        }
    
        foreach ($category in $regPaths.Keys) {
            Write-Host "  [-] Enumerating $category..." -ForegroundColor DarkGray
        
            $categoryData = @()
            foreach ($path in $regPaths[$category]) {
                try {
                    if (Test-Path $path -ErrorAction SilentlyContinue) {
                        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                        if ($props) {
                            $categoryData += $props
                        }
                    }
                }
                catch {
                    Write-Verbose "Error accessing $path : $($_.Exception.Message)"
                }
            }
        
            $regData[$category] = $categoryData
        
            # Export to CSV
            if ($OutputDir -and $categoryData.Count -gt 0) {
                $csvPath = Join-Path $OutputDir "Registry_$($category -replace ' ', '_').csv"
                $categoryData | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
    
        return $regData
    }

    # Helper function: Generate HTML Report
    function Generate-HTMLReport {
        param(
            [hashtable]$ForensicData,
            [string]$OutputPath,
            [string]$CSVDir,
            $StartDate,
            $EndDate,
            [string]$Mode
        )
    
        $hostname = $env:COMPUTERNAME
        $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
        # Build HTML structure
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - $hostname</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); padding: 30px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .header h1 { color: #ecf0f1; font-size: 2.5em; margin-bottom: 10px; }
        .header .info { color: #bdc3c7; font-size: 0.9em; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .tabs { display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; background: #2c2c2c; padding: 15px; border-radius: 8px; }
        .tab-button { padding: 12px 24px; background: #34495e; color: #ecf0f1; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; transition: all 0.3s; }
        .tab-button:hover { background: #4a6278; transform: translateY(-2px); }
        .tab-button.active { background: #3498db; box-shadow: 0 4px 8px rgba(52, 152, 219, 0.3); }
        .tab-content { display: none; animation: fadeIn 0.3s; }
        .tab-content.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .section { background: #2c2c2c; border-radius: 8px; padding: 25px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
        .section h2 { color: #3498db; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #34495e; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background: #34495e; color: #ecf0f1; padding: 12px; text-align: left; cursor: pointer; user-select: none; position: sticky; top: 0; }
        th:hover { background: #4a6278; }
        td { padding: 10px 12px; border-bottom: 1px solid #3a3a3a; }
        tr:hover { background: #333; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%); padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2.5em; color: #3498db; font-weight: bold; }
        .stat-label { color: #bdc3c7; margin-top: 8px; font-size: 0.9em; }
        .filter-box { background: #333; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .filter-box input { width: 100%; padding: 10px; background: #2c2c2c; border: 1px solid #444; color: #e0e0e0; border-radius: 4px; font-size: 14px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; margin: 2px; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .badge-info { background: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Forensic Analysis Report</h1>
        <div class="info">
            <strong>Hostname:</strong> $hostname | 
            <strong>Report Generated:</strong> $reportDate | 
            <strong>Analysis Period:</strong> $StartDate to $EndDate | 
            <strong>Mode:</strong> $Mode
        </div>
    </div>
    
    <div class="container">
        <div class="tabs">
            <button class="tab-button active" onclick="showTab('system')">System Info</button>
            <button class="tab-button" onclick="showTab('persistence')">Persistence</button>
            <button class="tab-button" onclick="showTab('files')">File System</button>
            <button class="tab-button" onclick="showTab('registry')">Registry</button>
            <button class="tab-button" onclick="showTab('browser')">Browser</button>
            <button class="tab-button" onclick="showTab('logs')">Event Logs</button>
            <button class="tab-button" onclick="showTab('services')">Services</button>
            <button class="tab-button" onclick="showTab('tasks')">Scheduled Tasks</button>
        </div>
"@

        # Add tab content placeholders
        $tabs = @('system', 'persistence', 'files', 'registry', 'browser', 'logs', 'services', 'tasks')
    
        foreach ($tab in $tabs) {
            $activeClass = if ($tab -eq 'system') { ' active' } else { '' }
            $html += @"
        
        <div id="$tab-tab" class="tab-content$activeClass">
            <div class="section">
                <h2>$($tab.Substring(0,1).ToUpper() + $tab.Substring(1)) Data</h2>
                <p>Loading data from CSV files...</p>
                <div id="$tab-data"></div>
            </div>
        </div>
"@
        }
    
        # Add JavaScript for interactivity
        $html += @"
    
    </div>
    <script>
        // Store CSV data in memory
        const csvData = {};
        
        function showTab(tabName) {
            // Hide all tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Remove active from all buttons
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            // Show selected tab
            const selectedTab = document.getElementById(tabName + '-tab');
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Set button active
            event.target.classList.add('active');
            
            // Load data if not already loaded
            if (!csvData[tabName]) {
                loadTabData(tabName);
            }
        }
        
        function loadTabData(tabName) {
            const dataDiv = document.getElementById(tabName + '-data');
            if (!dataDiv) return;
            
            // CSV file mapping
            const csvFiles = {
                'system': ['SystemInfo_Summary.csv', 'SystemInfo_Processes.csv', 'SystemInfo_NetworkConnections.csv'],
                'persistence': ['Persistence.csv'],
                'files': ['Files_All.csv', 'Files_Recycled.csv', 'Files_ADS.csv'],
                'registry': ['Registry_Run_Keys.csv'],
                'browser': ['Browser.csv'],
                'logs': ['EventLogs.csv'],
                'services': ['Services.csv'],
                'tasks': ['ScheduledTasks.csv']
            };
            
            const files = csvFiles[tabName] || [];
            if (files.length === 0) {
                dataDiv.innerHTML = '<p>No data files configured for this tab.</p>';
                return;
            }
            
            dataDiv.innerHTML = '<p>Loading ' + files.length + ' data file(s)...</p>';
            
            // Since we can't load external files in a standalone HTML,
            // we'll embed instructions for users
            dataDiv.innerHTML = `
                <div style="padding: 20px; background: #2c3e50; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #3498db;">Data Files for ${tabName}</h3>
                    <p style="color: #ecf0f1;">The following CSV files contain the forensic data:</p>
                    <ul style="color: #bdc3c7;">
                        ${files.map(f => '<li>' + f + ' (located in CSV_Data folder)</li>').join('')}
                    </ul>
                    <p style="color: #e74c3c; margin-top: 15px;">
                        <strong>Note:</strong> Due to browser security restrictions, CSV files cannot be automatically loaded.
                        Please open the CSV files directly using Excel, PowerShell, or a text editor.
                    </p>
                    <p style="color: #95a5a6; font-size: 0.9em;">
                        Tip: You can use PowerShell to view data:<br>
                        <code style="background: #1a1a1a; padding: 5px; display: block; margin-top: 5px;">
                            Import-Csv "CSV_Data\\${files[0]}" | Out-GridView
                        </code>
                    </p>
                </div>
            `;
            
            csvData[tabName] = true;
        }
        
        // Load first tab on page load
        window.addEventListener('DOMContentLoaded', function() {
            loadTabData('system');
        });
        
        function sortTable(table, column) {
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort((a, b) => {
                const aVal = a.children[column].textContent;
                const bVal = b.children[column].textContent;
                return aVal.localeCompare(bVal, undefined, {numeric: true});
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"@
    
        # Write HTML to file
        try {
            $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
            Write-Host "  [+] HTML report structure created" -ForegroundColor Green
        }
        catch {
            throw "Failed to generate HTML report: $($_.Exception.Message)"
        }
    }	
	
    
    # Initialize timing
    $script:StartTime = Get-Date
    
    # Validate parameters
    if ($Auto -and $Aggressive) {
        Write-Error "Cannot use both -Auto and -Aggressive modes simultaneously"
        return
    }

    # Set default StartDate if not specified (10 days ago)
    if (-not $PSBoundParameters.ContainsKey('StartDate') -and -not $Auto) {
        $StartDate = (Get-Date).AddDays(-10)
        Write-Verbose "No StartDate specified, defaulting to 10 days ago: $StartDate"
    }
    
    # Set default mode if none specified
    if (-not $Auto -and -not $Aggressive) {
        $Auto = $true
    }
    
    # Check for at least one action
    if (-not $ForensicDump -and -not $SystemInfo -and $Search.Count -eq 0 -and -not $ExportLogs) {
        Write-Error "No action specified. Use -ForensicDump, -SystemInfo, -Search, or -ExportLogs"
        return
    }
    
    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "Not running as Administrator. Some data collection will be limited."
    }
    
    # Setup output directory for ForensicDump
    if ($ForensicDump -or $ExportLogs) {
        if ([string]::IsNullOrWhiteSpace($OutputDir)) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputDir = "C:\ForensicDump_$($env:COMPUTERNAME)_$timestamp"
        }
        
        try {
            if (-not (Test-Path $OutputDir)) {
                New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
                Write-Host "[+] Created output directory: $OutputDir" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to create output directory: $($_.Exception.Message)"
            return
        }
    }
    
    # Handle ExportLogs independently
    if ($ExportLogs) {
        Write-Progress -Activity "Hunt-All" -Status "Exporting EVTX logs..." -PercentComplete 5
        Write-Host "[+] Exporting all EVTX logs..." -ForegroundColor Yellow
        
        try {
            $logsDir = Join-Path $OutputDir "EVTX_Export"
            New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
            
            # Use Hunt-Logs export functionality
            Hunt-Logs -Export $logsDir -Quiet
            
            Write-Host "[+] EVTX logs exported to: $logsDir" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to export EVTX logs: $($_.Exception.Message)"
        }
    }
    
    # Handle SystemInfo action
    if ($SystemInfo) {
        Write-Progress -Activity "Hunt-All" -Status "Gathering system information..." -PercentComplete 10
        Get-SystemInformation -OutputDir $OutputDir -ForensicDump:$ForensicDump
    }
    
    # Handle Search action without ForensicDump
    if ($Search.Count -gt 0 -and -not $ForensicDump) {
        Write-Progress -Activity "Hunt-All" -Status "Performing IOC searches..." -PercentComplete 20
        Invoke-IOCSearch -SearchParams $Search -StartDate $StartDate -EndDate $EndDate -Mode $(if ($Aggressive) { "Aggressive" } else { "Auto" })
    }
    
    # Handle ForensicDump
    if ($ForensicDump) {
        # Validate date parameters for ForensicDump
        if (-not $StartDate) {
            Write-Error "StartDate is required for ForensicDump mode"
            return
        }
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "    FORENSIC DUMP INITIATED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "[+] Output Directory: $OutputDir" -ForegroundColor Green
        Write-Host "[+] Mode: $(if ($Aggressive) { 'Aggressive' } else { 'Auto' })" -ForegroundColor Green
        Write-Host "[+] Date Range: $StartDate to $EndDate" -ForegroundColor Green
        if ($Search.Count -gt 0) {
            Write-Host "[+] IOC Search Terms: $($Search.Count) categories" -ForegroundColor Green
        }
        Write-Host ""
        
        # Create subdirectories
        $csvDir = Join-Path $OutputDir "CSV_Data"
        New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
        
        # Initialize data collection results
        $forensicData = @{
            SystemInfo  = $null
            Persistence = $null
            Files       = $null
            Registry    = $null
            Browser     = $null
            Logs        = $null
            Services    = $null
            Tasks       = $null
        }
        
        # Collect System Information
        Write-Progress -Activity "Forensic Dump" -Status "Collecting system information..." -PercentComplete 5
        Write-Host "[+] Collecting system information..." -ForegroundColor Yellow
        $forensicData.SystemInfo = Get-SystemInformation -OutputDir $csvDir -ForensicDump:$true
        
        # Collect Persistence Data
        Write-Progress -Activity "Forensic Dump" -Status "Analyzing persistence mechanisms..." -PercentComplete 15
        Write-Host "[+] Analyzing persistence mechanisms..." -ForegroundColor Yellow
        try {
            $persistenceParams = @{
                All       = $true
                PassThru  = $true
                Quiet     = $true
                OutputCSV = Join-Path $csvDir "Persistence.csv"
            }
            
            # Add search terms if provided
            if ($expandedSearch.ContainsKey('persistence') -or $expandedSearch.ContainsKey('all')) {
                $searchTerms = @()
                if ($expandedSearch.ContainsKey('persistence')) { $searchTerms += $Search['persistence'] }
                if ($expandedSearch.ContainsKey('all')) { $searchTerms += $Search['all'] }
                $persistenceParams['Search'] = $searchTerms
            }
            
            $forensicData.Persistence = Hunt-Persistence @persistenceParams -PassThru -Quiet
        }
        catch {
            Write-Warning "Persistence collection failed: $($_.Exception.Message)"
        }
        
        # Collect File System Data
        Write-Progress -Activity "Forensic Dump" -Status "Scanning file system..." -PercentComplete 25
        Write-Host "[+] Scanning file system..." -ForegroundColor Yellow
        try {
            $fileParams = @{
                StartDate = $StartDate
                EndDate   = $EndDate
                PassThru  = $true
                Quiet     = $true
                OutputCSV = Join-Path $csvDir "Files_All.csv"
                Path      = "C:\"  # Only scan C:\ drive
            }
    
            if ($Aggressive) {
                $fileParams['IncludeSystemFolders'] = $true
            }
    
            # Add file search terms using expanded search
            if ($expandedSearch.ContainsKey('file')) {
                $fileParams['Search'] = $expandedSearch['file']
            }
            
            # Cache the main file scan results
            Write-Host "[+] Performing main file system scan..." -ForegroundColor Yellow
            $allFiles = Hunt-Files @fileParams
    
            # Reuse cached results for recycled and ADS scans instead of re-scanning
            Write-Host "[+] Filtering recycled files from cache..." -ForegroundColor Yellow
            $recycledFiles = $allFiles | Where-Object { $_.IsRecycleBin -eq $true }
    
            Write-Host "[+] Filtering files with alternate data streams from cache..." -ForegroundColor Yellow
            $adsFiles = $allFiles | Where-Object { $_.AlternateStreamCount -gt 0 }
    
            # Export recycled and ADS to separate CSVs
            if ($recycledFiles) {
                $recycledFiles | Export-Csv -Path (Join-Path $csvDir "Files_Recycled.csv") -NoTypeInformation
            }
            if ($adsFiles) {
                $adsFiles | Export-Csv -Path (Join-Path $csvDir "Files_ADS.csv") -NoTypeInformation
            }
    
            $forensicData.Files = @{
                All      = $allFiles
                Recycled = $recycledFiles
                ADS      = $adsFiles
            }
        }
        catch {
            Write-Warning "File system scan failed: $($_.Exception.Message)"
        }        
        # Collect Registry Data
        Write-Progress -Activity "Forensic Dump" -Status "Analyzing registry..." -PercentComplete 35
        Write-Host "[+] Analyzing registry..." -ForegroundColor Yellow
        try {
            $forensicData.Registry = Get-RegistryForensics -OutputDir $csvDir -Search $Search -Mode $(if ($Aggressive) { "Aggressive" } else { "Auto" })
        }
        catch {
            Write-Warning "Registry analysis failed: $($_.Exception.Message)"
        }
        
        # Collect Browser Data
        Write-Progress -Activity "Forensic Dump" -Status "Extracting browser history..." -PercentComplete 45
        Write-Host "[+] Extracting browser history..." -ForegroundColor Yellow
        try {
            $browserParams = @{
                PassThru  = $true
                Quiet     = $true
                OutputCSV = Join-Path $csvDir "Browser.csv"
            }
            
            if ($Aggressive) {
                $browserParams['All'] = $true
            }
            else {
                $browserParams['Auto'] = $true
            }
            
            # Add browser search terms
            if ($expandedSearch.ContainsKey('browser') -or $expandedSearch.ContainsKey('all')) {
                $searchTerms = @()
                if ($expandedSearch.ContainsKey('browser')) { $searchTerms += $Search['browser'] }
                if ($expandedSearch.ContainsKey('all')) { $searchTerms += $Search['all'] }
                $browserParams['Search'] = $searchTerms
            }
            
            $forensicData.Browser = Hunt-Browser @browserParams
        }
        catch {
            Write-Warning "Browser history extraction failed: $($_.Exception.Message)"
        }
        
        # Collect Event Logs
        Write-Progress -Activity "Forensic Dump" -Status "Analyzing event logs..." -PercentComplete 55
        Write-Host "[+] Analyzing event logs..." -ForegroundColor Yellow
        try {
            # Convert dates before passing to Hunt-Logs
            $logParams = @{
                StartDate = $parsedStartDate.ToString("yyyy-MM-dd HH:mm:ss")
                EndDate   = $parsedEndDate.ToString("yyyy-MM-dd HH:mm:ss")
                PassThru  = $true
                Quiet     = $true
                OutputCSV = Join-Path $csvDir "EventLogs.csv"
            }
            
            if ($Aggressive) {
                $logParams['Auto'] = 2
            }
            else {
                $logParams['Auto'] = 1
            }
            
            # Add log search terms
            if ($expandedSearch.ContainsKey('log') -or $expandedSearch.ContainsKey('all')) {
                $searchTerms = @()
                if ($expandedSearch.ContainsKey('log')) { $searchTerms += $Search['log'] }
                if ($expandedSearch.ContainsKey('all')) { $searchTerms += $Search['all'] }
                $logParams['Search'] = $searchTerms
            }
            
            $forensicData.Logs = Hunt-Logs @logParams
        }
        catch {
            Write-Warning "Event log analysis failed: $($_.Exception.Message)"
        }
        
        # Collect Services
        Write-Progress -Activity "Forensic Dump" -Status "Enumerating services..." -PercentComplete 70
        Write-Host "[+] Enumerating services..." -ForegroundColor Yellow
        try {
            $serviceParams = @{
                PassThru  = $true
                Quiet     = $true
                OutputCSV = Join-Path $csvDir "Services.csv"
            }
            
            # Add service search terms
            if ($expandedSearch.ContainsKey('service') -or $expandedSearch.ContainsKey('all')) {
                $searchTerms = @()
                if ($expandedSearch.ContainsKey('service')) { $searchTerms += $Search['service'] }
                if ($expandedSearch.ContainsKey('all')) { $searchTerms += $Search['all'] }
                $serviceParams['Search'] = $searchTerms
            }
            
            $forensicData.Services = Hunt-Services @serviceParams
        }
        catch {
            Write-Warning "Service enumeration failed: $($_.Exception.Message)"
        }
        
        # Collect Scheduled Tasks
        Write-Progress -Activity "Forensic Dump" -Status "Analyzing scheduled tasks..." -PercentComplete 80
        Write-Host "[+] Analyzing scheduled tasks..." -ForegroundColor Yellow
        try {
            $taskParams = @{
                PassThru        = $true
                Quiet           = $true
                OutputCSV       = Join-Path $csvDir "ScheduledTasks.csv"
                IncludeDisabled = $true
            }
            
            # Add task search terms
            if ($expandedSearch.ContainsKey('task') -or $expandedSearch.ContainsKey('all')) {
                $searchTerms = @()
                if ($expandedSearch.ContainsKey('task')) { $searchTerms += $Search['task'] }
                if ($expandedSearch.ContainsKey('all')) { $searchTerms += $Search['all'] }
                $taskParams['Search'] = $searchTerms -join '*'
            }
            
            $forensicData.Tasks = Hunt-Tasks @taskParams
        }
        catch {
            Write-Warning "Scheduled task analysis failed: $($_.Exception.Message)"
        }
        
        # Generate HTML Report
        Write-Progress -Activity "Forensic Dump" -Status "Generating HTML report..." -PercentComplete 90
        Write-Host "[+] Generating interactive HTML report..." -ForegroundColor Yellow
        
        try {
            $htmlPath = Join-Path $OutputDir "ForensicReport.html"
            Generate-HTMLReport -ForensicData $forensicData -OutputPath $htmlPath -CSVDir $csvDir -StartDate $StartDate -EndDate $EndDate -Mode $(if ($Aggressive) { "Aggressive" } else { "Auto" })
            
            Write-Host "[+] HTML report generated: $htmlPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "HTML report generation failed: $($_.Exception.Message)"
        }
        
        Write-Progress -Activity "Forensic Dump" -Completed
    }
    
    # Display completion summary
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    HUNT-ALL COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[+] Total Runtime: $($duration.Hours)h $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor Yellow
    
    if ($ForensicDump -or $ExportLogs) {
        Write-Host "[+] Output Directory: $OutputDir" -ForegroundColor Green
        
        if ($ForensicDump) {
            Write-Host "[+] Forensic Report: $(Join-Path $OutputDir 'ForensicReport.html')" -ForegroundColor Green
            Write-Host "[+] CSV Data: $(Join-Path $OutputDir 'CSV_Data')" -ForegroundColor Green
        }
        
        if ($ExportLogs) {
            Write-Host "[+] EVTX Export: $(Join-Path $OutputDir 'EVTX_Export')" -ForegroundColor Green
        }
    }
    
    Write-Host ""
}



Function Hunt-Persistence {
    <#
.SYNOPSIS
Hunts for Windows persistence mechanisms across registry, services, tasks, and file system locations.

.DESCRIPTION
Hunt-Persistence performs comprehensive detection of Windows persistence techniques including registry run keys, 
scheduled tasks, services, WMI subscriptions, and dozens of other persistence vectors. Supports multiple 
detection modes from high-fidelity auto mode to comprehensive aggressive scanning.

.PARAMETER Technique
Specifies which persistence techniques to search. Default is 'All' to check all techniques.
Valid values include specific techniques like 'RegistryRunKeys', 'ScheduledTasks', 'Services', etc.

.PARAMETER Search
Array of custom strings to add to suspicious indicator checks.

.PARAMETER Exclude
Hashtable for excluding results. Key=string to match, Value=field name to match against.

.PARAMETER OutputCSV
Path for CSV export. Can be file path or directory (auto-generates filename with timestamp).

.PARAMETER Auto
High-fidelity mode focusing on clearly suspicious items (default behavior).

.PARAMETER Aggressive
Broader detection including unsigned binaries and non-standard configurations.

.PARAMETER Insane
Most comprehensive detection when used with -Aggressive. Includes user directory executables.

.PARAMETER All
Returns all discovered persistence mechanisms regardless of suspicion level.

.PARAMETER Quiet
Suppresses console output. Must be used with -OutputCSV or -PassThru.

.PARAMETER More
Displays additional technical details in console output.

.PARAMETER LoadHives
Attempts to mount unloaded user registry hives (requires Administrator).

.PARAMETER PassThru
Returns PowerShell objects for programmatic use.

.EXAMPLE
Hunt-Persistence
Basic scan using auto mode with console output.

.EXAMPLE
Hunt-Persistence -Aggressive -OutputCSV "C:\Reports\persistence.csv" -Quiet
Aggressive scan with CSV export and no console output.

.EXAMPLE
$results = Hunt-Persistence -Auto -PassThru -Quiet
Capture results as PowerShell objects for further analysis.

.EXAMPLE
Hunt-Persistence -Search "ScheduledTasks" -More
Focus only on scheduled tasks with detailed output.

.EXAMPLE
Hunt-Persistence -All -LoadHives -Search @("badware.exe", "malicious.dll")
Comprehensive scan including unloaded user hives and custom indicators.

.NOTES
Requires PowerShell 5.0 or higher. Some techniques require Administrator privileges for full detection.
Use -Aggressive carefully in production as it may generate false positives.

.LINK
https://attack.mitre.org/tactics/TA0003/
#>
    Param(
        [ValidateSet(
            'All', 'RegistryRunKeys', 'ImageFileExecutionOptions', 'NLDPDllOverridePath', 'AeDebug',
            'WerFaultHangs', 'CmdAutoRun', 'ExplorerLoad', 'WinlogonUserinit', 'WinlogonShell',
            'TerminalProfileStartOnUserLogin', 'AppCertDlls', 'ServiceDlls', 'GPExtensionDlls',
            'WinlogonMPNotify', 'CHMHelperDll', 'HHCtrlHijacking', 'StartupPrograms', 'UserInitMprScript',
            'AutodialDLL', 'LsaExtensions', 'ServerLevelPluginDll', 'LsaPasswordFilter',
            'LsaAuthenticationPackages', 'LsaSecurityPackages', 'WinlogonNotificationPackages',
            'ExplorerTools', 'DotNetDebugger', 'ErrorHandlerCmd', 'WMIEventsSubscrition',
            'AppPaths', 'TerminalServicesInitialProgram', 'AccessibilityTools',
            'AMSIProviders', 'PowershellProfiles', 'SilentExitMonitor', 'TelemetryController',
            'RDPWDSStartupPrograms', 'ScheduledTasks', 'BitsJobsNotify', 'Screensaver',
            'PowerAutomate', 'OfficeAddinsAndTemplates', 'Services', 'ExplorerContextMenu',
            'ServiceControlManagerSD', 'OfficeAiHijacking', 'DotNetStartupHooks',
            'SubornerAttack', 'DSRMBackdoor', 'BootVerificationProgram', 'AppInitDLLs', 'BootExecute',
            'NetshHelperDLL', 'SetupExecute', 'PlatformExecute'
        )]
        $Technique = 'All',
    
        [String[]]
        $Search = @(),

        [Hashtable]
        $Exclude = @{},
    
        [String]
        $OutputCSV = $null,

        [Switch]
        $Auto,

        [Switch] 
        $Aggressive,

        [Switch] 
        $Insane,

        [Switch]
        $All,

        [Switch]
        $Quiet,

        [Switch]
        $More,

        [Switch]
        $LoadHives,
    
        [Switch]
        $PassThru
    )

    # Add parameter validation and mode setting
    $modeCount = @($Auto, $Aggressive, $All, $Insane).Where({ $_ }).Count
    if ($modeCount -gt 1) {
        Write-Error "Cannot specify multiple modes. Choose only one: -Auto, -Aggressive, or -All"
        return
    }
    # Set default mode to Auto if none specified
    $Mode = if ($Aggressive -or $Insane) { 'Aggressive' } 
    elseif ($All) { 'All' }
    else { 'Auto' }

    # Improved parameter validation with correct null comparisons
    if ($Quiet -and ([string]::IsNullOrEmpty($OutputCSV)) -and -not $PassThru) {
        Write-Error "The -Quiet parameter can only be used when -OutputCSV or -PassThru is also specified."
        if ($PassThru) { return @() }
        return
    }
    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-not $isAdmin) {
        Write-Warning "Not running as Administrator, insufficient privileges may cause detection issues..."
    }
    else {
        Write-Verbose "Running as Administrator..."
    }

    # OutputCSV parameter validation and path processing
    if ($OutputCSV) {
        try {
            # If it's a directory, create filename
            if (Test-Path $OutputCSV -PathType Container -ErrorAction SilentlyContinue) {
                $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $OutputCSV = Join-Path $OutputCSV "Persistence-Report_$timestamp.csv"
            }
            elseif ([System.IO.Path]::GetExtension($OutputCSV) -eq '') {
                # If no extension provided, add .csv
                $OutputCSV = $OutputCSV + '.csv'
            }
        
            # Ensure directory exists
            $outputDir = Split-Path $OutputCSV -Parent
            if ($outputDir -and -not (Test-Path $outputDir -ErrorAction SilentlyContinue)) {
                New-Item -Path $outputDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        
            # Test write permissions
            $testFile = $OutputCSV + '.tmp'
            'test' | Out-File -FilePath $testFile -ErrorAction Stop
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error "Invalid OutputCSV path or insufficient permissions: $OutputCSV"
            if ($PassThru) { return @() }
            return
        }
    }

    # Process Search parameter - add custom strings to suspicious IOCs
    if ($Search -and $Search.Count -gt 0) {
        Write-Verbose "Adding $($Search.Count) custom strings to suspicious IOCs list..."
        foreach ($customIOC in $Search) {
            if (![string]::IsNullOrWhiteSpace($customIOC)) {
                $script:SuspiciousStringIOCs += $customIOC.Trim()
            }
        }
        Write-Verbose "Total suspicious IOCs after custom additions: $($script:SuspiciousStringIOCs.Count)"
    }

    # Initialize variables
    $script:globalPersistenceObjectArray = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ErrorActionPreference = 'SilentlyContinue'
    $hostname = ([Net.Dns]::GetHostByName($env:computerName)).HostName
    $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
    $systemAndUsersHives = [Collections.ArrayList]::new()

    function New-PersistenceObject {
        param(
            [String]$Hostname = $null,
            [String]$Technique = $null, 
            [String]$Classification = $null, 
            [String]$Path = $null, 
            [String]$ExecutePath = $null, 
            [String]$Value = $null, 
            [String]$SHA256 = $null, 
            [String]$AccessGained = $null,
            [String]$Note = $null,
            [String]$Reference = $null,
            [String]$Status = $null  
        )

        # Get executable path for additional analysis
        $trueFilePath = Get-FileFromCommandLine $Value

        # Initialize LNK-specific properties
        $lnkTargetPath = $null
        $lnkTargetHash = $null

        # Check if this is an LNK file and resolve target information
        if ($trueFilePath -and [System.IO.Path]::GetExtension($trueFilePath) -eq '.lnk') {
            $lnkTargetPath = Get-LnkTarget $trueFilePath
            if ($lnkTargetPath) {
                $lnkTargetHash = Get-FileHashSafe $lnkTargetPath
            }
        }

        # Create base persistence object
        $PersistenceObject = [PSCustomObject]@{
            'Hostname'        = $Hostname
            'Technique'       = $Technique
            'Classification'  = $Classification
            'Path'            = $Path
            'Execute Path'    = $trueFilePath
            'Value'           = $Value
            'SHA256'          = if ($SHA256) { $SHA256 } else { Get-FileHashSafe $trueFilePath }
            'Rights'          = $AccessGained
            'Note'            = $Note
            'Reference'       = $Reference
            'Signature'       = if ($lnkTargetPath) { Get-CombinedSignatureInfo $lnkTargetPath } else { Get-CombinedSignatureInfo $trueFilePath }
            'IsBuiltinBinary' = Get-IfBuiltinBinary $trueFilePath
            'IsLolbin'        = Get-IfLolBin $trueFilePath
            'Flag'            = ""
            'Status'          = $Status
        }

        # Add LNK-specific properties if this is an LNK file
        if ($lnkTargetPath -or $lnkTargetHash) {
            $PersistenceObject | Add-Member -NotePropertyName 'LnkTargetPath' -NotePropertyValue $lnkTargetPath
            $PersistenceObject | Add-Member -NotePropertyName 'LnkTargetHash' -NotePropertyValue $lnkTargetHash
        }
        return $PersistenceObject
    }

    function Find-ExecutableInSystemPaths {
        param([string]$FileName)
        
        if ([string]::IsNullOrWhiteSpace($FileName)) { 
            return $FileName 
        }
        
        # Define search paths in order of priority
        $searchPaths = @(
            "C:\Windows\System32",
            "C:\Windows\SysWOW64", 
            "C:\Windows",
            "C:\Program Files\Windows NT\Accessories",
            "C:\Program Files\Common Files\Microsoft Shared",
            "C:\Windows\System32\WindowsPowerShell\v1.0\",
            "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\",
            "C:\Users\<YourUsername>\AppData\Local\Microsoft\PowerShell\7\",
            "C:\Program Files\PowerShell\7\"
        )
        
        foreach ($searchPath in $searchPaths) {
            $fullPath = Join-Path $searchPath $FileName
            if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                return $fullPath
            }
        }
        
        # If not found, return the original filename
        return $FileName
    }

    function Get-FileFromCommandLine {
        param([String]$CommandLine)

        if ([string]::IsNullOrWhiteSpace($CommandLine)) {
            return $null
        }

        try {
            # Expand environment variables
            $expanded = [System.Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
        
            # 1. COMPATTELRUNNER.EXE with -m: parameter - extract the executable, not the DLL
            if ($expanded -match '(.*compattelrunner\.exe)\s+-m:') {
                return $matches[1]
            }
        
            # 2. CMD.EXE executing files - extract the target file
            if ($expanded -match 'cmd\.exe.*?/[dc]\s+([A-Za-z]:\\[^"\s]+\.(cmd|bat|ps1|vbs|js))') {
                return $matches[1]
            }
            if ($expanded -match 'cmd\.exe.*?/[dc]\s+"([^"]+\.(cmd|bat|ps1|vbs|js))"') {
                return $matches[1]
            }
            if ($expanded -match 'cmd\.exe.*?/[dc]\s+([^"\s]+\.(cmd|bat|ps1|vbs|js))') {
                return $matches[1]
            }
        
            # 3. POWERSHELL.EXE executing files - extract script files or executables
            if ($expanded -match 'powershell\.exe.*?-[Ff]ile\s+"?([^"\s]+\.(ps1|bat|cmd|exe|vbs|js))"?') {
                return $matches[1]
            }
            if ($expanded -match 'powershell\.exe.*?"[^"]*([A-Za-z]:\\[^"]*\.(ps1|bat|cmd|exe|vbs|js|dll))[^"]*"') {
                return $matches[1]
            }
            if ($expanded -match 'powershell\.exe.*?&\s+([A-Za-z]:\\[^"\s]+\.(ps1|bat|cmd|exe|vbs|js))') {
                return $matches[1]
            }
            if ($expanded -match 'powershell\.exe.*?\.\s+([A-Za-z]:\\[^"\s]+\.(ps1|bat|cmd|exe|vbs|js))') {
                return $matches[1]
            }
        
            # 4. NODE.EXE executing JavaScript files
            if ($expanded -match 'node\.exe\s+"?([^"\s]+\.js)"?') {
                return $matches[1]
            }
        
            # 5. PYTHON.EXE executing Python files
            if ($expanded -match 'python\.exe\s+"?([^"\s]+\.py)"?') {
                return $matches[1]
            }
        
            # 6. WSCRIPT.EXE / CSCRIPT.EXE executing scripts
            if ($expanded -match '(?:wscript|cscript)\.exe\s+"?([^"\s]+\.(vbs|js|wsf))"?') {
                return $matches[1]
            }
        
            # 7. MSHTA.EXE executing HTA files
            if ($expanded -match 'mshta\.exe\s+"?([^"\s]+\.hta)"?') {
                return $matches[1]
            }
        
            # 8. REGSVR32.EXE registering DLLs
            if ($expanded -match 'regsvr32\.exe.*?\s+"?([^"\s]+\.dll)"?') {
                return $matches[1]
            }
        
            # 9. RUNDLL32.EXE calling DLL functions - extract the DLL
            if ($expanded -match 'rundll32\.exe\s+([A-Za-z]:\\[^,\s]+\.dll|[^,\s]+\.dll)') {
                $dll = $matches[1]
                # If relative path, try to resolve it
                if ($dll -notmatch '^[A-Za-z]:') {
                    return Find-ExecutableInSystemPaths $dll
                }
                return $dll
            }
        
            # 10. MSIEXEC.EXE installing MSI files
            if ($expanded -match 'msiexec\.exe.*?[/\-]i\s+"?([^"\s]+\.msi)"?') {
                return $matches[1]
            }
        
            # 11. SCHTASKS.EXE with /RU (run as) pointing to executables
            if ($expanded -match 'schtasks\.exe.*?/TR\s+"?([^"\s]+\.(exe|bat|cmd|ps1))"?') {
                return $matches[1]
            }
        
            # 12. NET.EXE or SC.EXE starting services - return the full path
            if ($expanded -match '^(net\.exe|sc\.exe)\s+(?:start|stop|config)') {
                $utilityName = $matches[1]
                return Find-ExecutableInSystemPaths $utilityName
            }
        
            # 13. Quoted paths - but exclude PowerShell script content
            if ($expanded -match '"([^"]+)"' -and $matches[1] -notlike "& *" -and $matches[1] -notlike ".*-.*") {
                $path = $matches[1].Trim()
                # Clean trailing punctuation
                $path = $path -replace '[,;]+$', ''
                # Only return if it's a file path
                if ($path -match '\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf)$') {
                    return $path
                }
            }
        
            # 14. Simple drive paths with any extension
            if ($expanded -match '^([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))(\s|$)') {
                $path = $matches[1].Trim()
                # Clean trailing punctuation
                $path = $path -replace '[,;]+$', ''
                return $path
            }
        
            # 15. Drive paths with arguments - capture until first argument
            if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))\s+(-|/)') {
                return $matches[1].Trim()
            }
        
            # 16. Drive paths with space + word arguments (non-path arguments)
            if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))\s+([a-zA-Z]+)' -and $matches[3] -notmatch '^[A-Za-z]:') {
                return $matches[1].Trim()
            }
        
            # 17. UNC paths
            if ($expanded -match '(\\\\[^\\]+\\[^\s"]+\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))') {
                return $matches[1].Trim()
            }
        
            # 18. Simple executable names with arguments - handle cases like "BthUdTask.exe $(Arg0)"
            if ($expanded -match '^([a-zA-Z][a-zA-Z0-9]*\.(exe|com|scr|dll))(\s|$)') {
                $file = $matches[1]
                return Find-ExecutableInSystemPaths $file
            }
        
            # 19. Look for any executable file in command line arguments
            if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))') {
                return $matches[1] -replace '[,;]+$', ''
            }
        
            # 20. FINAL FALLBACK - if nothing else worked and we have a non-empty string, return it
            if (![string]::IsNullOrWhiteSpace($expanded)) {
                return $expanded.Trim()
            }
        
            return $null
        
        }
        catch {
            Write-Verbose "Error parsing command line '$CommandLine': $($_.Exception.Message)"
            # Even on error, try the fallback
            if (![string]::IsNullOrWhiteSpace($CommandLine)) {
                return $CommandLine.Trim()
            }
            return $null
        }
    }

    function Get-LnkTarget {
        param([String]$LnkPath)
    
        if (-not $LnkPath -or -not (Test-Path $LnkPath -ErrorAction SilentlyContinue)) {
            return $null
        }
    
        if ([System.IO.Path]::GetExtension($LnkPath) -ne '.lnk') {
            return $null
        }
    
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($LnkPath)
            $targetPath = $shortcut.TargetPath
        
            # Clean up COM objects
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shortcut) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
        
            # Expand environment variables in target path
            if (![string]::IsNullOrWhiteSpace($targetPath)) {
                $targetPath = [System.Environment]::ExpandEnvironmentVariables($targetPath)
                # Verify the target exists
                if (Test-Path $targetPath -ErrorAction SilentlyContinue) {
                    return $targetPath
                }
            }
        
            return $null
        
        }
        catch {
            Write-Verbose "Error resolving LNK target for '$LnkPath': $($_.Exception.Message)"
            return $null
        }
    }

    function Get-FileHashSafe {
        param([String]$FilePath)
        if ($null -eq $FilePath -or -not (Test-Path $FilePath -ErrorAction SilentlyContinue)) { 
            return $null 
        }
        try {
            return (Get-FileHash $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch [System.UnauthorizedAccessException] {
            Write-Verbose "Access denied to file: $FilePath"
            return "ERROR - Access Denied"
        }
        catch [System.IO.IOException] {
            Write-Verbose "File in use or IO error: $FilePath"
            return "ERROR - File In Use"
        }
        catch {
            Write-Verbose "Error accessing file $FilePath : $($_.Exception.Message)"
            return "Error: $($_.Exception.Message)"
        }
    }

    function Get-IfBuiltinBinary {
        param([String]$executable)
        if ($null -eq $executable) { 
            return $false 
        }
    
        if (-not (Test-Path $executable -ErrorAction SilentlyContinue)) {
            Write-Verbose "File not found for OS binary check: $executable"
            return $false
        }
    
        try {
            $authenticode = Get-AuthenticodeSignature $executable -ErrorAction Stop
            return $authenticode.IsOsBinary
        }
        catch [System.UnauthorizedAccessException] {
            Write-Verbose "Access denied checking OS binary status: $executable"
            return $false
        }
        catch [System.IO.IOException] {
            Write-Verbose "File in use checking OS binary status: $executable"
            return $false
        }
        catch { 
            return $false
        }
    }
    function Get-CombinedSignatureInfo {
        param([String]$FilePath)

        if (-not $FilePath) { 
            return "[NO_PATH]"
        }

        # Use Get-Item instead of Test-Path for better reliability with system files
        try {
            $fileExists = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        }
        catch [System.UnauthorizedAccessException] {
            return "[ACCESS_DENIED]"
        }
        catch [System.IO.FileNotFoundException], [System.Management.Automation.ItemNotFoundException] {
            return "[FILE_NOT_FOUND]"
        }
        catch {
            return "[FILE_NOT_FOUND]"
        }

        try {
            $authenticode = Get-AuthenticodeSignature $FilePath -ErrorAction Stop
            $status = $authenticode.Status
    
            if ($status -eq "Valid") {
                if ($authenticode.SignerCertificate) {
                    $cert = $authenticode.SignerCertificate
                    $subject = $cert.Subject
                    $issuer = $cert.Issuer
                    $thumbprint = $cert.Thumbprint
                    $notAfter = $cert.NotAfter
            
                    # Extract Common Name from subject
                    $subjectCN = if ($subject -match 'CN=([^,]+)') { $matches[1].Trim('"') } else { "Unknown" }
            
                    # Extract Common Name from issuer  
                    $issuerCN = if ($issuer -match 'CN=([^,]+)') { $matches[1].Trim('"') } else { "Unknown CA" }
            
                    # Check if certificate is expired
                    $currentDate = Get-Date
                    $isExpired = $currentDate -gt $notAfter
            
                    # Check if it's self-signed
                    $isSelfSigned = $subject -eq $issuer
            
                    # Determine the status tag
                    $statusTag = if ($isExpired) { 
                        "[VALID_EXPIRED]" 
                    }
                    elseif ($isSelfSigned) { 
                        "[VALID_SELF_SIGNED]" 
                    }
                    else { 
                        "[VALID]" 
                    }
            
                    # Format the date as MM-DD-YYYY
                    $formattedDate = $notAfter.ToString('MM-dd-yyyy')
            
                    return "$statusTag Subject: $subjectCN, Issuer: $issuerCN, Thumbprint: $thumbprint, Expires: $formattedDate"
                }
                else {
                    return "[VALID] No Certificate Details Available"
                }
            }
            elseif ($status -eq "NotSigned") {
                return "[NOT_SIGNED]"
            }
            elseif ($status -eq "HashMismatch") {
                return "[INVALID] Hash Mismatch - File Modified After Signing"
            }
            elseif ($status -eq "NotTrusted") {
                if ($authenticode.SignerCertificate) {
                    $cert = $authenticode.SignerCertificate
                    $subject = $cert.Subject
                    $thumbprint = $cert.Thumbprint
            
                    # Extract Common Name from subject
                    $subjectCN = if ($subject -match 'CN=([^,]+)') { $matches[1].Trim('"') } else { "Unknown" }
            
                    return "[NOT_TRUSTED] Subject: $subjectCN, Thumbprint: $thumbprint, Reason: Certificate not trusted by system"
                }
                else {
                    return "[NOT_TRUSTED] No Certificate Details Available"
                }
            }
            elseif ($status -eq "UnknownError") {
                return "[UNKNOWN_ERROR] Unable to verify signature"
            }
            else {
                # Handle any other statuses
                return "[$($status.ToString().ToUpper())] Signature verification failed"
            }
        }
        catch [System.UnauthorizedAccessException] {
            return "[ACCESS_DENIED]"
        }
        catch [System.IO.IOException] {
            return "[FILE_IN_USE]"
        }
        catch {
            return "[ERROR] Exception: $($_.Exception.Message)"
        }
    }
    function Get-IfLolBin {
        param([String]$executable)
        if (-not $executable) { return $false }
    
        [String[]]$lolbins = @(
            "APPINSTALLER.EXE", "ASPNET_COMPILER.EXE", "AT.EXE", "ATBROKER.EXE", "BASH.EXE", 
            "BITSADMIN.EXE", "CERTOC.EXE", "CERTREQ.EXE", "CERTUTIL.EXE", "CMD.EXE", "CMDKEY.EXE", 
            "CMDL32.EXE", "CMSTP.EXE", "CONFIGSECURITYPOLICY.EXE", "CONHOST.EXE", "CONTROL.EXE", 
            "CSC.EXE", "CSCRIPT.EXE", "DATASVCUTIL.EXE", "DESKTOPIMGDOWNLDR.EXE", "DFSVC.EXE", 
            "DIANTZ.EXE", "DISKSHADOW.EXE", "DNSCMD.EXE", "ESENTUTL.EXE", "EVENTVWR.EXE", 
            "EXPAND.EXE", "EXPLORER.EXE", "EXTEXPORT.EXE", "EXTRAC32.EXE", "FINDSTR.EXE", 
            "FINGER.EXE", "FLTMC.EXE", "FORFILES.EXE", "FTP.EXE", "GFXDOWNLOADWRAPPER.EXE", 
            "GPSCRIPT.EXE", "HH.EXE", "IMEWDBLD.EXE", "IE4UINIT.EXE", "IEEXEC.EXE", "ILASM.EXE", 
            "INFDEFAULTINSTALL.EXE", "INSTALLUTIL.EXE", "JSC.EXE", "MAKECAB.EXE", "MAVINJECT.EXE", 
            "MICROSOFT.WORKFLOW.COMPILER.EXE", "MMC.EXE", "MPCMDRUN.EXE", "MSBUILD.EXE", 
            "MSCONFIG.EXE", "MSDT.EXE", "MSHTA.EXE", "MSIEXEC.EXE", "NETSH.EXE", "ODBCCONF.EXE", 
            "OFFLINESCANNERSHELL.EXE", "ONEDRIVESTANDALONEUPDATER.EXE", "PCALUA.EXE", "PCWRUN.EXE", 
            "PKTMON.EXE", "PNPUTIL.EXE", "PRESENTATIONHOST.EXE", "PRINT.EXE", "PRINTBRM.EXE", 
            "PSR.EXE", "RASAUTOU.EXE", "RDRLEAKDIAG.EXE", "REG.EXE", "REGASM.EXE", "REGEDIT.EXE", 
            "REGINI.EXE", "REGISTER-CIMPROVIDER.EXE", "REGSVCS.EXE", "REGSVR32.EXE", "REPLACE.EXE", 
            "RPCPING.EXE", "RUNDLL32.EXE", "RUNONCE.EXE", "RUNSCRIPTHELPER.EXE", "SC.EXE", 
            "SCHTASKS.EXE", "SCRIPTRUNNER.EXE", "SETTINGSYNCHOST.EXE", "STORDIAG.EXE", 
            "SYNCAPPVPUBLISHINGSERVER.EXE", "TTDINJECT.EXE", "TTTRACER.EXE", "VBC.EXE", 
            "VERCLSID.EXE", "WAB.EXE", "WLRMDR.EXE", "WMIC.EXE", "WORKFOLDERS.EXE", "WSCRIPT.EXE", 
            "WSRESET.EXE", "WUAUCLT.EXE", "XWIZARD.EXE", "POWERSHELL.EXE", "WINWORD.EXE", 
            "EXCEL.EXE", "POWERPNT.EXE"
        )
    
        $exe = Split-Path -path $executable -Leaf
        return $lolbins -contains $exe.ToUpper()
    }


    function Test-ShouldIncludeEntry {
        param(
            [Parameter(Mandatory = $true)]
            $PersistenceObject,
    
            [Parameter(Mandatory = $true)]
            [ValidateSet("Auto", "All", "Aggressive")]
            [string]$Mode
        )

        # Initialize flags array to collect reasons for inclusion
        $flags = @()

        # Extract values for analysis - only check specific fields
        $valueToCheck = $PersistenceObject.Value
        $executePathToCheck = $PersistenceObject.'Execute Path'
        $pathToCheck = $PersistenceObject.Path
        $signatureToCheck = $PersistenceObject.Signature
        $techniqueToCheck = $PersistenceObject.Technique

        # Helper function to check if signature is valid (treats Valid and Valid_Expired as same)
        function Test-ValidSignature {
            param([string]$Signature)
            if (-not $Signature) { return $false }

            #special exception to treat file not found as valid, to temporarily continue forward and ignore.
            if ($Mode -eq "Auto" -and $Signature -eq "[FILE_NOT_FOUND]") { return $true }

            #special exception to treat expired Microsoft signature as valid
            if ($Mode -eq "Auto" -and $Signature -eq "[VALID_EXPIRED]*Issuer: Microsoft*") { return $true }

            # Check for both VALID and VALID_EXPIRED patterns
            return ($Signature -match '\[VALID[^\]]*\]')
        }


        # Helper function to check if signature is from Microsoft
        function Test-MicrosoftSignature {
            param([string]$Signature)
            if (-not $Signature) { return $false }
            return (Test-ValidSignature $Signature) -and ($Signature -like "*Microsoft*")
        }

        # Helper function to check if file is in Windows system directories
        function Test-WindowsSystemPath {
            param([string]$Path)
            if (-not $Path) { return $false }
            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($Path)
            return $expandedPath -like "C:\Windows*"
        }

        # Helper function for App Paths name matching check
        function Test-AppPathsNameMatch {
            param([string]$Path, [string]$Target, [string]$Signature)
            if (-not $Path -or -not $Target) { return $true }
    
            # Extract executable name from registry path (remove \(Default))
            if ($Path -match '\\([^\\]+)\.exe\\') {
                $pathExeName = $matches[1]
            }
            elseif ($Path -match '\\([^\\]+)\\') {
                $pathExeName = $matches[1]
            }
            else { 
                return $true 
            }
    
            # Extract executable name from target (without extension)
            $targetExeName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $Target -Leaf))
    
            # Exact match - always good
            if ($pathExeName -eq $targetExeName) { return $true }
    
            # For Microsoft signed binaries, be more lenient
            if (Test-MicrosoftSignature $Signature) {
                $knownRedirections = @{
                    'iediag'    = @('iediagcmd')
                    'mplayer2'  = @('wmplayer', 'mplayer')
                    'wmplayer2' = @('wmplayer')
                    'iexplore'  = @('iexplore')
                }
        
                $pathLower = $pathExeName.ToLower()
                $targetLower = $targetExeName.ToLower()
        
                if ($knownRedirections.ContainsKey($pathLower)) {
                    foreach ($validTarget in $knownRedirections[$pathLower]) {
                        if ($targetLower -eq $validTarget) {
                            return $true
                        }
                    }
                }
            }
    
            # Otherwise, it's a mismatch
            return $false
        }

        # === UNIVERSAL DETECTION LOGIC (ALL MODES) ===

        # 1. Check for suspicious string IOCs in Value and Execute Path
        foreach ($fieldValue in @($valueToCheck, $executePathToCheck)) {
            if ($fieldValue) {
                foreach ($ioc in $script:SuspiciousStringIOCs) {
                    if ($fieldValue -like "*$ioc*") {
                        $flags += "SUS_STRING: '$ioc'"
                        break
                    }
                }
            }
        }

        # 2. Check for aggressive string IOCs (Aggressive mode only)
        if ($Mode -eq 'Aggressive' -and $valueToCheck) {
            foreach ($ioc in $script:AggressiveStringIOCs) {
                if ($valueToCheck -like "*$ioc*") {
                    $flags += "SUS_STRING: '$ioc'"
                    break
                }
            }
        }

        # 2.5 Check for insane string IOCs (Insane mode only)
        if ($Mode -eq 'Aggressive' -and $valueToCheck -and $Insane) {
            foreach ($ioc in $script:InsaneStringIOCs) {
                if ($valueToCheck -like "*$ioc*") {
                    $flags += "SUS_STRING: '$ioc'"
                    break
                }
            }
        }


        # 3. Check for base64 content in Value
        if ($valueToCheck) {
            $base64Result = Test-EncodedContent -InputString $valueToCheck
            if ($base64Result -and $base64Result -ne $false) {
                $flags += "$base64Result"
            }
        }

        # 4. Check for network indicators in Value
        if ($valueToCheck) {
            $networkIndicator = Test-NetworkIndicators -InputString $valueToCheck
            if ($networkIndicator) {
                $flags += "NTWRK_STRING: '$networkIndicator'"
            }
        }

        # 5. Check for suspicious file extensions (Aggressive mode only)
        if ($Mode -eq 'Aggressive') {
            foreach ($fieldValue in @($valueToCheck, $executePathToCheck)) {
                if ($fieldValue) {
                    foreach ($ext in $script:suspiciousFileExt) {
                        if ($fieldValue -like "*$ext*") {
                            $flags += "SUS_EXT: '$ext'"
                            break
                        }
                    }
                }
            }
        }

        # 6. Check for suspicious paths (Aggressive mode only)
        if ($Mode -eq 'Aggressive') {
            foreach ($fieldValue in @($valueToCheck, $executePathToCheck)) {
                if ($fieldValue) {
                    foreach ($path in $script:suspiciousPaths) {
                        if ($fieldValue -like "*$path*") {
                            $flags += "SUS_PATH: '$path'"
                            break
                        }
                    }
                }
            }
        }

        # 7. Check for execution binaries in suspicious locations
        foreach ($fieldValue in @($valueToCheck, $executePathToCheck)) {
            if ($fieldValue) {
                foreach ($binary in $script:executionBinaries) {
                    if ($fieldValue -match "(?i)([A-Z]:\\(Users|AppData|Temp)\\.*?\\$binary\b)") {
                        $flags += "SUS_PATH_EXE: $binary"
                        break
                    }
                }
            }
        }

        # 8. Check for LNK target analysis
        if ($PersistenceObject.PSObject.Properties['LnkTargetPath'] -and $PersistenceObject.LnkTargetPath) {
            $lnkTarget = $PersistenceObject.LnkTargetPath
    
            # Check LNK target against suspicious strings
            foreach ($ioc in $script:SuspiciousStringIOCs) {
                if ($lnkTarget -like "*$ioc*") {
                    $flags += "LNK_SUS_STRING: '$ioc'"
                    break
                }
            }
    
            # Check LNK target for suspicious paths
            foreach ($path in $script:suspiciousPaths) {
                if ($lnkTarget -like "*$path*") {
                    $flags += "LNK_SUS_PATH: '$path'"
                    break
                }
            }
        }

        # === TECHNIQUE-SPECIFIC FILTERING LOGIC ===

        $isInWindowsPath = Test-WindowsSystemPath $executePathToCheck
        $isBuiltinBinary = $PersistenceObject.IsBuiltinBinary
        $hasValidSignature = Test-ValidSignature $signatureToCheck
        $hasMicrosoftSignature = Test-MicrosoftSignature $signatureToCheck

        switch ($techniqueToCheck) {
            'Image File Execution Options' {
                # Return ALL entries all the time
                $flags += "IFEO_ENTRY"
            }
    
            'Natural Language Development Platform DLL Override' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_MS_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "NLDP"
                }
            }
    
            'AEDebug Custom Debugger' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                    # Check for suspicious paths in auto mode
                    foreach ($path in $script:suspiciousPaths) {
                        if (($valueToCheck -like "*$path*") -or ($pathToCheck -like "*$path*")) {
                            $flags += "SUS_PATH: '$path'"
                            break
                        }
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                    if (-not $isInWindowsPath) {
                        $flags += "NON_WINDOWS_PATH"
                    }
                }
            }
    
            'Windows Error Reporting Debugger' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS_SIG"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "WER"
                }
            }
    
            'Command Processor AutoRun' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS_SIG"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "CMDAUTORUN"
                }
            }
    
            'Explorer Load Property' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS_SIG"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "EXPLORER_LOAD"
                }
            }
    
            { $_ -like "*Winlogon Userinit*" } {
                # Flag everything all the time
                $flags += "WINLOGON_USERINIT"
            }
    
            { $_ -like "*Winlogon Shell*" } {
                # Flag everything all the time
                $flags += "WINLOGON_SHELL"
            }
    
            'Windows Terminal startOnUserLogin' {
                # Flag everything all the time
                $flags += "TERMINAL_STARTUP"
            }
    
            'AppCertDlls' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS_SIG"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "APPCERTDLL"
                }
            }
            
            'App Paths Hijacking' {
                if ($Mode -eq 'Auto') {
                    # Only flag if names don't match - don't flag just for being unsigned
                    if (-not (Test-AppPathsNameMatch $pathToCheck $valueToCheck $signatureToCheck)) {
                        $flags += "NAME_MISMATCH"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if ($Insane) {
                        if (-not $hasValidSignature) {
                            $flags += "NOT_SIGNED"
                        }
                        if (-not $hasMicrosoftSignature) {
                            $flags += "NOT_MS_SIGNED"
                        }
                    }
                    if (-not (Test-AppPathsNameMatch $pathToCheck $valueToCheck $signatureToCheck)) {
                        $flags += "NAME_MISMATCH"
                    }

                    # Check for command line arguments (Value != Path means arguments present)
                    if ($valueToCheck -ne $executePathToCheck -and $valueToCheck -like "* *") {
                        $flags += "HAS_ARGUMENTS"
                    }
                }
            }
            
            'ServiceDll Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature -and -not $isBuiltinBinary) {
                        $flags += "UNSIGNED_NON_BUILTIN"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
            }
    
            'Group Policy Extension DLL' {
                if ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
            }
    
            'Winlogon MPNotify Executable' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "MPNOTIFY"
                }
            }
    
            'CHM Helper DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature -or -not $isBuiltinBinary -or -not $hasMicrosoftSignature) {
                        $flags += "NOT_MS_BUILTIN"
                    }
                }
            }
    
            'hhctrl.ocx Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature -or -not $isBuiltinBinary -or -not $hasMicrosoftSignature) {
                        $flags += "NOT_MS_BUILTIN"
                    }
                }
            }
    
            'Startup Folder' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "STARTUP"
                }
            }
    
            'User Init Mpr Logon Script' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "MPLOGON"
                }
            }
    
            'AutodialDLL Winsock Injection' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "AUTODIAL"
                }
            }
    
            'LSA Extensions DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "LSA_EXT"
                }
            }
    
            'ServerLevelPluginDll DNS Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "DNS_PLUGIN"
                }
            }
    
            'LSA Password Filter DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "LSA_PWFILTER"
                }
            }
    
            'LSA Authentication Package DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "LSA_AUTH"
                }
            }
    
            'LSA Security Package DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "LSA_SEC"
                }
            }
    
            'Winlogon Notification Package' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "WINLOGON_NOTIFY"
                }
            }
    
            { $_ -like "*DbgManagedDebugger*" } {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "DOTNET_DEBUG"
                }
            }
    
            'ErrorHandler.cmd Hijacking' {
                # Flag everything all the time
                $flags += "ERROR_HANDLER"
            }
    
            { $_ -like "*WMI*Event*" } {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "WMI"
                }
            }
    
            'Windows Service' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
            }
    
            'Power Automate' {
                if ($Mode -eq 'Aggressive') {
                    $flags += "POWER_AUTOMATE"
                }
            }
    
            'Terminal Services InitialProgram' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS_SIG"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "TS_INITIAL"
                }
            }
    
            'Accessibility Tools Backdoor' {
                # Always return everything (already has filtering built-in)
                $flags += "ACCESS_TOOLS"
            }
    
            'Custom AMSI Provider' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "AMSI"
                }
            }
    
            'PowerShell Profile' {
                # Return all entries always
                $flags += "PS_PROFILE"
            }
    
            'Silent Process Exit Monitor' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "SILENT_EXIT"
                }
            }
    
            'Telemetry Controller Command' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "TELEMETRY"
                }
            }
    
            'RDP WDS Startup Programs' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "RDP_WDS"
                }
            }
    
            'BITS Job NotifyCmdLine' {
                # Return everything
                $flags += "BITS_JOB"
            }
    
            'Screensaver Program' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "SCREENSAVER"
                }
            }
    
            'Office Application Startup' {
                if ($Mode -eq 'Aggressive') {
                    $flags += "OFFICE_STARTUP"
                }
            }
    
            'Explorer Tools Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "EXPLORER_TOOLS"
                }
            }
    
            'Explorer Context Menu Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "CONTEXT_MENU"
                }
            }
    
            'Service Control Manager Security Descriptor' {
                # Return all results
                $flags += "SCM_SD_MODIFIED"
            }
    
            'Microsoft Office AI.exe Hijacking' {
                if ($Mode -eq 'Aggressive') {
                    $flags += "OFFICE_AI_HIJACK"
                }
            }
    
            '.NET Startup Hooks DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "DOTNET_HOOKS"
                }
            }
    
            'Suborner Attack' {
                if ($Mode -eq 'Aggressive') {
                    $flags += "SUBORNER_ATTACK"
                }
            }
    
            'DSRM Backdoor' {
                if ($Mode -eq 'Aggressive') {
                    $flags += "DSRM_BACKDOOR"
                }
            }
    
            'Boot Verification Program Hijacking' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "BOOT_VERIFY"
                }
            }
    
            { $_ -like "*AppInit*" } {
                # Return all entries always
                $flags += "APPINIT_DLL"
            }
    
            { $_ -like "*BootExecute*" } {
                # Return everything always
                $flags += "BOOT_EXECUTE"
            }
    
            'Netsh Helper DLL' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature -or -not $isBuiltinBinary -or -not $hasMicrosoftSignature) {
                        $flags += "NOT_MS_BUILTIN"
                    }
                }
            }
    
            { $_ -like "*SetupExecute*" } {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "SETUP_EXECUTE"
                }
            }
    
            { $_ -like "*PlatformExecute*" } {
                if ($Mode -eq 'Auto') {
                    if (-not $hasMicrosoftSignature) {
                        $flags += "NOT_VALID_MS"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    $flags += "PLATFORM_EXECUTE"
                }
            }
    
            'Scheduled Task' {
                if ($Mode -eq 'Auto') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
                elseif ($Mode -eq 'Aggressive') {
                    if (-not $hasValidSignature) {
                        $flags += "NOT_SIGNED"
                    }
                }
            }
        }

        # Set the flags on the object
        $PersistenceObject.Flag = ($flags | Sort-Object -Unique) -join '; '
    
        # === MODE-SPECIFIC DECISION LOGIC ===
    
        if ($Mode -eq 'All') {
            # ALL MODE - Return everything with flags populated
            return $true
        }
        elseif ($Mode -eq 'Auto') {
            # Auto mode: High-fidelity, only flag clearly suspicious items
            return $flags.Count -gt 0
        }
        elseif ($Mode -eq 'Aggressive') {
            # Aggressive mode: Include more items for broader coverage
            if ($flags.Count -gt 0) {
                return $true
            }
            else {
                # Additional aggressive mode checks
                $additionalFlags = @()
            
                # Flag anything without a valid signature
                if ($executePathToCheck -and -not $hasValidSignature) {
                    if ($PersistenceObject.Technique -notlike "App Paths Hijacking") {
                        $additionalFlags += "NO_VALID_SIG"
                    }
                    elseif ($PersistenceObject.Technique -like "App Paths Hijacking" -and $Insane) {
                        $additionalFlags += "NO_VALID_SIG"
                    }
                }
            
                if ($Insane) {
                    # Flag executables in user directories
                    if ($executePathToCheck -like "*\Users\*" -and $executePathToCheck -notlike "*\Program Files*") {
                        $additionalFlags += "USER_DIR_EXECUTABLE"
                    }
            
                    # Flag command line execution patterns
                    if ($valueToCheck -like "*powershell*" -or $valueToCheck -like "*cmd.exe*") {
                        $additionalFlags += "CMDLINE_EXECUTION"
                    }
                }   

                if ($additionalFlags.Count -gt 0) {
                    $allFlags = $flags + $additionalFlags
                    $PersistenceObject.Flag = ($allFlags | Sort-Object -Unique) -join '; '
                    return $true
                }
            
                return $false
            }
        }
    
        # Fallback
        return $false
    }

    function Test-EncodedContent {
        param(
            [Parameter(Mandatory = $true)]
            [string]$InputString
        )
    
        if ([string]::IsNullOrWhiteSpace($InputString)) {
            return $false
        }
    
        # Check for PowerShell encoded command patterns first
        if ($InputString -match '-EncodedCommand\s+([A-Za-z0-9+/]{20,}={0,2})') {
            $base64String = $matches[1]
            $trailing = $base64String.Substring([Math]::Max(0, $base64String.Length - 10))
            return "PS_ENC_CMD -> '$trailing'"
        }
    
        if ($InputString -match '-enc\s+([A-Za-z0-9+/]{20,}={0,2})') {
            $base64String = $matches[1]
            $trailing = $base64String.Substring([Math]::Max(0, $base64String.Length - 10))
            return "PS_ENC -> '$trailing'"
        }
    
        if ($InputString -match '-e\s+([A-Za-z0-9+/]{20,}={0,2})') {
            $base64String = $matches[1]
            $trailing = $base64String.Substring([Math]::Max(0, $base64String.Length - 10))
            return "PS_ENC_SHORT -> '$trailing'"
        }
    
        # Check for hex encoding patterns
        if ($InputString -match '([0-9A-Fa-f]{40,})') {
            $hexString = $matches[1]
            if ($hexString.Length % 2 -eq 0) {
                return "HEX_STRING -> '$($hexString.Substring([Math]::Max(0, $hexString.Length - 10)))'"
            }
        }
    
        # Look for Base64 strings - with better filtering
        if ($InputString -match '([A-Za-z0-9+/]{20,}={0,2})') {
            $possibleB64 = $matches[1]
        
            # Skip if it looks like part of a Windows path or executable name
            if ($InputString -match '\\[^\\]*' + [regex]::Escape($possibleB64) + '[^\\]*\.(exe|dll|sys|bat|cmd|ps1)' -or
                $InputString -match 'C:\\' -or
                $InputString -match 'Program Files' -or
                $InputString -match 'WindowsApps' -or
                $InputString -match 'System32' -or
                $possibleB64 -match '^[a-zA-Z]+$') {
                # Skip if it's just letters (likely part of filename)
                return $false
            }
        
            # Fix Base64 padding if needed
            $paddingNeeded = 4 - ($possibleB64.Length % 4)
            if ($paddingNeeded -ne 4) {
                $possibleB64 += "=" * $paddingNeeded
            }
        
            try {
                $decoded = [System.Convert]::FromBase64String($possibleB64)
                if ($decoded.Length -ge 4) {
                    $trailing = $matches[1].Substring([Math]::Max(0, $matches[1].Length - 10))
                    return "B64_STRING -> '$trailing'"
                }
            }
            catch {
                # If padding fix didn't work, try without the detected string being valid Base64
                # Just flag it as suspicious based on pattern
                if ($matches[1].Length -ge 20) {
                    $trailing = $matches[1].Substring([Math]::Max(0, $matches[1].Length - 10))
                    return "SUSPECTED_B64 -> '$trailing'"
                }
            }
        }
    
        return $false
    }


    # Supporting function: Test for network indicators (domains/IPs) - FIXED
    function Test-NetworkIndicators {
        param(
            [Parameter(Mandatory = $true)]
            [string]$InputString
        )
    
        if ([string]::IsNullOrWhiteSpace($InputString)) { return $null }
    
        $cleanString = $InputString.Trim()
        # Split input by spaces to handle multiple items in one string
        $words = $cleanString -split '\s+'
    
        # First pass - look for IP addresses (higher priority)
        foreach ($word in $words) {
            if ([string]::IsNullOrWhiteSpace($word)) { continue }
        
            $cleanWord = $word.Trim('"', "'", '(', ')', '[', ']')
        
            # IPv4 detection - CHECK FIRST
            if ($cleanWord -match '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$') {
                return $cleanWord
            }
        
            # IPv6 detection
            if ($cleanWord -match '^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$') {
                return $cleanWord
            }
        }
    
        # Second pass - look for domains and URLs
        foreach ($word in $words) {
            if ([string]::IsNullOrWhiteSpace($word)) { continue }
        
            $cleanWord = $word.Trim('"', "'", '(', ')', '[', ']')
        
            # Skip obvious files with extensions - FIXED: Added .lnk and improved pattern
            if ($cleanWord -match '\.(exe|dll|sys|msi|bat|cmd|ps1|vbs|reg|inf|cab|zip|rar|7z|tar|gz|pdf|docx?|xlsx?|pptx?|txt|log|cfg|conf|xml|json|ini|jpe?g|png|gif|bmp|ico|svg|mp[34]|avi|mov|wmv|js|py|html|htm|css|php|asp|aspx|lnk|scr|com|cpl|hta|wsf)$') {
                continue
            }
        
            # Skip filesystem paths - IMPROVED: Better path detection
            if ($cleanWord -match '^[A-Za-z]:\\|^\\\\|[\\/]') {
                continue
            }
        
            # Skip relative paths and filenames containing backslashes or forward slashes
            if ($cleanWord -match '[\\/]') {
                continue
            }
        
            # Domain detection - IMPROVED: Better validation
            if ($cleanWord -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$') {
                $domain = $cleanWord
                $parts = $domain.Split('.')
            
                # Basic validation
                if ($parts.Count -lt 2 -or $domain.Length -lt 4) { continue }
            
                # Skip if it's all numbers (likely an IP we missed)
                if ($domain -match '^\d+\.\d+') { continue }
            
                # Skip Windows app ID patterns
                if ($parts.Count -eq 2 -and $parts[0] -match '^[A-Z][a-zA-Z]{3,}$' -and $parts[1] -match '^[A-Z][a-zA-Z0-9]{3,}$') { continue }
            
                # ADDED: Skip false positives
                $potentialNetworkFP = @(
                    '^OneNote\.'
                )
            
                $isWindowsApp = $false
                foreach ($pattern in $potentialNetworkFP) {
                    if ($domain -match $pattern) {
                        $isWindowsApp = $true
                        break
                    }
                }
                if ($isWindowsApp) { continue }
            
                return $domain
            }
        
            # URL detection (with protocols)
            if ($cleanWord -match '^(?:https?|ftp|ftps)://[^\s<>"\\]{2,}$') {
                return $cleanWord
            }
        }
    
        return $null
    }

    function Test-ExcludeEntry {
        param($entry)
        foreach ($excludeValue in $Exclude.Keys) {
            $fieldName = $Exclude[$excludeValue]
            if ($entry.PSObject.Properties[$fieldName] -and 
                ($entry.$fieldName -like "*$excludeValue*" -or $entry.$fieldName -eq $excludeValue)) {
                return $true
            }
        }
        return $false
    }

    function Write-ColoredPersistenceResult {
        param($PersistenceObject)
    
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host "Technique        : " -NoNewline -ForegroundColor Yellow
        Write-Host $PersistenceObject.Technique -ForegroundColor Cyan
    
        if ($More) {
            Write-Host "Classification   : " -NoNewline -ForegroundColor Yellow  
            Write-Host $PersistenceObject.Classification -ForegroundColor DarkGray
        }
    
        Write-Host "Source           : " -NoNewline -ForegroundColor Yellow
        Write-Host $PersistenceObject.Path -ForegroundColor DarkYellow
    
        # Only display Value if it's different from Execute Path
        if ($PersistenceObject.Value -ne $PersistenceObject.'Execute Path') {
            Write-Host "Value            : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.Value -ForegroundColor White
            Write-Host "Path             : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.'Execute Path' -ForegroundColor Red
        }
        else {
            Write-Host "Value            : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.'Execute Path' -ForegroundColor Red
        }

        if (![string]::IsNullOrWhiteSpace($PersistenceObject.Status)) {
            Write-Host "Status           : " -NoNewline -ForegroundColor Yellow
            
            # Color code based on status
            $statusColor = switch -Wildcard ($PersistenceObject.Status) {
                "*Running*" { "Green" }
                "*Stopped*" { "Red" }
                "*Disabled*" { "DarkGray" }
                "*Ready*" { "Green" }
                default { "White" }
            }
            Write-Host $PersistenceObject.Status -ForegroundColor $statusColor
        }
            
        if (![string]::IsNullOrWhiteSpace($PersistenceObject.SHA256)) {
            Write-Host "SHA256           : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.SHA256 -ForegroundColor DarkGray
        }
    
        # Display LNK-specific information if available
        if ($PersistenceObject.PSObject.Properties['LnkTargetPath'] -and 
            ![string]::IsNullOrWhiteSpace($PersistenceObject.LnkTargetPath)) {
            Write-Host "LNK Target       : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.LnkTargetPath -ForegroundColor Red
        }
    
        if ($PersistenceObject.PSObject.Properties['LnkTargetHash'] -and 
            ![string]::IsNullOrWhiteSpace($PersistenceObject.LnkTargetHash)) {
            Write-Host "Target Hash      : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.LnkTargetHash -ForegroundColor DarkGray
        }

        Write-Host "Signature        : " -NoNewline -ForegroundColor Yellow
    
        # Modify signature display based on -More switch
        $signatureToDisplay = $PersistenceObject.Signature
    
        # If -More is NOT used, remove thumbprint from valid signatures
        if (-not $More -and $signatureToDisplay -like "*[VALID]*" -and $signatureToDisplay -like "*Thumbprint:*") {
            # Remove the thumbprint portion from the signature
            $signatureToDisplay = $signatureToDisplay -replace ', Thumbprint: [A-F0-9]+', ''
        }
    
        # Color code based on signature status
        if ($signatureToDisplay -like "*[VALID]*") {
            Write-Host $signatureToDisplay -ForegroundColor White
        }
        elseif ($signatureToDisplay -eq "[NOT_SIGNED]") {
            Write-Host $signatureToDisplay -ForegroundColor White
        }
        elseif ($signatureToDisplay -like "*ERROR*") {
            Write-Host $signatureToDisplay -ForegroundColor White
        }
        else {
            Write-Host $signatureToDisplay -ForegroundColor White
        }

        if (![string]::IsNullOrWhiteSpace($PersistenceObject.Flag)) {
            $flagValue = $PersistenceObject.Flag
            if ($flagValue.Length -gt 100) {
                $flagValue = $flagValue.Substring(0, 100) + "..."
            }
            Write-Host "Flag             : " -NoNewline -ForegroundColor Yellow
            Write-Host $flagValue -ForegroundColor DarkRed
        }

        if ($More) {
            Write-Host "Rights           : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.Rights -ForegroundColor DarkGray
            Write-Host "Hostname         : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.Hostname -ForegroundColor DarkGray
        }

        if ($More) {
            Write-Host "IsBuiltinBinary  : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.IsBuiltinBinary -ForegroundColor DarkGray
            Write-Host "IsLolbin         : " -NoNewline -ForegroundColor Yellow
            Write-Host $PersistenceObject.IsLolbin -ForegroundColor DarkGray
        
            if (![string]::IsNullOrWhiteSpace($PersistenceObject.Note)) {
                Write-Host "Note             : " -NoNewline -ForegroundColor Yellow
                Write-Host $PersistenceObject.Note -ForegroundColor DarkGray
            }
        
            if (![string]::IsNullOrWhiteSpace($PersistenceObject.Reference)) {
                Write-Host "Reference        : " -NoNewline -ForegroundColor Yellow
                Write-Host $PersistenceObject.Reference -ForegroundColor Blue
            }
        }
    }


    function Get-AllRegistryHives {
        [CmdletBinding()]
        param(
            [Switch]$Unloaded
        )
        Dismount-TemporaryHives
        $hiveList = [Collections.ArrayList]::new()
        $script:mountedHives = @()  # Track mounted hives for cleanup
    
        # Check admin privileges if -Unloaded is requested
        if ($Unloaded) {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            if (-not $isAdmin) {
                Write-Warning "Administrator privileges required for -Unloaded switch. Continuing with loaded hives only."
                $Unloaded = $false
            }
        }
    
        # Add HKEY_LOCAL_MACHINE
        $hklm = Get-Item Registry::HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
        if ($hklm) { $null = $hiveList.Add($hklm.PSPath) }
    
        # Add HKEY_CURRENT_USER  
        $hkcu = Get-Item Registry::HKEY_CURRENT_USER -ErrorAction SilentlyContinue
        if ($hkcu) { $null = $hiveList.Add($hkcu.PSPath) }
    
        # Add all HKEY_USERS subkeys (loaded user profiles)
        $loadedUserHives = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue
        foreach ($hive in $loadedUserHives) {
            $null = $hiveList.Add($hive.PSPath)
        }
    
        # If -Unloaded requested, attempt to mount unloaded user profiles
        if ($Unloaded) {
            Write-Verbose "Attempting to load unloaded user profiles..."
        
            try {
                # Get all user profiles from ProfileList
                $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                $profiles = Get-ChildItem $profileListPath -ErrorAction Stop
            
                foreach ($profile in $profiles) {
                    $sid = Split-Path $profile.Name -Leaf
                
                    # Skip if SID is already loaded
                    $alreadyLoaded = $loadedUserHives | Where-Object { $_.Name -like "*$sid*" }
                    if ($alreadyLoaded) { continue }
                
                    # Get profile path
                    $profileData = Get-ItemProperty $profile.PSPath -ErrorAction SilentlyContinue
                    if (-not $profileData.ProfileImagePath) { continue }
                
                    $ntUserPath = Join-Path $profileData.ProfileImagePath "NTUSER.DAT"
                
                    # Attempt to mount NTUSER.DAT
                    if (Test-Path $ntUserPath -ErrorAction SilentlyContinue) {
                        $mountPoint = "TEMP_DFIR_$($sid.Replace('-','_'))"
                    
                        try {
                            $result = & reg.exe load "HKLM\$mountPoint" $ntUserPath 2>$null
                            if ($LASTEXITCODE -eq 0) {
                                $mountedHivePath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\$mountPoint"
                                $null = $hiveList.Add($mountedHivePath)
                                $script:mountedHives += $mountPoint
                                Write-Verbose "Mounted unloaded profile: $sid"
                            }
                            else {
                                Write-Verbose "Failed to mount profile for SID: $sid (reg.exe exit code: $LASTEXITCODE)"
                            }
                        }
                        catch {
                            Write-Verbose "Error mounting profile $sid : $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to enumerate user profiles: $($_.Exception.Message)"
            }
        }
    
        Write-Verbose "Found $($hiveList.Count) registry hives for scanning (Mounted: $($script:mountedHives.Count))"
        return $hiveList
    }

    function Dismount-TemporaryHives {
        [CmdletBinding()]
        param()

        # Get Temp DFIR Hives by name - find all hives with the naming convention prefix "TEMP_DFIR_"
        $TempDFIRHives = @()
        try {
            $hklmSubkeys = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE" -ErrorAction SilentlyContinue
            $TempDFIRHives = $hklmSubkeys | Where-Object { $_.Name -like "*TEMP_DFIR_*" } | ForEach-Object { Split-Path $_.Name -Leaf }
        }
        catch {
            Write-Verbose "Error enumerating HKLM subkeys: $($_.Exception.Message)"
        }
    
        if ($script:mountedHives -and $script:mountedHives.Count -gt 0 -or $TempDFIRHives.Count -gt 0) {
            # Combine both arrays and remove duplicates
            $allHivesToDismount = @()
            if ($script:mountedHives) { $allHivesToDismount += $script:mountedHives }
            if ($TempDFIRHives) { $allHivesToDismount += $TempDFIRHives }
            $allHivesToDismount = $allHivesToDismount | Select-Object -Unique
        
            Write-Verbose "Cleaning up $($allHivesToDismount.Count) temporarily mounted hives..."
        
            foreach ($mountPoint in $allHivesToDismount) {
                try {
                    $result = & reg.exe unload "HKLM\$mountPoint" 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Successfully dismounted: $mountPoint"
                    }
                    else {
                        Write-Warning "Failed to dismount $mountPoint (exit code: $LASTEXITCODE)"
                    }
                }
                catch {
                    Write-Warning "Error dismounting $mountPoint : $($_.Exception.Message)"
                }
            }
        
            # Clear the tracking array
            $script:mountedHives = @()
        }
        else {
            Write-Verbose "No temporary hives to dismount"
        }
    }

    # Get Registry Hives
    if ($All -or $LoadHives) {
        $systemAndUsersHives = Get-AllRegistryHives -Unloaded
    }
    else {
        $systemAndUsersHives = Get-AllRegistryHives
    }


    # PERSISTENCE FUNCTIONS
    # ----------------------

    function Get-RunKeys {
        Write-Verbose "$hostname - Getting Registry Run properties..."
    
        # Define all Run key locations to check
        $runKeyLocations = @(
            # Standard Run keys
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Name = "Registry Run Key"
                Note = "Executables in properties of the Run key are executed when the user logs in or when the machine boots up."
            },
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Name = "Registry RunOnce Key" 
                Note = "Executables in properties of the RunOnce key are run once when the user logs in or machine boots up, then deleted."
            },
            # RunServices (Windows 9x legacy, but still functional)
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
                Name = "Registry RunServices Key"
                Note = "Legacy Windows 9x services run key - still functional on modern Windows."
            },
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                Name = "Registry RunServicesOnce Key"
                Note = "Legacy Windows 9x services run once key - still functional on modern Windows."
            },
            # Policies Run keys (often overlooked)
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                Name = "Registry Policies Run Key"
                Note = "Run key under Policies - executed during user logon, harder to detect."
            },
            # RunOnceEx (used by Windows Update and installers)
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
                Name = "Registry RunOnceEx Key"
                Note = "Extended RunOnce key used by installers and Windows Update - supports dependencies and ordering."
            },
            # RunEx (used by Windows Update and installers)
            @{
                Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
                Name = "Registry RunEx Key"
                Note = "Extended Run key used by installers and Windows Update - supports dependencies and ordering."
            },
            # WOW64 Run keys (32-bit applications on 64-bit systems)
            @{
                Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                Name = "Registry WOW64 Run Key"
                Note = "32-bit application Run key on 64-bit systems - executed during user logon."
            },
            @{
                Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                Name = "Registry WOW64 RunOnce Key"
                Note = "32-bit application RunOnce key on 64-bit systems - executed once during user logon."
            },
            # Terminal Services Run keys
            @{
                Path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"
                Name = "Registry Terminal Server Run Key"
                Note = "Terminal Server specific Run key - executed during Terminal Server user logon."
            },
            @{
                Path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                Name = "Registry Terminal Server RunOnce Key"
                Note = "Terminal Server specific RunOnce key - executed once during Terminal Server user logon."
            },
            @{
                Path          = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\System"
                Name          = "Winlogon System"
                Note          = "System processes executed during logon - typically blank or lsass.exe."
                IsValueDirect = $true
            }
        )
    
        foreach ($location in $runKeyLocations) {
            foreach ($hive in $systemAndUsersHives) {
                # Skip user hives for system-only keys
                if ($location.SystemOnly -and -not (($hive -like "*HKEY_LOCAL_MACHINE*") -or ($hive -like "*HKEY_USERS\S-1-5-18*") -or ($hive -like "*HKEY_USERS\S-1-5-19*") -or ($hive -like "*HKEY_USERS\S-1-5-20*"))) {
                    continue
                }
            
                $fullPath = "$hive\$($location.Path)"
            
                if ($location.IsValueDirect) {
                    # Handle direct registry values (like Userinit, Shell)
                    $regValue = Get-ItemProperty -Path (Split-Path $fullPath) -Name (Split-Path $fullPath -Leaf) -ErrorAction SilentlyContinue
                    if ($regValue) {
                        $valueName = Split-Path $fullPath -Leaf
                        $actualValue = $regValue.$valueName
                    
                        if ($actualValue -and $actualValue -ne "") {
                            $currentHive = Convert-Path -Path $hive
                            $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
                        
                            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique $location.Name -Classification 'MITRE ATT&CK T1547.001' -Path $fullPath -Value $actualValue -AccessGained $access -Note $location.Note -Reference 'https://attack.mitre.org/techniques/T1547/001/'
                        
                            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                $script:globalPersistenceObjectArray.Add($PersistenceObject)
                            }
                        }
                    }
                }
                else {
                    # Handle registry keys with multiple properties
                    $runProps = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue
                    if ($runProps) {
                        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps)) {
                            if ($psProperties.Contains($prop.Name)) { continue }
                        
                            $propPath = Convert-Path -Path $runProps.PSPath -ErrorAction SilentlyContinue
                            if ($propPath) {
                                $propPath += '\' + $prop.Name
                            }
                            $currentHive = Convert-Path -Path $hive
                            $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
                        
                            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique $location.Name -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained $access -Note $location.Note -Reference 'https://attack.mitre.org/techniques/T1547/001/'
                        
                            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                $script:globalPersistenceObjectArray.Add($PersistenceObject)
                            }
                        }
                    }
                }
            }
        }
    }

    function Get-ImageFileExecutionOptions {
        Write-Verbose "$hostname - Getting Image File Execution Options..."
        foreach ($hive in $systemAndUsersHives) {
            $ifeOpts = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue
            if ($ifeOpts) {
                foreach ($key in $ifeOpts) {
                    $debugger = Get-ItemProperty -Path Registry::$key -Name Debugger -ErrorAction SilentlyContinue
                    if ($debugger -and $debugger.Debugger) {
                        $propPath = Convert-Path -Path $debugger.PSPath
                        $propPath += '\Debugger'
                    
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Image File Execution Options' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $debugger.Debugger -AccessGained 'System/User' -Note 'Executables in the Debugger property are run instead of the target program. Access level depends on context of debugged process.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }

    function Get-NLDPDllOverridePath {
        Write-Verbose "$hostname - Getting Natural Language Development Platform DLL path override properties..."
        foreach ($hive in $systemAndUsersHives) {
            $NLDPLanguages = Get-ChildItem -Path "$hive\SYSTEM\CurrentControlSet\Control\ContentIndex\Language" -ErrorAction SilentlyContinue
            if ($NLDPLanguages) {
                foreach ($key in $NLDPLanguages) {
                    $DllOverridePath = Get-ItemProperty -Path Registry::$key -Name *DLLPathOverride -ErrorAction SilentlyContinue
                    if ($DllOverridePath) {
                        $properties = Get-ItemProperty -Path Registry::$key -ErrorAction SilentlyContinue | Select-Object -Property *DLLPathOverride, PS*
                        if ($properties) {
                            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $properties)) {
                                if ($psProperties.Contains($prop.Name)) { continue }
                                if (-not $prop.Name.EndsWith('DLLPathOverride')) { continue }
                            
                                $propPath = Convert-Path -Path $properties.PSPath -ErrorAction SilentlyContinue
                                if ($propPath) {
                                    $propPath += '\' + $prop.Name
                                    $currentHive = Convert-Path -Path $hive -ErrorAction SilentlyContinue
                                    $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
                                
                                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Natural Language Development Platform DLL Override' -Classification 'Hexacorn Technique N.98' -Path $propPath -Value $properties.($prop.Name) -AccessGained $access -Note 'DLLs listed in DLLPathOverride properties are loaded by SearchIndexer.exe for language processing.' -Reference 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
                                
                                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    function Get-AeDebug {
        Write-Verbose "$hostname - Getting AeDebug properties..."
        foreach ($hive in $systemAndUsersHives) {
            $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -ErrorAction SilentlyContinue
            if ($aeDebugger -and $aeDebugger.Debugger) {
                $propPath = Convert-Path -Path $aeDebugger.PSPath
                $propPath += '\Debugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.Debugger -AccessGained 'System/User' -Note "The executable in the Debugger property is run when a process crashes. Access depends on context of debugged process. Visual Studio debugger may be legitimate." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }

            $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -ErrorAction SilentlyContinue
            if ($aeDebugger -and $aeDebugger.Debugger) {
                $propPath = Convert-Path -Path $aeDebugger.PSPath
                $propPath += '\Debugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Wow6432Node AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.Debugger -AccessGained 'System/User' -Note "The executable in the Debugger property is run when a 32-bit process crashes on 64-bit system. Access depends on context of debugged process." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-WerFaultHangs {
        Write-Verbose "$hostname - Getting WerFault Hangs registry key properties..."
        foreach ($hive in $systemAndUsersHives) {
            $werfaultDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name Debugger -ErrorAction SilentlyContinue
            if ($werfaultDebugger -and $werfaultDebugger.Debugger) {
                $propPath = Convert-Path -Path $werfaultDebugger.PSPath
                $propPath += '\Debugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.Debugger -AccessGained 'System' -Note 'The executable in the Debugger property is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }

            $werfaultReflectDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name ReflectDebugger -ErrorAction SilentlyContinue
            if ($werfaultReflectDebugger -and $werfaultReflectDebugger.ReflectDebugger) {
                $propPath = Convert-Path -Path $werfaultReflectDebugger.PSPath
                $propPath += '\ReflectDebugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting ReflectDebugger' -Classification 'Hexacorn Technique N.85' -Path $propPath -Value $werfaultReflectDebugger.ReflectDebugger -AccessGained 'System' -Note 'The executable in the ReflectDebugger property is spawned by WerFault.exe when called with the -pr argument.' -Reference 'https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-CmdAutoRun {
        Write-Verbose "$hostname - Getting Command Processor's AutoRun property..."
        foreach ($hive in $systemAndUsersHives) {
            $autorunProperty = Get-ItemProperty -Path "$hive\Software\Microsoft\Command Processor" -Name AutoRun -ErrorAction SilentlyContinue
            if ($autorunProperty -and $autorunProperty.AutoRun) {
                $propPath = Convert-Path -Path $hive -ErrorAction SilentlyContinue
                if ($propPath) {
                    $propPath += "\Software\Microsoft\Command Processor\AutoRun"
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Command Processor AutoRun' -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorunProperty.AutoRun -AccessGained 'User' -Note 'The executable in the AutoRun property is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-ExplorerLoad {
        Write-Verbose "$hostname - Getting Explorer's Load property..."
        foreach ($hive in $systemAndUsersHives) {
            $loadKey = Get-ItemProperty -Path "$hive\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name Load -ErrorAction SilentlyContinue
            if ($loadKey -and $loadKey.Load) {
                $propPath = Convert-Path -Path $loadKey.PSPath
                $propPath += '\Load'
                $currentHive = Convert-Path -Path $hive
                $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Load Property' -Classification 'Uncatalogued Technique N.2' -Path $propPath -Value $loadKey.Load -AccessGained $access -Note 'The executable in the Load property is run by explorer.exe at login time.' -Reference 'https://persistence-info.github.io/Data/windowsload.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-WinlogonUserinit {
        Write-Verbose "$hostname - Getting Winlogon's Userinit property..."
        foreach ($hive in $systemAndUsersHives) {
            $userinit = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit -ErrorAction SilentlyContinue
            if ($userinit -and $userinit.Userinit) {
                $propPath = Convert-Path -Path $userinit.PSPath
                $propPath += '\Userinit'
            
                # Only flag if not the default value
                if ($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,') {
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Userinit Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $userinit.Userinit -AccessGained 'System' -Note "The executables in the Userinit property are run at login time. Normal value is 'C:\Windows\system32\userinit.exe,' without additional executables." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-WinlogonShell {
        Write-Verbose "$hostname - Getting Winlogon's Shell property..."
        foreach ($hive in $systemAndUsersHives) {
            $shell = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -ErrorAction SilentlyContinue
            if ($shell -and $shell.Shell) {
                $propPath = Convert-Path -Path $shell.PSPath
                $propPath += '\Shell'
            
                # Only flag if not the default value
                if ($shell.Shell -ne 'explorer.exe') {
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Shell Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $shell.Shell -AccessGained 'User' -Note "The executables in the Shell property are run as the default shell. Normal value is 'explorer.exe' without additional executables." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-TerminalProfileStartOnUserLogin {
        Write-Verbose "$hostname - Checking Windows Terminal startOnUserLogin settings..."
        $userDirectories = Get-ChildItem -Path 'C:\Users\' -ErrorAction SilentlyContinue
        foreach ($directory in $userDirectories) {
            $terminalDirectories = Get-ChildItem -Path "$($directory.FullName)\Appdata\Local\Packages\Microsoft.WindowsTerminal_*" -ErrorAction SilentlyContinue
            foreach ($terminalDirectory in $terminalDirectories) {
                $settingsPath = "$($terminalDirectory.FullName)\LocalState\settings.json"
                if (-not (Test-Path $settingsPath -ErrorAction SilentlyContinue)) { continue }
            
                try {
                    $settingsFile = Get-Content -Raw -Path $settingsPath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($settingsFile.startOnUserLogin -ne $true -and $settingsFile.startOnUserLogin -ne 'true') { continue }
                
                    $defaultProfileGuid = $settingsFile.defaultProfile
                    $found = $false 
                
                    # Handle both new and old profile structure
                    $profiles = if ($settingsFile.profiles.list) { $settingsFile.profiles.list } else { $settingsFile.profiles }
                
                    foreach ($profile in $profiles) {
                        if ($profile.guid -eq $defaultProfileGuid) {
                            $executable = if ($profile.commandline) { $profile.commandline } else { $profile.name }
                        
                            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Terminal startOnUserLogin' -Classification 'Uncatalogued Technique N.3' -Path $settingsPath -Value $executable -AccessGained 'User' -Note "The executable specified in a Terminal profile with startOnUserLogin=true runs every time the user logs in." -Reference 'https://twitter.com/nas_bench/status/1550836225652686848'
                        
                            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                $script:globalPersistenceObjectArray.Add($PersistenceObject)
                            }
                            $found = $true
                            break
                        }
                    }
                }
                catch {
                    # Skip invalid JSON files or access errors
                    Write-Verbose "Could not parse Terminal settings file: $settingsPath"
                    continue
                }
            }
        }
    }
    function Get-AppCertDlls {
        Write-Verbose "$hostname - Getting AppCertDlls properties..."
        foreach ($hive in $systemAndUsersHives) {
            $appCertDllsProps = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -ErrorAction SilentlyContinue
            if ($appCertDllsProps) {
                foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $appCertDllsProps)) {
                    if ($psProperties.Contains($prop.Name)) { continue }
                
                    $propPath = Convert-Path -Path $appCertDllsProps.PSPath
                    $propPath += '\' + $prop.Name
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AppCertDlls' -Classification 'MITRE ATT&CK T1546.009' -Path $propPath -Value $appCertDllsProps.($prop.Name) -AccessGained 'System' -Note 'DLLs in AppCertDlls registry key are loaded by every process that loads Win32 API at process creation.' -Reference 'https://attack.mitre.org/techniques/T1546/009/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-AppPaths {
        Write-Verbose "$hostname - Getting App Paths inside the registry..."
        foreach ($hive in $systemAndUsersHives) {
            $appPathsKeys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" -ErrorAction SilentlyContinue
            foreach ($key in $appPathsKeys) {
                $appPath = Get-ItemProperty -Path Registry::$key -Name '(Default)' -ErrorAction SilentlyContinue
                if ($appPath -and $appPath.'(Default)') {
                    $keyName = $key.PSChildName
                    $targetPath = $appPath.'(Default)'
                
                    # Expand environment variables
                    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($targetPath)
                
                    # Create persistence object for mode-based filtering
                    $propPath = Convert-Path -Path $key.PSPath -ErrorAction SilentlyContinue
                    if ($propPath) {
                        $propPath += '\(Default)'
                    
                        # Build note with context about the redirection
                        $keyBaseName = [System.IO.Path]::GetFileNameWithoutExtension($keyName)
                        $actualExeName = if (Test-Path $expandedPath -ErrorAction SilentlyContinue) {
                            [System.IO.Path]::GetFileNameWithoutExtension($expandedPath)
                        }
                        else {
                            "File not found"
                        }
                    
                        $note = "App Path '$keyBaseName' redirects to '$actualExeName'. This mechanism can be used to hijack application launches."
                    
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'App Paths Hijacking' -Classification 'Hexacorn Technique N.3' -Path $propPath -Value $targetPath -AccessGained 'System/User' -Note $note -Reference 'https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }

    function Get-ServiceDlls {
        Write-Verbose "$hostname - Getting Service DLLs inside the registry..."
        foreach ($hive in $systemAndUsersHives) {
            $keys = Get-ChildItem -Path "$hive\SYSTEM\CurrentControlSet\Services\" -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $ImagePath = (Get-ItemProperty -Path ($key.pspath) -ErrorAction SilentlyContinue).ImagePath
                if ($ImagePath -and $ImagePath.ToLower().Contains('\svchost.exe')) {
                    $ServiceDll = $null
                    $propPath = $null
                
                    # Check Parameters subkey first, then main key
                    if (Test-Path -Path ($key.pspath + '\Parameters') -ErrorAction SilentlyContinue) {
                        $ServiceDll = (Get-ItemProperty -Path ($key.pspath + '\Parameters') -ErrorAction SilentlyContinue).ServiceDll
                        if ($ServiceDll) {
                            $propPath = (Convert-Path -Path "$($key.pspath)" -ErrorAction SilentlyContinue) + '\Parameters\ServiceDll'
                        }
                    }
                    else {
                        $ServiceDll = (Get-ItemProperty -Path ($key.pspath) -ErrorAction SilentlyContinue).ServiceDll
                        if ($ServiceDll) {
                            $propPath = (Convert-Path -Path "$($key.pspath)" -ErrorAction SilentlyContinue) + '\ServiceDll'
                        }
                    }
                
                    if ($ServiceDll -and $propPath) {
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServiceDll Hijacking' -Classification 'MITRE ATT&CK T1543.003' -Path $propPath -Value $ServiceDll -AccessGained 'System' -Note "ServiceDll property specifies DLL loaded by svchost.exe for this service. Malicious DLLs can be loaded by modifying this entry." -Reference 'https://attack.mitre.org/techniques/T1543/003/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }

    function Get-GPExtensionDlls {
        Write-Verbose "$hostname - Getting Group Policy Extension DLLs inside the registry..."
        foreach ($hive in $systemAndUsersHives) {
            $keys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $DllName = (Get-ItemProperty -Path ($key.pspath) -ErrorAction SilentlyContinue).DllName
                if ($DllName) {
                    $propPath = (Convert-Path -Path "$($key.pspath)" -ErrorAction SilentlyContinue) + '\DllName'
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Group Policy Extension DLL' -Classification 'Uncatalogued Technique N.4' -Path $propPath -Value $DllName -AccessGained 'System' -Note 'DLLs in GPExtensions DllName property are loaded by Group Policy service (gpsvc) during policy processing.' -Reference 'https://persistence-info.github.io/Data/gpoextension.html'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-WinlogonMPNotify {
        Write-Verbose "$hostname - Getting Winlogon MPNotify property..."
        foreach ($hive in $systemAndUsersHives) {
            $mpnotify = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name mpnotify -ErrorAction SilentlyContinue
            if ($mpnotify -and $mpnotify.mpnotify) {
                $propPath = (Convert-Path -Path $mpnotify.PSPath -ErrorAction SilentlyContinue) + '\mpnotify'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon MPNotify Executable' -Classification 'Uncatalogued Technique N.5' -Path $propPath -Value $mpnotify.mpnotify -AccessGained 'System' -Note 'Executable specified in mpnotify property is run by Winlogon during user logon with 30-second timeout.' -Reference 'https://persistence-info.github.io/Data/mpnotify.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-CHMHelperDll {
        Write-Verbose "$hostname - Getting CHM Helper DLL inside the registry..."
        foreach ($hive in $systemAndUsersHives) {
            $dllLocation = Get-ItemProperty -Path "$hive\Software\Microsoft\HtmlHelp Author" -Name Location -ErrorAction SilentlyContinue
            if ($dllLocation -and $dllLocation.Location) {
                $propPath = (Convert-Path -Path "$($dllLocation.pspath)" -ErrorAction SilentlyContinue) + '\Location'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'CHM Helper DLL' -Classification 'Hexacorn Technique N.76' -Path $propPath -Value $dllLocation.Location -AccessGained 'User' -Note 'DLLs in HtmlHelp Author Location property are loaded when CHM help files are parsed.' -Reference 'https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-HHCtrlHijacking {
        Write-Verbose "$hostname - Getting the hhctrl.ocx library inside the registry..."
        $hive = (Get-Item Registry::HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue).PSpath
        if ($hive) {
            $dllLocation = Get-ItemProperty -Path "$hive\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32" -Name '(Default)' -ErrorAction SilentlyContinue
        
            if ($dllLocation -and $dllLocation.'(Default)') {
                $propPath = (Convert-Path -Path "$($dllLocation.pspath)" -ErrorAction SilentlyContinue) + '\(Default)'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'hhctrl.ocx Hijacking' -Classification 'Hexacorn Technique N.77' -Path $propPath -Value $dllLocation.'(Default)' -AccessGained 'User' -Note 'hhctrl.ocx DLL is loaded when CHM help files are parsed or hh.exe starts. Registry entry can be modified to load malicious DLL.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
            else {
                # Check fallback location
                $dllPath = "C:\Windows\System32\hhctrl.ocx"
                if (Test-Path $dllPath -ErrorAction SilentlyContinue) {
                    $isOSBinary = try { 
                        (Get-AuthenticodeSignature $dllPath -ErrorAction SilentlyContinue).IsOsBinary 
                    }
                    catch { 
                        $false 
                    }
                
                    if (-not $isOSBinary) {
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'hhctrl.ocx Hijacking' -Classification 'Hexacorn Technique N.77' -Path $dllPath -Value "Fallback DLL not OS-signed" -AccessGained 'User' -Note 'Fallback hhctrl.ocx at System32 location is not an OS binary, indicating potential DLL replacement.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }
    function Get-StartupPrograms {
        Write-Verbose "$hostname - Checking users' Startup folder contents..."
        $userDirectories = Get-ChildItem -Path 'C:\Users\' -ErrorAction SilentlyContinue
        foreach ($directory in $userDirectories) {
            $startupPath = "$($directory.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
            if (-not (Test-Path $startupPath -ErrorAction SilentlyContinue)) { continue }
        
            $startupFiles = Get-ChildItem -Path $startupPath -ErrorAction SilentlyContinue
            foreach ($file in $startupFiles) {
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Startup Folder' -Classification 'MITRE ATT&CK T1547.001' -Path $startupPath -Value $file.FullName -AccessGained 'User' -Note "Files in the Startup folder are executed when the user logs in." -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-UserInitMprScript {
        Write-Verbose "$hostname - Getting UserInitMprLogonScript properties..."
        foreach ($hive in $systemAndUsersHives) {
            $mprlogonscript = Get-ItemProperty -Path "$hive\Environment" -Name UserInitMprLogonScript -ErrorAction SilentlyContinue
            if ($mprlogonscript -and $mprlogonscript.UserInitMprLogonScript) {
                $propPath = (Convert-Path -Path $mprlogonscript.PSPath -ErrorAction SilentlyContinue) + '\UserInitMprLogonScript'
                $currentHive = Convert-Path -Path $hive -ErrorAction SilentlyContinue
                $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'User Init Mpr Logon Script' -Classification 'MITRE ATT&CK T1037.001' -Path $propPath -Value $mprlogonscript.UserInitMprLogonScript -AccessGained $access -Note 'The executable specified in UserInitMprLogonScript property is run when the user logs on.' -Reference 'https://attack.mitre.org/techniques/T1037/001/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-AutodialDLL {
        Write-Verbose "$hostname - Getting AutodialDLL property..."
        foreach ($hive in $systemAndUsersHives) {
            $autodialDll = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters" -Name AutodialDLL -ErrorAction SilentlyContinue
            if ($autodialDll -and $autodialDll.AutodialDLL) {
                $propPath = (Convert-Path -Path $autodialDll.PSPath -ErrorAction SilentlyContinue) + '\AutodialDLL'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AutodialDLL Winsock Injection' -Classification 'Hexacorn Technique N.24' -Path $propPath -Value $autodialDll.AutodialDLL -AccessGained 'System' -Note 'DLL specified in AutodialDLL property is loaded by Winsock library on internet connections.' -Reference 'https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-LsaExtensions {
        Write-Verbose "$hostname - Getting LSA extensions..."
        foreach ($hive in $systemAndUsersHives) {
            $lsaExtensions = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv" -Name Extensions -ErrorAction SilentlyContinue
            if ($lsaExtensions -and $lsaExtensions.Extensions) {
                $dlls = $lsaExtensions.Extensions -split '\s+' | Where-Object { $_ -ne '' }
                foreach ($dll in $dlls) {
                    $propPath = (Convert-Path -Path $lsaExtensions.PSPath -ErrorAction SilentlyContinue) + '\Extensions'
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Extensions DLL' -Classification 'Uncatalogued Technique N.6' -Path $propPath -Value $dll -AccessGained 'System' -Note 'DLLs specified in LSA Extensions property are loaded by LSASS at machine boot.' -Reference 'https://persistence-info.github.io/Data/lsaaextension.html'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-ServerLevelPluginDll {
        Write-Verbose "$hostname - Getting ServerLevelPluginDll property..."
        foreach ($hive in $systemAndUsersHives) {
            $pluginDll = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll -ErrorAction SilentlyContinue
            if ($pluginDll -and $pluginDll.ServerLevelPluginDll) {
                $propPath = (Convert-Path -Path $pluginDll.PSPath -ErrorAction SilentlyContinue) + '\ServerLevelPluginDll'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServerLevelPluginDll DNS Hijacking' -Classification 'Uncatalogued Technique N.7' -Path $propPath -Value $pluginDll.ServerLevelPluginDll -AccessGained 'System' -Note 'DLL specified in ServerLevelPluginDll property is loaded by DNS service on systems with DNS Server role.' -Reference 'https://persistence-info.github.io/Data/serverlevelplugindll.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-LsaPasswordFilter {
        Write-Verbose "$hostname - Getting LSA password filters..."
        foreach ($hive in $systemAndUsersHives) {
            $passwordFilters = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Notification Packages' -ErrorAction SilentlyContinue
            if ($passwordFilters -and $passwordFilters.'Notification Packages') {
                $dlls = $passwordFilters.'Notification Packages' -split '\s+' | Where-Object { $_ -ne '' }
                foreach ($dll in $dlls) {
                    $dllPath = if ($dll -like "*.dll") { "C:\Windows\System32\$dll" } else { "C:\Windows\System32\$dll.dll" }
                    $propPath = (Convert-Path -Path $passwordFilters.PSPath -ErrorAction SilentlyContinue) + '\Notification Packages'
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Password Filter DLL' -Classification 'MITRE ATT&CK T1556.002' -Path $propPath -Value $dllPath -AccessGained 'System' -Note 'DLLs specified in Notification Packages are loaded by LSASS and can intercept password changes.' -Reference 'https://attack.mitre.org/techniques/T1556/002/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-LsaAuthenticationPackages {
        Write-Verbose "$hostname - Getting LSA authentication packages..."
        foreach ($hive in $systemAndUsersHives) {
            $authPackages = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Authentication Packages' -ErrorAction SilentlyContinue
            if ($authPackages -and $authPackages.'Authentication Packages') {
                $dlls = $authPackages.'Authentication Packages' -split '\s+' | Where-Object { $_ -ne '' }
                foreach ($dll in $dlls) {
                    $dllPath = "C:\Windows\System32\$dll.dll"
                    $propPath = (Convert-Path -Path $authPackages.PSPath -ErrorAction SilentlyContinue) + '\Authentication Packages'
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Authentication Package DLL' -Classification 'MITRE ATT&CK T1547.002' -Path $propPath -Value $dllPath -AccessGained 'System' -Note 'DLLs specified in Authentication Packages are loaded by LSASS at machine boot for custom authentication.' -Reference 'https://attack.mitre.org/techniques/T1547/002/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-LsaSecurityPackages {
        Write-Verbose "$hostname - Getting LSA security packages..."
        foreach ($hive in $systemAndUsersHives) {
            $secPackages = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Security Packages' -ErrorAction SilentlyContinue
            if ($secPackages -and $secPackages.'Security Packages') {
                $packageString = $secPackages.'Security Packages' -replace '"', ''
                $dlls = $packageString -split '\s+' | Where-Object { $_ -ne '' }
                foreach ($dll in $dlls) {
                    $dllPath = if (([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dll))) -eq $false) {
                        "C:\Windows\System32\$dll.dll"
                    }
                    else { 
                        $dll 
                    }
                
                    $propPath = (Convert-Path -Path $secPackages.PSPath -ErrorAction SilentlyContinue) + '\Security Packages'
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Security Package DLL' -Classification 'MITRE ATT&CK T1547.005' -Path $propPath -Value $dllPath -AccessGained 'System' -Note 'DLLs specified in Security Packages are loaded by LSASS at machine boot for security protocols.' -Reference 'https://attack.mitre.org/techniques/T1547/005/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-WinlogonNotificationPackages {
        Write-Verbose "$hostname - Getting Winlogon Notification packages..."
        foreach ($hive in $systemAndUsersHives) {
            $notificationPackages = Get-ItemProperty -Path "$hive\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ErrorAction SilentlyContinue
            if ($notificationPackages) {
                foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $notificationPackages)) {
                    if ($psProperties.Contains($prop.Name)) { continue }
                
                    $propPath = Convert-Path -Path $notificationPackages.PSPath -ErrorAction SilentlyContinue
                    $propPath += '\' + $prop.Name
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Notification Package' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $notificationPackages.($prop.Name) -AccessGained 'System' -Note 'DLLs in Winlogon Notify properties are loaded by the system at boot for logon notifications.' -Reference 'https://attack.mitre.org/techniques/T1547/004/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-DotNetDebugger {
        Write-Verbose "$hostname - Getting .NET Debugger properties..."
        foreach ($hive in $systemAndUsersHives) {
            $dotNetDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\.NETFramework" -Name DbgManagedDebugger -ErrorAction SilentlyContinue
            if ($dotNetDebugger -and $dotNetDebugger.DbgManagedDebugger) {
                $propPath = Convert-Path -Path $dotNetDebugger.PSPath -ErrorAction SilentlyContinue
                $propPath += '\DbgManagedDebugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'DbgManagedDebugger Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $dotNetDebugger.DbgManagedDebugger -AccessGained 'System/User' -Note "Executable in DbgManagedDebugger property runs when a .NET process crashes. Access depends on crashed process context." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }

            $dotNetDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name DbgManagedDebugger -ErrorAction SilentlyContinue
            if ($dotNetDebugger -and $dotNetDebugger.DbgManagedDebugger) {
                $propPath = Convert-Path -Path $dotNetDebugger.PSPath -ErrorAction SilentlyContinue
                $propPath += '\DbgManagedDebugger'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Wow6432Node DbgManagedDebugger Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $dotNetDebugger.DbgManagedDebugger -AccessGained 'System/User' -Note "Executable in Wow6432Node DbgManagedDebugger property runs when a 32-bit .NET process crashes on 64-bit system." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }
    function Get-ErrorHandlerCmd {
        Write-Verbose "$hostname - Checking for ErrorHandler.cmd..."
        $errorHandlerCmd = Get-ChildItem -Path 'C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd' -ErrorAction SilentlyContinue
        if ($errorHandlerCmd) {
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ErrorHandler.cmd Hijacking' -Classification 'Hexacorn Technique N.135' -Path "C:\WINDOWS\Setup\Scripts\" -Value $errorHandlerCmd.FullName -AccessGained 'User' -Note "ErrorHandler.cmd is executed when Windows Setup tools fail. This file should not exist by default." -Reference 'https://www.hexacorn.com/blog/2022/01/16/beyond-good-ol-run-key-part-135/'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-WMIEventsSubscrition {
        Write-Verbose "$hostname - Checking WMI Subscriptions..."
    
        try {
            $cmdEventConsumer = Get-WmiObject -Namespace root\Subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
            if ($cmdEventConsumer) {
                foreach ($cmdEntry in $cmdEventConsumer) {
                    $value = if ($cmdEntry.CommandLineTemplate) {
                        "CommandLineTemplate: $($cmdEntry.CommandLineTemplate)"
                    }
                    elseif ($cmdEntry.ExecutablePath) {
                        "ExecutablePath: $($cmdEntry.ExecutablePath)"
                    }
                    else {
                        "Name: $($cmdEntry.Name)"
                    }
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'WMI Command Line Event Consumer' -Classification 'MITRE ATT&CK T1546.003' -Path $cmdEntry.__PATH -Value $value -AccessGained 'System' -Note "WMI Event subscriptions can execute commands when specific events occur." -Reference 'https://attack.mitre.org/techniques/T1546/003/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }

            $scriptEventConsumer = Get-WmiObject -Namespace root\Subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
            if ($scriptEventConsumer) {
                foreach ($scriptEntry in $scriptEventConsumer) {
                    $value = if ($scriptEntry.ScriptText) {
                        "ScriptText: $($scriptEntry.ScriptText -replace '\s+', ' ')"
                    }
                    elseif ($scriptEntry.ScriptFileName) {
                        "ScriptFileName: $($scriptEntry.ScriptFileName)"
                    }
                    else {
                        "Name: $($scriptEntry.Name)"
                    }
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'WMI Active Script Event Consumer' -Classification 'MITRE ATT&CK T1546.003' -Path $scriptEntry.__PATH -Value $value -AccessGained 'System' -Note "WMI Event subscriptions can execute scripts when specific events occur." -Reference 'https://attack.mitre.org/techniques/T1546/003/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Error accessing WMI subscriptions: $($_.Exception.Message)"
        }
    }

    function Get-WindowsServices {
        Write-Verbose "$hostname - Checking Windows Services..."
        try {
            $services = Get-CimInstance -ClassName win32_service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, PathName, StartMode
            foreach ($service in $services) {
                # Skip if no pathname
                if (-not $service.PathName) { continue }
                
                # Create status string
                $statusString = "$($service.State)/$($service.StartMode)"
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Service' -Classification 'MITRE ATT&CK T1543.003' -Path $service.Name -Value $service.PathName -AccessGained 'System' -Note "Windows services run automatically at boot and can be used for persistence. StartMode: $($service.StartMode)" -Reference 'https://attack.mitre.org/techniques/T1543/003/' -Status $statusString
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Error accessing Windows Services: $($_.Exception.Message)"
        }
    }
    function Get-PowerAutomate {
        Write-Verbose "$hostname - Checking Power Automate presence..."
        $PADFolder = "$env:ProgramData\Microsoft\Power Automate\Logs"
        if (Test-Path $PADFolder -ErrorAction SilentlyContinue) {
            $LastPALog = Get-ChildItem -Path $PADFolder -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

            if ($LastPALog) {
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Power Automate' -Classification 'Uncatalogued Technique N.12' -Path $PADFolder -Value $LastPALog.FullName -AccessGained 'System/User' -Note "Power Automate RPA platform is present and active. While legitimate, it can be abused for malicious automation." -Reference 'https://github.com/mbrg/defcon30/tree/main/No_Code_Malware'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-TSInitialProgram {
        Write-Verbose "$hostname - Getting Terminal Services InitialProgram properties..."
        foreach ($hive in $systemAndUsersHives) {
            # Check Group Policy location
            $InitialProgram = Get-ItemProperty -Path "$hive\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name InitialProgram -ErrorAction SilentlyContinue
            if ($InitialProgram -and $InitialProgram.InitialProgram -and $InitialProgram.InitialProgram.Length -ne 0) {
                $propPath = Convert-Path -Path $InitialProgram.PSPath -ErrorAction SilentlyContinue
                $propPath += '\InitialProgram'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Terminal Services InitialProgram' -Classification 'Uncatalogued Technique N.8' -Path $propPath -Value $InitialProgram.InitialProgram -AccessGained 'System/User' -Note "Executable in InitialProgram property runs when RDP connection is made." -Reference 'https://persistence-info.github.io/Data/tsinitialprogram.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }

            # Check WinStations location
            $InitialProgram = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name InitialProgram -ErrorAction SilentlyContinue
            if ($InitialProgram -and $InitialProgram.InitialProgram -and $InitialProgram.InitialProgram.Length -ne 0) {
                $propPath = Convert-Path -Path $InitialProgram.PSPath -ErrorAction SilentlyContinue
                $propPath += '\InitialProgram'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Terminal Services InitialProgram' -Classification 'Uncatalogued Technique N.8' -Path $propPath -Value $InitialProgram.InitialProgram -AccessGained 'System/User' -Note "Executable in InitialProgram property runs when RDP connection is made to RDP-Tcp WinStation." -Reference 'https://persistence-info.github.io/Data/tsinitialprogram.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-AccessibilityTools {
        Write-Verbose "$hostname - Checking accessibility tools for backdoors..."
        $accessibilityTools = @(
            "$env:windir\System32\sethc.exe",
            "$env:windir\System32\osk.exe", 
            "$env:windir\System32\Narrator.exe",
            "$env:windir\System32\Magnify.exe",
            "$env:windir\System32\DisplaySwitch.exe",
            "$env:windir\System32\Utilman.exe",
            "$env:windir\System32\AtBroker.exe"
        )
    
        # Get reference hashes for comparison
        $referenceHashes = @{}
        $referenceFiles = @(
            "$env:windir\System32\cmd.exe",
            "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe",
            "$env:windir\explorer.exe",
            "$env:windir\System32\notepad.exe",
            "$env:windir\System32\rundll32.exe",
            "$env:windir\System32\mshta.exe",
            "$env:windir\System32\net.exe",
            "$env:windir\System32\regsvr32.exe"
        )
    
        try {
            foreach ($refFile in $referenceFiles) {
                if (Test-Path $refFile -ErrorAction SilentlyContinue) {
                    $hash = (Get-FileHash -LiteralPath $refFile -ErrorAction SilentlyContinue).Hash
                    if ($hash) { $referenceHashes[$refFile] = $hash }
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Could not get reference hashes for accessibility tool comparison"
        }
    
        foreach ($tool in $accessibilityTools) {
            if (Test-Path $tool -ErrorAction SilentlyContinue) {
                try {
                    $toolHash = (Get-FileHash -LiteralPath $tool -ErrorAction SilentlyContinue).Hash
                    $isReplaced = $false
                    $replacedWith = ""
                    $shouldFlag = $false
                
                    # Check if tool has been replaced with common utilities
                    foreach ($refPath in $referenceHashes.Keys) {
                        if ($toolHash -eq $referenceHashes[$refPath]) {
                            $isReplaced = $true
                            $replacedWith = " (replaced with $(Split-Path $refPath -Leaf))"
                            $shouldFlag = $true  # Always flag if replaced
                            break
                        }
                    }
                
                    # Check digital signature
                    $signatureStatus = $null
                    $isMicrosoftSigned = $false
                    $isValidOrExpired = $false
                
                    try {
                        $signature = Get-AuthenticodeSignature -LiteralPath $tool -ErrorAction SilentlyContinue
                        $signatureStatus = $signature.Status
                    
                        # Check if it's Microsoft signed
                        if ($signature.SignerCertificate.Subject -like "*Microsoft*") {
                            $isMicrosoftSigned = $true
                        }
                    
                        # Check if signature is Valid or just expired but otherwise valid
                        if ($signature.Status -eq 'Valid' -or 
                            ($signature.Status -eq 'NotTrusted' -and $signature.SignerCertificate.Subject -like "*Microsoft*")) {
                            $isValidOrExpired = $true
                        }
                    
                    }
                    catch { 
                        $shouldFlag = $true
                        $replacedWith += " (signature check failed)"
                    }
                
                    # Decision logic for flagging
                    if (-not $isReplaced) {
                        # If not replaced, only flag if:
                        # 1. Not Microsoft signed, OR
                        # 2. Invalid signature (not Valid or expired Microsoft cert)
                        if (-not $isMicrosoftSigned -or -not $isValidOrExpired) {
                            $shouldFlag = $true
                            if (-not $isMicrosoftSigned) {
                                $replacedWith += " (not Microsoft signed)"
                            }
                            elseif (-not $isValidOrExpired) {
                                $replacedWith += " (invalid signature)"
                            }
                        }
                    }
                
                    # Only create persistence object if we should flag this entry
                    if ($shouldFlag) {
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Accessibility Tools Backdoor' -Classification 'MITRE ATT&CK T1546.008' -Path $tool -Value "$tool$replacedWith" -AccessGained 'System' -Note "Accessibility tools can be executed from lock screen with SYSTEM privileges. Tool may have been replaced or modified." -Reference 'https://attack.mitre.org/techniques/T1546/008/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                    else {
                        # Log that we're skipping a legitimate Microsoft binary
                        Write-Verbose "$hostname - Skipping legitimate Microsoft accessibility tool: $tool"
                    }
                
                }
                catch {
                    Write-Verbose "$hostname - Error checking accessibility tool: $tool"
                }
            }
        }
    }

    function Get-AMSIProviders {
        Write-Verbose "$hostname - Getting AMSI providers..."
        $legitAMSIGUID = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'
    
        # Check if AMSI Providers key exists
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\" -ErrorAction SilentlyContinue)) {
            Write-Verbose "$hostname - AMSI Providers registry key not found"
            return
        }
    
        # Get all AMSI provider keys
        $amsiProviders = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\" -ErrorAction SilentlyContinue
        if (-not $amsiProviders) {
            Write-Verbose "$hostname - No AMSI provider keys found"
            return
        }
    
        foreach ($key in $amsiProviders) {
            try {
                $keyGUID = $key.PSChildName
                if ($keyGUID -eq $legitAMSIGUID) { 
                    Write-Verbose "$hostname - Skipping legitimate AMSI provider: $keyGUID"
                    continue 
                }
            
                $clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$keyGUID\InprocServer32"
            
                # Check if CLSID key exists before trying to read from it
                if (-not (Test-Path $clsidPath -ErrorAction SilentlyContinue)) {
                    Write-Verbose "$hostname - CLSID path not found: $clsidPath"
                    continue
                }
            
                $dllLocation = Get-ItemProperty -Path $clsidPath -Name '(Default)' -ErrorAction SilentlyContinue
                if ($dllLocation -and $dllLocation.'(Default)') {
                    $path = $dllLocation.'(Default)'
                
                    # Construct full path if needed
                    if (-not ($path -like '*.dll')) { $path = $path + '.dll' }
                    if (-not ([System.IO.Path]::IsPathRooted($path))) {
                        $path = "C:\Windows\System32\$path"
                    }
                
                    # Expand environment variables after path construction
                    $path = [System.Environment]::ExpandEnvironmentVariables($path)
                
                    # Use consistent registry path format
                    $propPath = Convert-Path -Path $clsidPath -ErrorAction SilentlyContinue
                    if ($propPath) {
                        $propPath += "\(Default)"
                    }
                    else {
                        $propPath = "$clsidPath\(Default)"
                    }
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Custom AMSI Provider' -Classification 'Uncatalogued Technique N.9' -Path $propPath -Value $path -AccessGained 'System/User' -Note 'Custom AMSI providers are loaded by .NET processes and can be used for persistence or evasion.' -Reference 'https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
            catch {
                Write-Verbose "$hostname - Error processing AMSI provider $($key.PSChildName): $($_.Exception.Message)"
                continue
            }
        }
    }

    function Get-PowershellProfiles {
        Write-Verbose "$hostname - Getting PowerShell profiles..."
    
        # Windows PowerShell 5.1 system profiles
        $profilePaths = @(
            'C:\Windows\System32\WindowsPowerShell\v1.0\Profile.ps1',
            'C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1'
        )
    
        # PowerShell Core system profiles (if installed)
        $psCorePaths = @(
            'C:\Program Files\PowerShell\7\Profile.ps1',
            'C:\Program Files\PowerShell\7\Microsoft.PowerShell_profile.ps1'
        )
    
        $allSystemPaths = $profilePaths + $psCorePaths
        $foundProfiles = 0
   
        # Check system profiles
        foreach ($profilePath in $allSystemPaths) {
            if (Test-Path $profilePath -ErrorAction SilentlyContinue) {
                $foundProfiles++
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'PowerShell Profile' -Classification 'MITRE ATT&CK T1546.013' -Path (Split-Path $profilePath) -Value $profilePath -AccessGained 'System' -Note "PowerShell profiles are loaded whenever PowerShell starts." -Reference 'https://attack.mitre.org/techniques/T1546/013/'
           
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
   
        # Check user profiles
        $userDirectories = Get-ChildItem -Path 'C:\Users\' -ErrorAction SilentlyContinue
        foreach ($directory in $userDirectories) {
            $userProfilePaths = @(
                "$($directory.FullName)\Documents\WindowsPowerShell\Profile.ps1",
                "$($directory.FullName)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
                "$($directory.FullName)\Documents\PowerShell\Profile.ps1",
                "$($directory.FullName)\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
            )
       
            foreach ($profilePath in $userProfilePaths) {
                if (Test-Path $profilePath -ErrorAction SilentlyContinue) {
                    $foundProfiles++
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'PowerShell Profile' -Classification 'MITRE ATT&CK T1546.013' -Path (Split-Path $profilePath) -Value $profilePath -AccessGained 'User' -Note "PowerShell profiles are loaded whenever PowerShell starts." -Reference 'https://attack.mitre.org/techniques/T1546/013/'
               
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }



    function Get-SilentExitMonitor {
        Write-Verbose "$hostname - Getting Silent Process Exit monitors..."
        $exitMonitors = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" -ErrorAction SilentlyContinue
        foreach ($key in $exitMonitors) {
            $monitorProperty = Get-ItemProperty -Path $key.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue
            if ($monitorProperty -and $monitorProperty.MonitorProcess) {
                $propPath = Convert-Path -Path $key.PSPath -ErrorAction SilentlyContinue
                $propPath += '\MonitorProcess'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Silent Process Exit Monitor' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $monitorProperty.MonitorProcess -AccessGained 'System/User' -Note 'Executables specified in MonitorProcess are run when the associated process is terminated.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-TelemetryController {
        Write-Verbose "$hostname - Getting Telemetry controller..."
        $telemetryProperty = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" -Name Command -ErrorAction SilentlyContinue
        if ($telemetryProperty -and $telemetryProperty.Command) {
            $propPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\Command'
        
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Telemetry Controller Command' -Classification 'Uncatalogued Technique N.10' -Path $propPath -Value $telemetryProperty.Command -AccessGained 'System' -Note "Executable specified in TelemetryController Command is run by CompatTelRunner.exe." -Reference 'https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-RDPWDSStartupPrograms {
        Write-Verbose "$hostname - Getting RDP WDS startup programs..."
        $startupProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" -Name StartupPrograms -ErrorAction SilentlyContinue
        if ($startupProperty -and $startupProperty.StartupPrograms) {
            $executables = $startupProperty.StartupPrograms -split ','
            foreach ($exe in $executables) {
                $exe = $exe.Trim()
                if ($exe -eq 'rdpclip') { continue }
            
                $propPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'RDP WDS Startup Programs' -Classification 'Uncatalogued Technique N.11' -Path $propPath -Value $exe -AccessGained 'System' -Note "Executables in StartupPrograms are run when users log on through remote desktop." -Reference 'https://persistence-info.github.io/Data/rdpwdstartupprograms.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-BitsJobsNotifyCmdLine {
        Write-Verbose "$hostname - Getting BITS Jobs..."
        try {
            $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -eq "Error" } | Where-Object { $_.NotifyCmdLine -and $_.NotifyCmdLine.Length -gt 0 }
            if ($jobs) {
                foreach ($job in $jobs) {
                    $propPath = $job.JobId
                    $access = if ($job.OwnerAccount -eq 'NT AUTHORITY\SYSTEM') { 'System' } else { 'User' }
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'BITS Job NotifyCmdLine' -Classification 'MITRE ATT&CK T1197' -Path $propPath -Value $job.NotifyCmdLine -AccessGained $access -Note "BITS jobs with NotifyCmdLine execute commands when job fails or completes." -Reference 'https://attack.mitre.org/techniques/T1197/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Error accessing BITS jobs: $($_.Exception.Message)"
        }
    }

    function Get-Screensaver {
        Write-Verbose "$hostname - Getting Screensaver programs..."
        foreach ($sid in $systemAndUsersHives) {
            $screenSaverProgram = Get-ItemProperty -Path "$sid\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue
            if ($screenSaverProgram -and $screenSaverProgram."SCRNSAVE.EXE" -and $screenSaverProgram."SCRNSAVE.EXE" -ne "") {
                $propPath = Convert-Path -Path $screenSaverProgram.PSPath -ErrorAction SilentlyContinue
                $propPath += '\SCRNSAVE.EXE'

                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Screensaver Program' -Classification 'MITRE ATT&CK T1546.002' -Path $propPath -Value $screenSaverProgram."SCRNSAVE.EXE" -AccessGained 'User' -Note "Custom screensaver executables run when screensaver activates, providing user-level persistence." -Reference 'https://attack.mitre.org/techniques/T1546/002/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-OfficeTemplates {
        Write-Verbose "$hostname - Checking Office application startup files..."
        $userDirectories = Get-ChildItem -Path 'C:\Users\' -ErrorAction SilentlyContinue
        foreach ($directory in $userDirectories) {
            $searchPaths = @{
                "$($directory.FullName)\AppData\Roaming\Microsoft\Word\STARTUP\"  = "Word"
                "$($directory.FullName)\AppData\Roaming\Microsoft\Excel\XLSTART\" = "Excel"  
                "$($directory.FullName)\AppData\Roaming\Microsoft\AddIns\"        = "Office AddIns"
            }
        
            # Check startup folders
            foreach ($searchPath in $searchPaths.Keys) {
                if (Test-Path $searchPath -ErrorAction SilentlyContinue) {
                    $files = Get-ChildItem -Path $searchPath -ErrorAction SilentlyContinue
                    foreach ($file in $files) {
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Office Application Startup' -Classification 'MITRE ATT&CK T1137.001' -Path $searchPath -Value $file.FullName -AccessGained 'User' -Note "Files in $($searchPaths[$searchPath]) startup folder execute when Office application starts." -Reference 'https://attack.mitre.org/techniques/T1137/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        
            # Check for macro-enabled templates
            $templatesPath = "$($directory.FullName)\AppData\Roaming\Microsoft\Templates\"
            if (Test-Path $templatesPath -ErrorAction SilentlyContinue) {
                $macroTemplates = Get-ChildItem -Path $templatesPath -Filter "*.dotm" -ErrorAction SilentlyContinue
                foreach ($template in $macroTemplates) {
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Office Application Startup' -Classification 'MITRE ATT&CK T1137.001' -Path $templatesPath -Value $template.FullName -AccessGained 'User' -Note "Macro-enabled Word templates execute when documents are opened." -Reference 'https://attack.mitre.org/techniques/T1137/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        
            # Check for Outlook templates
            $outlookPath = "$($directory.FullName)\AppData\Roaming\Microsoft\Outlook\"
            if (Test-Path $outlookPath -ErrorAction SilentlyContinue) {
                $outlookTemplates = Get-ChildItem -Path $outlookPath -Filter "*.OTM" -ErrorAction SilentlyContinue
                foreach ($template in $outlookTemplates) {
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Office Application Startup' -Classification 'MITRE ATT&CK T1137.001' -Path $outlookPath -Value $template.FullName -AccessGained 'User' -Note "Outlook macro templates execute when Outlook starts." -Reference 'https://attack.mitre.org/techniques/T1137/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-ExplorerTools {
        Write-Verbose "$hostname - Getting Explorer Tools..."
        foreach ($hive in $systemAndUsersHives) {
            $explorerTools = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer" -ErrorAction SilentlyContinue
            foreach ($key in $explorerTools) {
                $defaultValue = (Get-ItemProperty -Path Registry::$key -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
                if ($defaultValue) {
                    $propPath = Convert-Path -Path $key.PSPath -ErrorAction SilentlyContinue
                    $propPath += '\(Default)'
                    $currentHive = Convert-Path -Path $hive -ErrorAction SilentlyContinue
                    $access = if (($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20')) { 'System' } else { 'User' }
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Tools Hijacking' -Classification 'Hexacorn Technique N.55' -Path $propPath -Value $defaultValue -AccessGained $access -Note 'Executables in Explorer MyComputer subkeys run when corresponding events trigger.' -Reference 'https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    }

    function Get-ExplorerContextMenu {
        Write-Verbose "$hostname - Checking Explorer Context Menu..."
        $contextMenuPath = "Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}"
        $dllProperty = Get-ItemProperty -Path $contextMenuPath -Name '(Default)' -ErrorAction SilentlyContinue
    
        if ($dllProperty -and $dllProperty.'(Default)') {
            $path = $dllProperty.'(Default)'
            if (([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false) {
                $path = "C:\Windows\System32\$path"
            }
        
            $propPath = 'HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}\(Default)'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Context Menu Hijacking' -Classification 'Uncatalogued Technique N.13' -Path $propPath -Value $path -AccessGained 'User' -Note 'DLL in context menu handler is loaded when user right-clicks in Explorer.' -Reference 'https://ristbs.github.io/2023/02/15/hijack-explorer-context-menu-for-persistence-and-fun.html'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-ServiceControlManagerSecurityDescriptor {
        Write-Verbose "$hostname - Checking Service Control Manager security descriptor..."
        try {
            $currentSDDL = (sc.exe sdshow scmanager 2>$null) -join ''
            $defaultSDDL = 'D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)(A;;CC;;;S-1-15-3-1024-528118966-3876874398-709513571-1907873084-3598227634-3698730060-278077788-3990600205)'
            if ($currentSDDL -notlike $defaultSDDL) {
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Service Control Manager Security Descriptor' -Classification 'Uncatalogued Technique N.14' -Path 'Service Control Manager' -Value $currentSDDL -AccessGained 'System' -Note 'Modified SCM security descriptor can allow non-admin processes to create privileged services.' -Reference 'https://pentestlab.blog/2023/03/20/persistence-service-control-manager/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Error accessing Service Control Manager: $($_.Exception.Message)"
        }
    }

    function Get-MicrosoftOfficeAIHijacking {
        Write-Verbose "$hostname - Checking for Office AI.exe hijacking..."
        $officePaths = @(
            [System.Environment]::ExpandEnvironmentVariables('%ProgramFiles%\Microsoft Office\root\'),
            [System.Environment]::ExpandEnvironmentVariables('%ProgramFiles(x86)%\Microsoft Office\root\')
        )
    
        foreach ($basePath in $officePaths) {
            if (Test-Path $basePath -ErrorAction SilentlyContinue) {
                $officeDirs = Get-ChildItem $basePath -ErrorAction SilentlyContinue
                foreach ($officeDir in $officeDirs) {
                    $aiPath = "$($officeDir.FullName)\ai.exe"
                    if (Test-Path $aiPath -ErrorAction SilentlyContinue) {
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Microsoft Office AI.exe Hijacking' -Classification 'Uncatalogued Technique N.15' -Path $officeDir.FullName -Value $aiPath -AccessGained 'User' -Note 'AI.exe in Office directories is loaded by Office applications for persistence.' -Reference 'https://twitter.com/laughing_mantis/status/1645268114966470662'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }

    function Get-DotNetStartupHooks {
        Write-Verbose "$hostname - Getting .NET Startup Hooks..."
    
        # Check user environment variables
        foreach ($hive in $systemAndUsersHives) {
            $envProperty = Get-ItemProperty -Path "$hive\Environment" -Name DOTNET_STARTUP_HOOKS -ErrorAction SilentlyContinue
            if ($envProperty -and $envProperty.DOTNET_STARTUP_HOOKS) {
                $hooks = $envProperty.DOTNET_STARTUP_HOOKS -split ';' | Where-Object { $_ -ne '' }
                foreach ($hook in $hooks) {
                    $propPath = Convert-Path -Path $hive -ErrorAction SilentlyContinue
                    $propPath += "\Environment\DOTNET_STARTUP_HOOKS"
                
                    $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique '.NET Startup Hooks DLL' -Classification 'MITRE ATT&CK T1574.002' -Path $propPath -Value $hook -AccessGained 'User/System' -Note '.NET DLLs in DOTNET_STARTUP_HOOKS are loaded into .NET processes at runtime.' -Reference 'https://persistence-info.github.io/Data/dotnetstartuphooks.html'
                
                    if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                        $script:globalPersistenceObjectArray.Add($PersistenceObject)
                    }
                }
            }
        }
    
        # Check system environment variables
        $systemEnvProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name DOTNET_STARTUP_HOOKS -ErrorAction SilentlyContinue
        if ($systemEnvProperty -and $systemEnvProperty.DOTNET_STARTUP_HOOKS) {
            $hooks = $systemEnvProperty.DOTNET_STARTUP_HOOKS -split ';' | Where-Object { $_ -ne '' }
            foreach ($hook in $hooks) {
                $propPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\DOTNET_STARTUP_HOOKS"
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique '.NET Startup Hooks DLL' -Classification 'MITRE ATT&CK T1574.002' -Path $propPath -Value $hook -AccessGained 'System' -Note '.NET DLLs in system DOTNET_STARTUP_HOOKS are loaded into all .NET processes.' -Reference 'https://persistence-info.github.io/Data/dotnetstartuphooks.html'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Parse-NetUser {
        $outputStart = 0
        foreach ($item in $input) {
            if ($item -match '----') {
                $outputStart = 1
                continue
            }
            elseif ($outputStart -eq 0) {
                continue
            }
            if ($item -eq "") {
                continue
            }
            if ($item -match '.*\.$') {
                continue
            }

            $contentArray = @()
            foreach ($line in $item -split '\s{2,}') {
                if ($line -ne '') {
                    $contentArray += $line
                }
            }
 
            foreach ($content in $contentArray) {
                $content = $content -replace '"', ''
                if ($content.Length -ne 0) {
                    New-Object -TypeName PSObject -Property @{"Name" = $content.Trim() }
                }
            }
        }
    }


    function Get-SubornerAttack {
        Write-Verbose "$hostname - Checking for Suborner Attack (hidden users)..."
        try {
            $netUsers = net.exe users 2>$null | Parse-NetUser
            $poshUsers = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name
        
            if ($netUsers -and $poshUsers) {
                $diffUsers = Compare-Object -ReferenceObject $poshUsers -DifferenceObject $netUsers -Property Name -ErrorAction SilentlyContinue
                foreach ($user in $diffUsers) {
                    if ($user.SideIndicator -eq '<=') {
                        # User exists in PowerShell but not in net user
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Suborner Attack' -Classification 'Uncatalogued Technique N.16' -Path 'Hidden User Account' -Value $user.Name -AccessGained 'User/System' -Note 'Hidden user account not visible via net user command but detectable with Get-LocalUser. Often paired with RID hijacking for stealthy persistence.' -Reference 'https://r4wsec.com/notes/the_suborner_attack/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "$hostname - Error checking for hidden users: $($_.Exception.Message)"
        }
    }

    function Get-DSRMBackdoor {
        Write-Verbose "$hostname - Checking for DSRM backdoor..."
        $dsrmProperty = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue
        if ($dsrmProperty -and $dsrmProperty.DsrmAdminLogonBehavior -EQ 2) {
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'DSRM Backdoor' -Classification 'MITRE ATT&CK T1003.003' -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior' -Value $dsrmProperty.DsrmAdminLogonBehavior -AccessGained 'System' -Note "DSRM backdoor allows using DSRM password for normal logon when DsrmAdminLogonBehavior is set to 2." -Reference 'https://adsecurity.org/?p=1785'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-BootVerificationProgram {
        Write-Verbose "$hostname - Checking Boot Verification Program..."
        $bootProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BootVerificationProgram" -Name ImagePath -ErrorAction SilentlyContinue
        if ($bootProperty -and $bootProperty.ImagePath) {
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Boot Verification Program Hijacking' -Classification 'Uncatalogued Technique N.19' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BootVerificationProgram\ImagePath' -Value $bootProperty.ImagePath -AccessGained 'System' -Note "Boot Verification Program runs at boot time in place of legitimate Bootvrfy.exe." -Reference 'https://persistence-info.github.io/Data/bootverificationprogram.html'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-AppInitDLLs {
        Write-Verbose "$hostname - Getting AppInit DLLs..."
    
        # Check native AppInit_DLLs
        $appInitProperty = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
        if ($appInitProperty -and $appInitProperty.AppInit_DLLs) {
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AppInit DLL Injection' -Classification 'MITRE ATT&CK T1546.010' -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs' -Value $appInitProperty.AppInit_DLLs -AccessGained 'System/User' -Note "AppInit DLLs are loaded by user32.dll in every process that loads the Win32 subsystem." -Reference 'https://attack.mitre.org/techniques/T1546/010/'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }

        # Check Wow6432Node AppInit_DLLs  
        $appInitProperty = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
        if ($appInitProperty -and $appInitProperty.AppInit_DLLs) {
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AppInit DLL Injection (WOW64)' -Classification 'MITRE ATT&CK T1546.010' -Path 'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs' -Value $appInitProperty.AppInit_DLLs -AccessGained 'System/User' -Note "AppInit DLLs in WOW64 node are loaded by 32-bit processes on 64-bit systems." -Reference 'https://attack.mitre.org/techniques/T1546/010/'
        
            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                $script:globalPersistenceObjectArray.Add($PersistenceObject)
            }
        }
    }

    function Get-BootExecute {
        Write-Verbose "$hostname - Getting BootExecute executables..."
    
        # Process BootExecute
        $bootExecProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name 'BootExecute' -ErrorAction SilentlyContinue
        if ($bootExecProperty -and $bootExecProperty.BootExecute) {
            $entries = if ($bootExecProperty.BootExecute -is [string]) {
                @($bootExecProperty.BootExecute)
            }
            else {
                $bootExecProperty.BootExecute
            }
        
            foreach ($entry in $entries) {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            
                # Skip the standard legitimate entry
                if ($entry -eq "autocheck autochk *") { continue }
            
                # Extract the executable from the command line
                $executable = ($entry -split '\s+')[0]
            
                # Skip if it's just "autocheck" or "autochk" alone (legitimate components)
                if ($executable -eq "autocheck" -or $executable -eq "autochk") { continue }
            
                # Build full path if not already rooted
                $exePath = if (-not [System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($executable))) {
                    "C:\Windows\System32\$executable"
                }
                else { 
                    $executable 
                }
            
                $propPath = (Convert-Path -Path $bootExecProperty.PSPath -ErrorAction SilentlyContinue) + '\BootExecute'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'BootExecute Binary' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $entry -ExecutePath $exePath -AccessGained 'System' -Note 'BootExecute programs run before any other process during system startup.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }

        # Process BootExecuteNoPnpSync
        $bootExecNoPnpProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name 'BootExecuteNoPnpSync' -ErrorAction SilentlyContinue
        if ($bootExecNoPnpProperty -and $bootExecNoPnpProperty.BootExecuteNoPnpSync) {
            $entries = if ($bootExecNoPnpProperty.BootExecuteNoPnpSync -is [string]) {
                @($bootExecNoPnpProperty.BootExecuteNoPnpSync)
            }
            else {
                $bootExecNoPnpProperty.BootExecuteNoPnpSync
            }
        
            foreach ($entry in $entries) {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            
                # Extract the executable from the command line  
                $executable = ($entry -split '\s+')[0]
            
                # Build full path if not already rooted
                $exePath = if (-not [System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($executable))) {
                    "C:\Windows\System32\$executable"
                }
                else { 
                    $executable 
                }
            
                $propPath = (Convert-Path -Path $bootExecNoPnpProperty.PSPath -ErrorAction SilentlyContinue) + '\BootExecuteNoPnpSync'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'BootExecuteNoPnpSync Binary' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $entry -ExecutePath $exePath -AccessGained 'System' -Note 'BootExecuteNoPnpSync programs run before other processes during startup without PnP synchronization.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-NetshHelperDLL {
        Write-Verbose "$hostname - Getting Netsh Helper DLLs..."
        $netshKey = Get-Item 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
        if ($netshKey) {
            $props = $netshKey | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
            foreach ($prop in $props) {
                if ($prop) {
                    $dllProperty = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -Name $prop -ErrorAction SilentlyContinue
                    if ($dllProperty -and $dllProperty.$prop) {
                        $dll = $dllProperty.$prop
                        $dllPath = if ($dll -like "*.dll") { 
                            if ([System.IO.Path]::IsPathRooted($dll)) { $dll } else { "C:\Windows\System32\$dll" }
                        }
                        else { 
                            "C:\Windows\System32\$dll.dll" 
                        }
                    
                        $propPath = "HKLM:\SOFTWARE\Microsoft\NetSh\$prop"
                    
                        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Netsh Helper DLL' -Classification 'MITRE ATT&CK T1546.007' -Path $propPath -Value $dllPath -AccessGained 'System/User' -Note 'Netsh Helper DLLs are loaded whenever netsh.exe runs, which may occur during system operations.' -Reference 'https://attack.mitre.org/techniques/T1546/007/'
                    
                        if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                            $script:globalPersistenceObjectArray.Add($PersistenceObject)
                        }
                    }
                }
            }
        }
    }

    function Get-SetupExecute {
        Write-Verbose "$hostname - Getting SetupExecute executables..."
    
        # Process SetupExecute
        $setupExecProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name 'SetupExecute' -ErrorAction SilentlyContinue
        if ($setupExecProperty -and $setupExecProperty.SetupExecute) {
            $exes = $setupExecProperty.SetupExecute -split '\s+' | Where-Object { $_ -ne '' }
            foreach ($exe in $exes) {
                $exePath = if (([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($exe))) -eq $false) {
                    "C:\Windows\System32\$exe"
                }
                else { $exe }
            
                $propPath = (Convert-Path -Path $setupExecProperty.PSPath -ErrorAction SilentlyContinue) + '\SetupExecute'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'SetupExecute Binary' -Classification 'Uncatalogued Technique N.20' -Path $propPath -Value $exePath -AccessGained 'System' -Note 'SetupExecute programs run during system startup before other processes.' -Reference 'https://github.com/rad9800/BootExecuteEDR'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }

        # Process SetupExecuteNoPnpSync
        $setupExecNoPnpProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name 'SetupExecuteNoPnpSync' -ErrorAction SilentlyContinue
        if ($setupExecNoPnpProperty -and $setupExecNoPnpProperty.SetupExecuteNoPnpSync) {
            $exes = $setupExecNoPnpProperty.SetupExecuteNoPnpSync -split '\s+' | Where-Object { $_ -ne '' }
            foreach ($exe in $exes) {
                $exePath = if (([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($exe))) -eq $false) {
                    "C:\Windows\System32\$exe"
                }
                else { $exe }
            
                $propPath = (Convert-Path -Path $setupExecNoPnpProperty.PSPath -ErrorAction SilentlyContinue) + '\SetupExecuteNoPnpSync'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'SetupExecuteNoPnpSync Binary' -Classification 'Uncatalogued Technique N.20' -Path $propPath -Value $exePath -AccessGained 'System' -Note 'SetupExecuteNoPnpSync programs run during startup without PnP synchronization.' -Reference 'https://github.com/rad9800/BootExecuteEDR'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    function Get-PlatformExecute {
        Write-Verbose "$hostname - Getting PlatformExecute executables..."
        $platformExecProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name 'PlatformExecute' -ErrorAction SilentlyContinue
        if ($platformExecProperty -and $platformExecProperty.PlatformExecute) {
            $exes = $platformExecProperty.PlatformExecute -split '\s+' | Where-Object { $_ -ne '' }
            foreach ($exe in $exes) {
                $exePath = if (([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($exe))) -eq $false) {
                    "C:\Windows\System32\$exe"
                }
                else { $exe }
            
                $propPath = (Convert-Path -Path $platformExecProperty.PSPath -ErrorAction SilentlyContinue) + '\PlatformExecute'
            
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'PlatformExecute Binary' -Classification 'Uncatalogued Technique N.21' -Path $propPath -Value $exePath -AccessGained 'System' -Note 'PlatformExecute programs run during platform-specific startup operations.' -Reference 'https://github.com/rad9800/BootExecuteEDR'
            
                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                }
            }
        }
    }

    
    function Get-ScheduledTasks {
        Write-Verbose "$hostname - Getting scheduled tasks..."

        try {
            # Primary method: Use Get-ScheduledTask
            $tasks = $null
            try {
                $tasks = Get-ScheduledTask -ErrorAction Stop
                Write-Verbose "$hostname - Retrieved $($tasks.Count) scheduled tasks"
            }
            catch {
                Write-Verbose "$hostname - Get-ScheduledTask failed: $($_.Exception.Message)"
                Write-Verbose "$hostname - Attempting schtasks.exe fallback"
            
                # Fallback method: Parse schtasks output
                try {
                    $schtasksOutput = schtasks.exe /query /fo csv /v 2>$null
                    if ($schtasksOutput -and $schtasksOutput.Count -gt 1) {
                        $csvData = $schtasksOutput | ConvertFrom-Csv -ErrorAction Stop
                        Write-Verbose "$hostname - Parsed $($csvData.Count) tasks from schtasks.exe"
                    
                        foreach ($row in $csvData) {
                            if ($row.'Task To Run' -and $row.'Task To Run' -ne 'N/A' -and $row.'Task To Run'.Trim() -ne '') {
                                $taskPath = if ($row.TaskName) { $row.TaskName } else { "Unknown" }
                                $executable = $row.'Task To Run'
                                $status = if ($row.Status) { $row.Status } else { "Unknown" }
                            
                                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Scheduled Task' -Classification 'MITRE ATT&CK T1053.005' -Path $taskPath -Value $executable -AccessGained 'User/System' -Note "Scheduled tasks execute actions and run files when triggered." -Reference 'https://attack.mitre.org/techniques/T1053/005/' -Status $status
                            
                                if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                    $script:globalPersistenceObjectArray.Add($PersistenceObject)
                                }
                            }
                        }
                        Write-Verbose "$hostname - Completed fallback task processing"
                        return
                    }
                    else {
                        Write-Verbose "$hostname - schtasks.exe returned no usable output"
                    }
                }
                catch {
                    Write-Verbose "$hostname - schtasks.exe fallback also failed: $($_.Exception.Message)"
                }
            }

            if (-not $tasks -or $tasks.Count -eq 0) {
                Write-Verbose "$hostname - No scheduled tasks retrieved from any method"
                return
            }
        
            Write-Verbose "$hostname - Processing $($tasks.Count) scheduled tasks"
            $processedCount = 0
            $errorCount = 0

            foreach ($task in $tasks) {
                try {
                    # Skip tasks with no actions
                    if (-not $task.Actions -or $task.Actions.Count -eq 0) { 
                        continue 
                    }

                    # Safely get task info with error handling
                    $taskInfo = $null
                    try {
                        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "$hostname - Could not retrieve task info for $($task.TaskName): $($_.Exception.Message)"
                    }

                    # Process each action in the task
                    foreach ($action in $task.Actions) {
                        if (-not $action.Execute) { continue }
                    
                        try {
                            $executable = [Environment]::ExpandEnvironmentVariables($action.Execute)
                            $arguments = if ($action.Arguments) { [Environment]::ExpandEnvironmentVariables($action.Arguments) } else { "" }
                            $fullCommand = if ($arguments) { "$executable $arguments" } else { $executable }

                            # Determine access level
                            $access = switch ($task.Principal.UserId) {
                                { $_ -in @('SYSTEM', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') } { 'System' }
                                default { 
                                    if ($task.Principal.RunLevel -eq 'Highest') { 'User/Admin' } else { 'User' }
                                }
                            }

                            $taskPath = $task.TaskPath + $task.TaskName

                            # Safely get task state with error handling
                            $statusString = "Unknown"
                            try {
                                $statusString = $task.State.ToString()
                                if ($taskInfo -and $taskInfo.LastTaskResult -ne $null) {
                                    $statusString += "/$($taskInfo.LastTaskResult)"
                                }
                                if ($task.State -eq 'Disabled') { 
                                    $taskPath += " [DISABLED]" 
                                    $statusString = "Disabled"
                                }
                            }
                            catch {
                                Write-Verbose "$hostname - Could not determine state for task $($task.TaskName), using 'Unknown'"
                            }

                            # Build note with author information
                            $note = "Scheduled tasks execute actions and run files when triggered."
                            try {
                                if ($task.Author -and $task.Author -ne 'Microsoft Corporation' -and $task.Author.Trim() -ne '') {
                                    $note += " Author: $($task.Author)."
                                }
                            }
                            catch {
                                # Ignore author retrieval errors
                            }

                            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Scheduled Task' -Classification 'MITRE ATT&CK T1053.005' -Path $taskPath -Value $fullCommand -AccessGained $access -Note $note -Reference 'https://attack.mitre.org/techniques/T1053/005/' -Status $statusString

                            if ((Test-ShouldIncludeEntry $PersistenceObject $Mode) -and (-not (Test-ExcludeEntry $PersistenceObject))) {
                                $script:globalPersistenceObjectArray.Add($PersistenceObject)
                                $processedCount++
                            }
                        }
                        catch {
                            Write-Verbose "$hostname - Error processing action for task $($task.TaskName): $($_.Exception.Message)"
                            $errorCount++
                            continue
                        }
                    }
                }
                catch {
                    Write-Verbose "$hostname - Error processing task $($task.TaskName): $($_.Exception.Message)"
                    $errorCount++
                    continue
                }
            }
        
            Write-Verbose "$hostname - Completed scheduled task processing: $processedCount items processed"
            if ($errorCount -gt 0) {
                Write-Verbose "$hostname - Encountered $errorCount errors during task processing"
            }
        }
        catch {
            Write-Verbose "$hostname - Critical error in scheduled task enumeration: $($_.Exception.Message)"
        }
    }


    # Enhanced error handling wrapper
    try {
        # Main execution logic
        Write-Verbose "$hostname - Starting execution..."
        if ($Technique -eq 'All') {
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Registry Run Keys..." -PercentComplete 2 }
            Get-RunKeys
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Image File Execution Options..." -PercentComplete 4 }
            Get-ImageFileExecutionOptions
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Windows Services..." -PercentComplete 6 }
            Get-WindowsServices
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Scheduled Tasks..." -PercentComplete 8 }
            Get-ScheduledTasks
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting NLDP DLL Override..." -PercentComplete 10 }
            Get-NLDPDllOverridePath
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AeDebug..." -PercentComplete 12 }
            Get-AeDebug
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting WerFault Hangs..." -PercentComplete 14 }
            Get-WerFaultHangs
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Command AutoRun..." -PercentComplete 16 }
            Get-CmdAutoRun
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Explorer Load..." -PercentComplete 18 }
            Get-ExplorerLoad
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon Userinit..." -PercentComplete 20 }
            Get-WinlogonUserinit
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon Shell..." -PercentComplete 22 }
            Get-WinlogonShell
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Terminal Profile..." -PercentComplete 24 }
            Get-TerminalProfileStartOnUserLogin
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AppCert DLLs..." -PercentComplete 26 }
            Get-AppCertDlls
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Service DLLs..." -PercentComplete 28 }
            Get-ServiceDlls
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting GP Extension DLLs..." -PercentComplete 30 }
            Get-GPExtensionDlls
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon MPNotify..." -PercentComplete 32 }
            Get-WinlogonMPNotify
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting CHM Helper DLL..." -PercentComplete 34 }
            Get-CHMHelperDll
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting HHCtrl Hijacking..." -PercentComplete 36 }
            Get-HHCtrlHijacking
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Startup Programs..." -PercentComplete 38 }
            Get-StartupPrograms
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting User Init Script..." -PercentComplete 40 }
            Get-UserInitMprScript
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Autodial DLL..." -PercentComplete 42 }
            Get-AutodialDLL
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting LSA Extensions..." -PercentComplete 44 }
            Get-LsaExtensions
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Server Plugin DLL..." -PercentComplete 46 }
            Get-ServerLevelPluginDll
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Password Filter..." -PercentComplete 48 }
            Get-LsaPasswordFilter
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Auth Packages..." -PercentComplete 50 }
            Get-LsaAuthenticationPackages
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Security Packages..." -PercentComplete 52 }
            Get-LsaSecurityPackages
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Notification Packages..." -PercentComplete 54 }
            Get-WinlogonNotificationPackages
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Explorer Tools..." -PercentComplete 56 }
            Get-ExplorerTools
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting .NET Debugger..." -PercentComplete 58 }
            Get-DotNetDebugger
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Error Handler..." -PercentComplete 60 }
            Get-ErrorHandlerCmd
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting WMI Events..." -PercentComplete 62 }
            Get-WMIEventsSubscrition
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting TS Initial Program..." -PercentComplete 64 }
            Get-TSInitialProgram
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Accessibility Tools..." -PercentComplete 66 }
            Get-AccessibilityTools
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AMSI Providers..." -PercentComplete 68 }
            Get-AMSIProviders
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting PowerShell Profiles..." -PercentComplete 70 }
            Get-PowershellProfiles
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Silent Exit Monitor..." -PercentComplete 72 }
            Get-SilentExitMonitor
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Telemetry Controller..." -PercentComplete 74 }
            Get-TelemetryController
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting RDP WDS Programs..." -PercentComplete 76 }
            Get-RDPWDSStartupPrograms
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting BITS Jobs..." -PercentComplete 78 }
            Get-BitsJobsNotifyCmdLine
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Screensaver..." -PercentComplete 80 }
            Get-Screensaver
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Power Automate..." -PercentComplete 82 }
            Get-PowerAutomate
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Office Templates..." -PercentComplete 84 }
            Get-OfficeTemplates
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Context Menu..." -PercentComplete 86 }
            Get-ExplorerContextMenu
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting SCM Security..." -PercentComplete 88 }
            Get-ServiceControlManagerSecurityDescriptor
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Office AI Hijacking..." -PercentComplete 90 }
            Get-MicrosoftOfficeAIHijacking
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting .NET Startup Hooks..." -PercentComplete 92 }
            Get-DotNetStartupHooks
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Suborner Attack..." -PercentComplete 94 }
            Get-SubornerAttack
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting DSRM Backdoor..." -PercentComplete 96 }
            Get-DSRMBackdoor
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Boot Verification..." -PercentComplete 97 }
            Get-BootVerificationProgram
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AppInit DLLs..." -PercentComplete 98 }
            Get-AppInitDLLs
            if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Boot Execute..." -PercentComplete 99 }
            Get-BootExecute
            Get-NetshHelperDLL
            Get-SetupExecute
            Get-PlatformExecute
            Get-AppPaths
        }
        else {
            switch ($Technique) {
                'RegistryRunKeys' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Registry Run Keys..." -PercentComplete 50 }
                    Get-RunKeys
                    break 
                }
                'ImageFileExecutionOptions' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Image File Execution Options..." -PercentComplete 50 }
                    Get-ImageFileExecutionOptions
                    break 
                }
                'ScheduledTasks' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Scheduled Tasks..." -PercentComplete 50 }
                    Get-ScheduledTasks
                    break 
                }
                'Services' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Windows Services..." -PercentComplete 50 }
                    Get-WindowsServices
                    break 
                }
                'NLDPDllOverridePath' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting NLDP DLL Override..." -PercentComplete 50 }
                    Get-NLDPDllOverridePath
                    break 
                }
                'AeDebug' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AeDebug..." -PercentComplete 50 }
                    Get-AeDebug
                    break 
                }
                'WerFaultHangs' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting WerFault Hangs..." -PercentComplete 50 }
                    Get-WerFaultHangs
                    break 
                }
                'CmdAutoRun' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Command AutoRun..." -PercentComplete 50 }
                    Get-CmdAutoRun
                    break 
                }
                'ExplorerLoad' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Explorer Load..." -PercentComplete 50 }
                    Get-ExplorerLoad
                    break 
                }
                'WinlogonUserinit' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon Userinit..." -PercentComplete 50 }
                    Get-WinlogonUserinit
                    break 
                }
                'WinlogonShell' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon Shell..." -PercentComplete 50 }
                    Get-WinlogonShell
                    break 
                }
                'TerminalProfileStartOnUserLogin' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Terminal Profile..." -PercentComplete 50 }
                    Get-TerminalProfileStartOnUserLogin
                    break 
                }
                'AppCertDlls' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AppCert DLLs..." -PercentComplete 50 }
                    Get-AppCertDlls
                    break 
                }
                'ServiceDlls' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Service DLLs..." -PercentComplete 50 }
                    Get-ServiceDlls
                    break 
                }
                'GPExtensionDlls' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting GP Extension DLLs..." -PercentComplete 50 }
                    Get-GPExtensionDlls
                    break 
                }
                'WinlogonMPNotify' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Winlogon MPNotify..." -PercentComplete 50 }
                    Get-WinlogonMPNotify
                    break 
                }
                'CHMHelperDll' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting CHM Helper DLL..." -PercentComplete 50 }
                    Get-CHMHelperDll
                    break 
                }
                'HHCtrlHijacking' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting HHCtrl Hijacking..." -PercentComplete 50 }
                    Get-HHCtrlHijacking
                    break 
                }
                'StartupPrograms' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Startup Programs..." -PercentComplete 50 }
                    Get-StartupPrograms
                    break 
                }
                'UserInitMprScript' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting User Init Script..." -PercentComplete 50 }
                    Get-UserInitMprScript
                    break 
                }
                'AutodialDLL' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Autodial DLL..." -PercentComplete 50 }
                    Get-AutodialDLL
                    break 
                }
                'LsaExtensions' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting LSA Extensions..." -PercentComplete 50 }
                    Get-LsaExtensions
                    break 
                }
                'ServerLevelPluginDll' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Server Plugin DLL..." -PercentComplete 50 }
                    Get-ServerLevelPluginDll
                    break 
                }
                'LsaPasswordFilter' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Password Filter..." -PercentComplete 50 }
                    Get-LsaPasswordFilter
                    break 
                }
                'LsaAuthenticationPackages' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Auth Packages..." -PercentComplete 50 }
                    Get-LsaAuthenticationPackages
                    break 
                }
                'LsaSecurityPackages' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Security Packages..." -PercentComplete 50 }
                    Get-LsaSecurityPackages
                    break 
                }
                'WinlogonNotificationPackages' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Notification Packages..." -PercentComplete 50 }
                    Get-WinlogonNotificationPackages
                    break 
                }
                'ExplorerTools' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Explorer Tools..." -PercentComplete 50 }
                    Get-ExplorerTools
                    break 
                }
                'DotNetDebugger' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting .NET Debugger..." -PercentComplete 50 }
                    Get-DotNetDebugger
                    break 
                }
                'ErrorHandlerCmd' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Error Handler..." -PercentComplete 50 }
                    Get-ErrorHandlerCmd
                    break 
                }
                'WMIEventsSubscrition' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting WMI Events..." -PercentComplete 50 }
                    Get-WMIEventsSubscrition
                    break 
                }
                'AppPaths' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting App Paths..." -PercentComplete 50 }
                    Get-AppPaths
                    break 
                }
                'TerminalServicesInitialProgram' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting TS Initial Program..." -PercentComplete 50 }
                    Get-TSInitialProgram
                    break 
                }
                'AccessibilityTools' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Accessibility Tools..." -PercentComplete 50 }
                    Get-AccessibilityTools
                    break 
                }
                'AMSIProviders' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AMSI Providers..." -PercentComplete 50 }
                    Get-AMSIProviders
                    break 
                }
                'PowershellProfiles' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting PowerShell Profiles..." -PercentComplete 50 }
                    Get-PowershellProfiles
                    break 
                }
                'SilentExitMonitor' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Silent Exit Monitor..." -PercentComplete 50 }
                    Get-SilentExitMonitor
                    break 
                }
                'TelemetryController' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Telemetry Controller..." -PercentComplete 50 }
                    Get-TelemetryController
                    break 
                }
                'RDPWDSStartupPrograms' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting RDP WDS Programs..." -PercentComplete 50 }
                    Get-RDPWDSStartupPrograms
                    break 
                }
                'BitsJobsNotify' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting BITS Jobs..." -PercentComplete 50 }
                    Get-BitsJobsNotifyCmdLine
                    break 
                }
                'Screensaver' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Screensaver..." -PercentComplete 50 }
                    Get-Screensaver
                    break 
                }
                'PowerAutomate' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Power Automate..." -PercentComplete 50 }
                    Get-PowerAutomate
                    break 
                }
                'OfficeAddinsAndTemplates' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Office Templates..." -PercentComplete 50 }
                    Get-OfficeTemplates
                    break 
                }
                'ExplorerContextMenu' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Context Menu..." -PercentComplete 50 }
                    Get-ExplorerContextMenu
                    break 
                }
                'ServiceControlManagerSD' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting SCM Security..." -PercentComplete 50 }
                    Get-ServiceControlManagerSecurityDescriptor
                    break 
                }
                'OfficeAiHijacking' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Office AI Hijacking..." -PercentComplete 50 }
                    Get-MicrosoftOfficeAIHijacking
                    break 
                }
                'DotNetStartupHooks' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting .NET Startup Hooks..." -PercentComplete 50 }
                    Get-DotNetStartupHooks
                    break 
                }
                'SubornerAttack' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Suborner Attack..." -PercentComplete 50 }
                    Get-SubornerAttack
                    break 
                }
                'DSRMBackdoor' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting DSRM Backdoor..." -PercentComplete 50 }
                    Get-DSRMBackdoor
                    break 
                }
                'BootVerificationProgram' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Boot Verification..." -PercentComplete 50 }
                    Get-BootVerificationProgram
                    break 
                }
                'AppInitDLLs' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting AppInit DLLs..." -PercentComplete 50 }
                    Get-AppInitDLLs
                    break 
                }
                'BootExecute' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Boot Execute..." -PercentComplete 50 }
                    Get-BootExecute
                    break 
                }
                'NetshHelperDLL' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Netsh Helper DLL..." -PercentComplete 50 }
                    Get-NetshHelperDLL
                    break 
                }
                'SetupExecute' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Setup Execute..." -PercentComplete 50 }
                    Get-SetupExecute
                    break 
                }
                'PlatformExecute' { 
                    if (-not $Quiet) { Write-Progress -Activity "Hunt-Persistence" -Status "Getting Platform Execute..." -PercentComplete 50 }
                    Get-PlatformExecute
                    break 
                }
            }
        }

        # Cleanup
        Dismount-TemporaryHives
  
        $script:globalPersistenceObjectArray = @($script:globalPersistenceObjectArray)
    
        # Handle CSV export
        if ($OutputCSV) {
            try {
                if ($null -eq $script:globalPersistenceObjectArray -or $script:globalPersistenceObjectArray.Count -eq 0) {
                    # Create empty CSV with headers
                    $headers = @("Hostname", "Technique", "Classification", "Path", "Execute Path", "Value", "SHA256", "Rights", "Note", "Reference", "Signature", "IsBuiltinBinary", "IsLolbin", "Flag", "Status", "LnkTargetPath", "LnkTargetHash")
                    $headerLine = '"' + ($headers -join '","') + '"'
                    $headerLine | Out-File -FilePath $OutputCSV -Encoding UTF8 -ErrorAction Stop

                    if (-not $Quiet) {
                        Write-Host "Empty results exported to: $OutputCSV" -ForegroundColor Yellow
                    }
                }
                else {
                    # Helper function to sanitize individual fields
                    function Sanitize-CSVField {
                        param([string]$Value)
        
                        if ([string]::IsNullOrEmpty($Value)) { return "" }
        
                        # Convert to string and handle null/empty
                        $sanitized = $Value.ToString().Trim()
        
                        # Remove control characters and non-printable chars
                        $sanitized = $sanitized -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', ''
        
                        # Excel formula injection protection - escape dangerous starting characters
                        if ($sanitized -match '^[=@+\-]') {
                            $sanitized = "'" + $sanitized
                        }
        
                        # Replace line breaks with spaces
                        $sanitized = $sanitized -replace '[\r\n]+', ' ' -replace '\s+', ' '
        
                        # Limit length for Excel (32,767 character limit per cell)
                        if ($sanitized.Length -gt 32767) {
                            $sanitized = $sanitized.Substring(0, 32764) + "..."
                        }
        
                        # Escape quotes for CSV
                        $sanitized = $sanitized -replace '"', '""'
        
                        return $sanitized
                    }

                    # Export using Export-Csv with proper handling
                    $csvData = foreach ($obj in $script:globalPersistenceObjectArray) {
                        [PSCustomObject]@{
                            'Hostname'        = if ($obj.Hostname) { Sanitize-CSVField $obj.Hostname } else { "" }
                            'Technique'       = if ($obj.Technique) { Sanitize-CSVField $obj.Technique } else { "" }
                            'Classification'  = if ($obj.Classification) { Sanitize-CSVField $obj.Classification } else { "" }
                            'Path'            = if ($obj.Path) { Sanitize-CSVField $obj.Path } else { "" }
                            'Execute Path'    = if ($obj.'Execute Path') { Sanitize-CSVField $obj.'Execute Path' } else { "" }
                            'Value'           = if ($obj.Value) { Sanitize-CSVField $obj.Value } else { "" }
                            'SHA256'          = if ($obj.SHA256) { Sanitize-CSVField $obj.SHA256 } else { "" }
                            'Rights'          = if ($obj.Rights) { Sanitize-CSVField $obj.Rights } else { "" }
                            'Note'            = if ($obj.Note) { Sanitize-CSVField $obj.Note } else { "" }
                            'Reference'       = if ($obj.Reference) { Sanitize-CSVField $obj.Reference } else { "" }
                            'Signature'       = if ($obj.Signature) { Sanitize-CSVField $obj.Signature } else { "" }
                            'IsBuiltinBinary' = if ($obj.IsBuiltinBinary) { Sanitize-CSVField $obj.IsBuiltinBinary.ToString() } else { "" }
                            'IsLolbin'        = if ($obj.IsLolbin) { Sanitize-CSVField $obj.IsLolbin.ToString() } else { "" }
                            'Flag'            = if ($obj.Flag) { Sanitize-CSVField $obj.Flag } else { "" }
                            'Status'          = if ($obj.Status) { Sanitize-CSVField $obj.Status } else { "" }
                            'LnkTargetPath'   = if ($obj.PSObject.Properties.Name -contains 'LnkTargetPath' -and $obj.LnkTargetPath) { Sanitize-CSVField $obj.LnkTargetPath } else { "" }
                            'LnkTargetHash'   = if ($obj.PSObject.Properties.Name -contains 'LnkTargetHash' -and $obj.LnkTargetHash) { Sanitize-CSVField $obj.LnkTargetHash } else { "" }
                        }
                    }

                    $csvData | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

                    if (-not $Quiet) {
                        Write-Host "Results exported to: $OutputCSV" -ForegroundColor Green
                        Write-Host "Total items exported: $($csvData.Count)" -ForegroundColor Cyan
                    }
                }
            }
            catch {
                Write-Error "Failed to export CSV to $OutputCSV : $($_.Exception.Message)"
                if ($PassThru) { return @() }
                return
            }
        }

        # Display results to console (unless Quiet is specified)
        if (-not $Quiet) {
            if ($null -eq $script:globalPersistenceObjectArray -or $script:globalPersistenceObjectArray.Count -eq 0) {
                Write-Host "`n[X] No persistence mechanisms found" -ForegroundColor Red
            }
            else {
                # Summary
                $modeText = if ($Mode -eq 'Aggressive') { 
                    if ($Insane) { "insane mode" } else { "aggressive mode" }
                }
                else { "auto mode" }
                Write-Host "-------------------- $($script:globalPersistenceObjectArray.Count) potential persistence mechanisms ($modeText) --------------------" -ForegroundColor Green

                # Use indexed access instead of foreach
                for ($i = 0; $i -lt $script:globalPersistenceObjectArray.Count; $i++) {
                    try {
                        Write-ColoredPersistenceResult $script:globalPersistenceObjectArray[$i]
                    }
                    catch {
                        Write-Verbose "Error displaying result: $($_.Exception.Message)"
                        continue
                    }
                }

                Write-Host ""
                Write-Host "-------------------- $($script:globalPersistenceObjectArray.Count) potential persistence mechanisms ($modeText) --------------------" -ForegroundColor Green
            }
            Write-Host ""
        }

        # Return objects only if PassThru is specified
        if ($PassThru) {
            Write-Verbose "Returning $($script:globalPersistenceObjectArray.Count) objects via PassThru"
            return $script:globalPersistenceObjectArray
        }

    }
    catch {
        Write-Error "Critical error during persistence hunting: $($_.Exception.Message)"
        if ($PassThru) { return @() }
        return
    }
    finally {
        # Cleanup
        try {
            Dismount-TemporaryHives
            if (-not $Quiet) {
                Write-Progress -Activity "Hunt-Persistence" -Completed
            }
        }
        catch {
            Write-Warning "Cleanup error: $($_.Exception.Message)"
        }
    }
}


Function Hunt-Logs {
    <#
.SYNOPSIS
Hunts for security indicators and suspicious activities across Windows Event Logs and file systems.

.DESCRIPTION
Hunt-Logs is a comprehensive DFIR tool that searches Windows Event Logs and optionally scans file systems for indicators of compromise (IOCs), suspicious activities, and security events. It supports both live system analysis and offline EVTX file examination with advanced filtering, export capabilities, and automated threat hunting modes.

.PARAMETER StartDate
Start date for log search. Accepts datetime objects, relative time strings ('7D', '24H', '30M'), or 'Now'. Defaults to 7 days ago if not specified.

.PARAMETER EndDate  
End date for log search. Accepts same formats as StartDate. Defaults to current time.

.PARAMETER Search
Array of strings to search for in event messages and XML data. Case-insensitive wildcard matching.

.PARAMETER Exclude
Array of strings to exclude from results. Events containing these strings will be filtered out.

.PARAMETER Auto
Automated hunting mode with predefined IOC lists and time ranges:
- Level 1: 14-day search with core logs and baseline IOCs
- Level 2: 30-day comprehensive search with full IOC list  
- Level 3: 30-day search plus aggressive file system scanning

.PARAMETER Aggressive
Enables file system scanning for .log files. Specify path or use empty string for C:\ scan.

.PARAMETER PassThru
Returns PowerShell objects for programmatic processing instead of console output.

.PARAMETER Quiet
Suppresses console output (use with PassThru for silent operation).

.PARAMETER OutputCSV
Exports results to CSV format. Accepts file path or directory (auto-generates filename).

.PARAMETER Export
Exports all EVTX files to compressed archive. Specify path or use switch for default location.

.PARAMETER StopLogging
Stops Windows Event Log service to prevent log overwriting during forensics.

.EXAMPLE
Hunt-Logs -Auto 2
Runs comprehensive 30-day automated hunt with predefined IOCs.

.EXAMPLE
Hunt-Logs -StartDate "7D" -IncludeStrings "powershell","mimikatz" -OutputCSV "C:\DFIR\results.csv"
Searches last 7 days for PowerShell and Mimikatz indicators, exports to CSV.

.EXAMPLE
$results = Hunt-Logs -StartDate "24H" -LogNames "Security","System" -PassThru -Quiet
Silent search returning PowerShell objects for programmatic analysis.

.EXAMPLE
Hunt-Logs -FolderPath "C:\Evidence\logs" -IncludeStrings "lateral movement" -Aggressive "C:\Windows\Logs"
Analyzes offline EVTX files and scans file system for lateral movement indicators.

.NOTES
Requires PowerShell 5.0+. Administrator privileges recommended for complete log access.
#>
    param (
        [Parameter(Mandatory = $false)]
        $StartDate,
        [Parameter(Mandatory = $false)]
        $EndDate = "Now",
        [Parameter(Mandatory = $false)]
        [string[]]$Search = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$Exclude = @(),
        [Parameter(Mandatory = $false)]
        [int[]]$EventId = @(),
        [Parameter(Mandatory = $false)]
        [int[]]$ExcludeEventId = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$LogNames = @(),
        [Parameter(Mandatory = $false)]
        [ValidateSet("OldestFirst", "NewestFirst")]
        [string]$SortOrder = "NewestFirst",
        [Parameter(Mandatory = $false)]
        [int]$XML = 1250,
        [Parameter(Mandatory = $false)]
        [int]$MSG = 1000,
        [Parameter(Mandatory = $false)]
        [int]$MaxPrint = 0,
        [Parameter(Mandatory = $false)]
        [string]$Timezone = "",
        [Parameter(Mandatory = $false)]
        [switch]$StopLogging,
        [Parameter(Mandatory = $false)]
        [string]$Export,
        [Parameter(Mandatory = $false)]
        [string]$FolderPath,
        [Parameter(Mandatory = $false)]
        [string]$Aggressive,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Auto,
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        [Parameter(Mandatory = $false)]
        [string]$OutputCSV,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    # Define global IOC list if not already defined
    if ($null -eq (Get-Variable -Name "GlobalLogIOCs" -Scope Global -ErrorAction SilentlyContinue)) {
        Write-Warning "GlobalLogIOCs not found. Defining default IOC list."
        $script:GlobalLogIOCs = @("")
    }

    # Check for administrator privileges for optimal functionality
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-not $isAdmin) {
        Write-Warning "Not running as Administrator. Some event logs may be inaccessible, reducing detection coverage."
    }

    # Initialize result collection for PassThru
    $script:HuntLogResults = @()

    # Helper function to create log result object
    function New-LogResult {
        param(
            $LogEvent,
            $TargetTimeZone,
            $MatchedStrings = "",
            $IsAggressive = $false,
            $FilePath = "",
            $Match = ""
        )

        if ($IsAggressive) {
            return [PSCustomObject]@{
                Type             = "FileSystem"
                FilePath         = $FilePath
                FileName         = if ($FilePath) { Split-Path $FilePath -Leaf } else { "" }
                CreationDate     = $LogEvent.CreationDate
                LastModifiedDate = $LogEvent.LastModifiedDate
                Match            = $Match  # This is correct
                Text             = $LogEvent.Text
                Hostname         = Se([Net.Dns]::GetHostByName($env:computerName)).HostNamearch
                TimeCreated      = $null
                FormattedTime    = ""
                LogName          = "FileSystem"
                EventId          = $null
                RecordId         = $null
                Message          = $LogEvent.Text
                XML              = ""
                LevelDisplayName = ""
                ProcessId        = $null
                ThreadId         = $null
                UserId           = $null
            }
        }
        else {
            $formattedTime = Format-DateTimeWithTimeZone -DateTime $LogEvent.TimeCreated -TargetTimeZone $TargetTimeZone
        
            $xmlData = ""
            try {
                $xmlData = $LogEvent.ToXml()
            }
            catch {
                $xmlData = ""
            }

            return [PSCustomObject]@{
                Type             = "EventLog"
                TimeCreated      = $LogEvent.TimeCreated
                FormattedTime    = $formattedTime
                LogName          = $LogEvent.LogName
                EventId          = $LogEvent.Id
                RecordId         = $LogEvent.RecordId
                Message          = if ([string]::IsNullOrWhiteSpace($LogEvent.Message)) { "[No Message]" } else { $LogEvent.Message }
                MatchedStrings   = $MatchedStrings
                XML              = $xmlData
                LevelDisplayName = $LogEvent.LevelDisplayName
                ProcessId        = $LogEvent.ProcessId
                ThreadId         = $LogEvent.ThreadId
                UserId           = $LogEvent.UserId
                Hostname         = Se([Net.Dns]::GetHostByName($env:computerName)).HostNamearch
                FilePath         = ""      # Always blank for EventLog
                FileName         = ""      # Always blank for EventLog  
                CreationDate     = $null   # Always null for EventLog
                LastModifiedDate = $null   # Always null for EventLog
                Match            = $MatchedStrings  # Use MatchedStrings for EventLog entries
                Text             = if ([string]::IsNullOrWhiteSpace($LogEvent.Message)) { "[No Message]" } else { $LogEvent.Message }
            }
        }
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
            EndDate   = if ($PSBoundParameters.ContainsKey('EndDate')) { $EndDate } else { $baselineParams.EndDate }
            Search    = @($script:GlobalLogIOCs) + $Search  # Combine baseline IOCs with user additions
            SortOrder = $SortOrder
            XML       = $XML
            MSG       = $MSG
            MaxPrint  = $MaxPrint
            Timezone  = $Timezone
        }
        
        # Add LogNames (combine baseline with user additions)
        if ($baselineLogNames.Count -gt 0) {
            $finalParams.LogNames = $baselineLogNames + $LogNames | Select-Object -Unique
        }
        elseif ($LogNames.Count -gt 0) {
            $finalParams.LogNames = $LogNames
        }
        
        # Add other optional parameters
        if ($Exclude.Count -gt 0) { $finalParams.Exclude = $Exclude }
        if ($EventId.Count -gt 0) { $finalParams.EventId = $EventId }
        if ($ExcludeEventId.Count -gt 0) { $finalParams.ExcludeEventId = $ExcludeEventId }
        if ($PSBoundParameters.ContainsKey('FolderPath')) { $finalParams.FolderPath = $FolderPath }
        if ($PSBoundParameters.ContainsKey('Export')) { $finalParams.Export = $Export }
        
        # Handle Aggressive parameter for Auto Level 3
        if ($baselineAggressive) {
            if ($PSBoundParameters.ContainsKey('Aggressive') -and ![string]::IsNullOrWhiteSpace($Aggressive)) {
                $finalParams.Aggressive = $Aggressive  # User specified custom path
            }
            else {
                $finalParams.Aggressive = ""  # Default aggressive search
            }
        }
        elseif ($PSBoundParameters.ContainsKey('Aggressive')) {
            $finalParams.Aggressive = $Aggressive  # User added aggressive search
        }
        
        Write-Host "Baseline IOCs: $($script:GlobalLogIOCs.Count)" -ForegroundColor Green
        if ($Search.Count -gt 0) {
            Write-Host "Additional User IOCs: $($Search.Count)" -ForegroundColor Green
        }
        Write-Host "Total Search Strings: $($finalParams.Search.Count)" -ForegroundColor Green
        
        # Recursively call Hunt-Logs with final parameters
        return Hunt-Logs @finalParams
    }

    # Validate Aggressive parameter requires Search
    if ($PSBoundParameters.ContainsKey('Aggressive') -and $Search.Count -eq 0) {
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
            if (($null -ne $eventLogService) -and ($eventLogService.Status -eq "Running")) {
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
                }
                catch {
                    Write-Warning "Could not configure $logName log: $($_.Exception.Message)"
                }
            }

            Write-Host "Event logging has been paused. Remember to restart the EventLog service when forensics is complete." -ForegroundColor Cyan
            Write-Host "To restart: Start-Service -Name 'EventLog'" -ForegroundColor Cyan
            
        }
        catch {
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
                if (($Export -eq $true) -or [string]::IsNullOrWhiteSpace($Export)) {
                    # Just -Export with no path specified - use temp directory
                    $exportFullPath = Join-Path $tempDir $safeFilename
                    Write-Host "No export path specified, using default: $exportFullPath" -ForegroundColor Cyan
                }
                elseif ($Export -match '\.zip$') {
                    # Contains .zip extension
                    if ([System.IO.Path]::IsPathRooted($Export)) {
                        # Full absolute path with .zip extension
                        $exportFullPath = $Export
                    }
                    else {
                        # Relative path with .zip extension - treat as file in current directory
                        $currentDir = Get-Location -ErrorAction Stop
                        $exportFullPath = Join-Path $currentDir.Path $Export
                    }
                }
                else {
                    # No .zip extension - treat as directory path
                    if ([System.IO.Path]::IsPathRooted($Export)) {
                        # Full absolute directory path
                        $exportFullPath = Join-Path $Export $safeFilename
                    }
                    else {
                        # Relative directory path
                        $currentDir = Get-Location -ErrorAction Stop
                        $targetDir = Join-Path $currentDir.Path $Export
                        $exportFullPath = Join-Path $targetDir $safeFilename
                    }
                }
            }
            catch {
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
                }
                catch {
                    throw "Cannot create export directory '$exportDir': $($_.Exception.Message)"
                }
            }
            
            # Verify directory is writable
            try {
                $testFile = Join-Path $exportDir "test_write_$(Get-Random).tmp"
                New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            }
            catch {
                throw "Export directory '$exportDir' is not writable: $($_.Exception.Message)"
            }

            Write-Host "Export path: $exportFullPath" -ForegroundColor Cyan

            # Create temporary export directory
            $tempEvtxDir = Join-Path $tempDir "EVTX_Export_$datetime"
            try {
                New-Item -Path $tempEvtxDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
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
                    }
                    catch {
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
                    }
                    catch {
                        Write-Verbose "Cannot enumerate path: $basePath - $($_.Exception.Message)"
                    }
                }
                else {
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
                }
                catch {
                    # wevtutil failed, will try file copy
                }
                
                if (-not $exported) {
                    try {
                        # Fall back to file copy for archived/inactive logs
                        if (Test-Path $file.FullName -PathType Leaf) {
                            Copy-Item $file.FullName $destPath -ErrorAction Stop
                            $copiedCount++
                            $totalSize += $file.Length
                        }
                        else {
                            Write-Verbose "Source file no longer exists: $($file.FullName)"
                            $copyErrors++
                        }
                    }
                    catch [UnauthorizedAccessException] {
                        Write-Verbose "Access denied copying $($file.Name)"
                        $accessDeniedCount++
                    }
                    catch [System.IO.IOException] {
                        Write-Verbose "File in use, skipping $($file.Name)"
                        $copyErrors++
                    }
                    catch {
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
            }
            catch {
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
                }
                else {
                    # Fallback for older PowerShell versions
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempEvtxDir, $exportFullPath)
                }
            }
            catch {
                throw "Failed to create ZIP archive: $($_.Exception.Message)"
            }

            # Clean up temporary directory
            try {
                Remove-Item $tempEvtxDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "Could not clean up temporary directory: $tempEvtxDir"
            }

            # Get final archive information
            if (Test-Path $exportFullPath) {
                $exportItem = Get-Item $exportFullPath
                $exportSize = $exportItem.Length
                $exportSizeMB = [math]::Round($exportSize / 1MB, 2)
                $compressionRatio = if ($totalSize -gt 0) { 
                    [math]::Round((1 - ($exportSize / $totalSize)) * 100, 1) 
                }
                else { 
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
            }
            else {
                throw "Export file was not created successfully."
            }

        }
        catch {
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
            }
            return [System.TimeZoneInfo]::FindSystemTimeZoneById($mappedName)
        }
        catch {
            Write-Warning "Invalid timezone '$TimezoneName', using system local time"
            return $systemTimeZone
        }
    }

    $targetTimeZone = if ([string]::IsNullOrWhiteSpace($Timezone)) { $systemTimeZone } else { Get-TimezoneInfo -TimezoneName $Timezone }

    # Function to parse time strings - treats input as being in target timezone, converts to system time for queries
    function ConvertTo-DateTime {
        param($InputValue, $TargetTimeZone)
    
        $resultTime = $null
    
        try {
            if ($InputValue -is [datetime]) {
                $resultTime = $InputValue
            }
            elseif ($InputValue -is [string]) {
                $InputValue = $InputValue.Trim()
            
                if ($InputValue.ToLower() -eq 'now') {
                    $resultTime = Get-Date
                }
                elseif ($InputValue -match '^(\d+)([DHMdhm])$') {
                    $number = [int]$matches[1]
                    $unit = $matches[2].ToUpper()
                
                    $currentTime = Get-Date
                    switch ($unit) {
                        'D' { $resultTime = $currentTime.AddDays(-$number) }
                        'H' { $resultTime = $currentTime.AddHours(-$number) }
                        'M' { $resultTime = $currentTime.AddMinutes(-$number) }
                    }
                }
                else {
                    $resultTime = [datetime]$InputValue
                }
            }
            else {
                throw "Unsupported input type"
            }
        
            # Convert from target timezone to system timezone for log queries
            if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                $resultTime = [System.TimeZoneInfo]::ConvertTime(
                    [DateTime]::SpecifyKind($resultTime, [DateTimeKind]::Unspecified),
                    $TargetTimeZone,
                    $systemTimeZone
                )
            }
        
            return $resultTime
        }
        catch {
            throw "Invalid date format: $InputValue. Use datetime, 'now', or relative format like '7D', '24H', '30M'"
        }
    }

    # Function to format datetime - converts from system time back to target timezone for display
    function Format-DateTimeWithTimeZone {
        param($DateTime, $TargetTimeZone)
    
        try {
            $convertedTime = if ($TargetTimeZone.Id -eq $systemTimeZone.Id) {
                $DateTime
            }
            else {
                [System.TimeZoneInfo]::ConvertTime($DateTime, $systemTimeZone, $TargetTimeZone)
            }
        
            $tzAbbrev = if ($TargetTimeZone.Id -eq 'UTC') { 
                'UTC' 
            }
            elseif ($TargetTimeZone.StandardName -like "*Eastern*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'EDT' } else { 'EST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Central*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'CDT' } else { 'CST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Mountain*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'MDT' } else { 'MST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Pacific*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'PDT' } else { 'PST' } 
            }
            else { 
                $TargetTimeZone.StandardName.Split(' ')[0] 
            }
        
            return $convertedTime.ToString("yyyy-MM-dd HH:mm:ss") + " $tzAbbrev"
        }
        catch {
            return $DateTime.ToString("yyyy-MM-dd HH:mm:ss")
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
            }
            else {
                try {
                    $parsedDate = [datetime]$InputValue
                    # If user specified a timezone, interpret the input date as being in that timezone
                    if ($TargetTimeZone.Id -ne $systemTimeZone.Id) {
                        # Convert from target timezone to system timezone for search
                        $convertedTime = [System.TimeZoneInfo]::ConvertTime($parsedDate, $TargetTimeZone, $systemTimeZone)
                        return $convertedTime
                    }
                    return $parsedDate
                }
                catch {
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
        }
        else {
            $convertedTime = [System.TimeZoneInfo]::ConvertTime($DateTime, $systemTimeZone, $TargetTimeZone)
            
            $tzAbbrev = if ($TargetTimeZone.Id -eq 'UTC') { 
                'UTC' 
            }
            elseif ($TargetTimeZone.StandardName -like "*Eastern*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'EDT' } else { 'EST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Central*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'CDT' } else { 'CST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Mountain*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'MDT' } else { 'MST' } 
            }
            elseif ($TargetTimeZone.StandardName -like "*Pacific*") { 
                if ($TargetTimeZone.IsDaylightSavingTime($convertedTime)) { 'PDT' } else { 'PST' } 
            }
            else { 
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
    }
    elseif ($null -eq $StartDate) {
        throw "EndDate specified but StartDate is missing. Please provide both dates or neither."
    }
    elseif ($null -eq $EndDate) {
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
                    }
                    elseif ($data -is [string] -and ![string]::IsNullOrWhiteSpace($data)) {
                        $outputLines += "    Data: $data"
                    }
                }
            }
            
            if ($xmlDoc.Event.UserData) {
                $outputLines += "  UserData:"
                foreach ($child in $xmlDoc.Event.UserData.ChildNodes) {
                    if ($child.InnerText) {
                        $outputLines += "    $($child.Name): $($child.InnerText)"
                    }
                    elseif ($child.HasChildNodes) {
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
            
        }
        catch {
            $rawResult = "  [XML Parse Error] Raw: $XmlString"
            if ($TruncateLength -gt 0 -and $rawResult.Length -gt $TruncateLength) {
                $rawResult = $rawResult.Substring(0, $TruncateLength) + "..."
            }
            return $rawResult
        }
    }


    # Function to sanitize CSV data for Excel compatibility
    function Format-CSVValue {
        param($Value)
    
        if ($null -eq $Value -or $Value -eq "") {
            return ""
        }
    
        $stringValue = $Value.ToString()
    
        # Remove or escape problematic characters
        $stringValue = $stringValue -replace '[\r\n]+', ' ' # Replace newlines with spaces
        $stringValue = $stringValue -replace '\t', ' '      # Replace tabs with spaces
        $stringValue = $stringValue -replace '"', '""'      # Escape quotes for CSV
    
        # Sanitize formula triggers for Excel security
        if ($stringValue -match '^[=@+\-]') {
            $stringValue = "'" + $stringValue
        }
    
        # Truncate if too long for Excel (32,767 character limit per cell)
        if ($stringValue.Length -gt 32760) {
            $stringValue = $stringValue.Substring(0, 32760) + "..."
        }
    
        return $stringValue
    }

    # Function to test if strings match
    function Test-EventMatches {
        param($Event, $Search, $Exclude)
        
        $message = if ([string]::IsNullOrWhiteSpace($Event.Message)) { "" } else { $Event.Message }
        $xmlContent = ""
        try {
            $xmlContent = $Event.ToXml()
        }
        catch {
            $xmlContent = ""
        }
        
        $searchContent = "$message $xmlContent"
        
        if ($Exclude.Count -gt 0) {
            foreach ($excludeStr in $Exclude) {
                if ($searchContent -like "*$excludeStr*") {
                    return $false
                }
            }
        }
        
        if ($Search.Count -gt 0) {
            foreach ($includeStr in $Search) {
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
        param($Event, $Search)
        
        $matchList = @()
        $message = if ([string]::IsNullOrWhiteSpace($Event.Message)) { "" } else { $Event.Message }
        $xmlContent = ""
        try {
            $xmlContent = $Event.ToXml()
        }
        catch {
            $xmlContent = ""
        }
        
        foreach ($includeStr in $Search) {
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
        param($SearchPath, $Search, $MsgTruncateLength)
        
        $logMatches = @()
        $maxFileSizeMB = 100  # Safety limit - don't scan files larger than 100MB
        
        # Check if we've already scanned C:\ and have cached results
        if ($SearchPath -eq "C:\" -and $global:HuntLogs_SystemScanComplete -and $global:HuntLogs_LogFilePaths) {
            Write-Host "Using cached log file paths from previous system scan..." -ForegroundColor Cyan
            Write-Host "Cached paths: $($global:HuntLogs_LogFilePaths.Count) .log files" -ForegroundColor Green
            $logFileList = $global:HuntLogs_LogFilePaths | ForEach-Object { 
                if (Test-Path $_) { Get-Item $_ -ErrorAction SilentlyContinue }
            } | Where-Object { $null -ne $_ }
        }
        else {
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
            }
            catch {
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
            }
            else {
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
                    foreach ($searchString in $Search) {
                        if ($line -like "*$searchString*") {
                            $truncatedText = $line
                            if ($MsgTruncateLength -gt 0 -and $line.Length -gt $MsgTruncateLength) {
                                $truncatedText = $line.Substring(0, [math]::Max(1, $MsgTruncateLength)) + "..."
                            }
                            
                            $logMatches += [PSCustomObject]@{
                                FilePath         = $logFile.FullName
                                CreationDate     = $logFile.CreationTime
                                LastModifiedDate = $logFile.LastWriteTime
                                Match            = $searchString
                                Text             = $truncatedText
                            }
                            break # Only add one match per line
                        }
                    }
                }
            }
            catch {
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
    }
    catch {
        throw "Date parsing error: $($_.Exception.Message)"
    }

    # Handle Aggressive search first (will be displayed last)
    $aggressiveResults = @()
    if ($PSBoundParameters.ContainsKey('Aggressive')) {
        $searchPath = if ([string]::IsNullOrWhiteSpace($Aggressive)) { "C:\" } else { $Aggressive }
        
        if (-not (Test-Path $searchPath)) {
            throw "Aggressive search path does not exist: $searchPath"
        }
        
        $aggressiveResults = Search-AggressiveLogFiles -SearchPath $searchPath -IncludeStrings $Search -MsgTruncateLength $msgTruncateLength
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
        }
        else {
            if ($FolderPath -like "*.evtx") {
                $evtxFileList = @(Get-Item $FolderPath -ErrorAction SilentlyContinue)
            }
            else {
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
                    Path      = $evtxFile.FullName
                    StartTime = $parsedStartDate
                    EndTime   = $parsedEndDate
                }

                if ($EventId.Count -gt 0) { $filterHash.Id = $EventId }

                $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($eventItem in $events) {
                        if ($ExcludeEventId.Count -gt 0 -and $ExcludeEventId -contains $eventItem.Id) { 
                            $filteredCount++
                            continue 
                        }
                        
                        if (-not (Test-EventMatches -Event $eventItem -IncludeStrings $Search -ExcludeStrings $Exclude)) {
                            $filteredCount++
                            continue
                        }

                        $hashKey = Get-EventHashKey -Event $eventItem
                        if (-not $allEvents.ContainsKey($hashKey)) {
                            if ($Search.Count -gt 0) {
                                $matchInfo = Get-MatchedStrings -Event $eventItem -IncludeStrings $Search
                                $eventItem | Add-Member -MemberType NoteProperty -Name "MatchedStrings" -Value $matchInfo -Force
                            }
                            $allEvents[$hashKey] = $eventItem
                            $eventCount++
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error processing EVTX file '$($evtxFile.Name)': $($_.Exception.Message)"
            }
        }

    }
    else {
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
                    }
                    else {
                        $logsToQuery += $logName
                    }
                }
            }
            else {
                $logsToQuery = $availableLogs | Select-Object -ExpandProperty LogName
            }
        }
        catch {
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
                    LogName   = $logName
                    StartTime = $parsedStartDate
                    EndTime   = $parsedEndDate 
                }

                if ($EventId.Count -gt 0) { $filterHash.Id = $EventId }

                $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($eventItem in $events) {
                        if ($ExcludeEventId.Count -gt 0 -and $ExcludeEventId -contains $eventItem.Id) { 
                            $filteredCount++
                            continue 
                        }
                        
                        if (-not (Test-EventMatches -Event $eventItem -IncludeStrings $Search -ExcludeStrings $Exclude)) {
                            $filteredCount++
                            continue
                        }

                        $hashKey = Get-EventHashKey -Event $eventItem
                        if (-not $allEvents.ContainsKey($hashKey)) {
                            if ($Search.Count -gt 0) {
                                $matchInfo = Get-MatchedStrings -Event $eventItem -IncludeStrings $Search
                                $eventItem | Add-Member -MemberType NoteProperty -Name "MatchedStrings" -Value $matchInfo -Force
                            }
                            $allEvents[$hashKey] = $eventItem
                            $eventCount++
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error processing log '$logName': $($_.Exception.Message)"
            }
        }
    }

    Write-Progress -Activity "Hunt-Logs Search" -Status "Processing $($allEvents.Count) events..." -PercentComplete 90

    $uniqueEvents = $allEvents.Values
    $sortedEvents = if ($SortOrder -eq "OldestFirst") {
        $uniqueEvents | Sort-Object TimeCreated
    }
    else {
        $uniqueEvents | Sort-Object TimeCreated -Descending
    }

    Write-Progress -Activity "Hunt-Logs Search" -Status "Complete - Found $($sortedEvents.Count) unique events" -PercentComplete 100
    Start-Sleep -Milliseconds 500
    Write-Progress -Activity "Hunt-Logs Search" -Completed

    $totalOutputChars = 0

    # Collect results for PassThru and CSV export (always collect, regardless of PassThru)
    foreach ($logEvent in $sortedEvents) {
        $message = if ([string]::IsNullOrWhiteSpace($logEvent.Message)) { "[No Message]" } else { $logEvent.Message }
        $cleanMessage = $message -replace '\r?\n', ' ' -replace '\s+', ' ' -replace '^\s+|\s+$', ''

        # Always create result object for CSV export and potential PassThru
        $matchedStrings = if (($Search.Count -gt 0) -and $logEvent.MatchedStrings) { $logEvent.MatchedStrings } else { "" }
        $logResult = New-LogResult -LogEvent $logEvent -TargetTimeZone $targetTimeZone -MatchedStrings $matchedStrings
        $script:HuntLogResults += $logResult

        # Display only if not Quiet
        if (-not $Quiet) {
            # Prepare display message
            if ($msgTruncateLength -eq 0) {
                $displayMessage = "[Message Display Disabled]"
            }
            elseif (($msgTruncateLength -gt 0) -and ($cleanMessage.Length -gt $msgTruncateLength)) {
                $displayMessage = $cleanMessage.Substring(0, [math]::Max(1, $msgTruncateLength)) + "..."
            }
            else {
                $displayMessage = $cleanMessage
            }

            $formattedTime = Format-DateTimeWithTimeZone -DateTime $logEvent.TimeCreated -TargetTimeZone $targetTimeZone

            # Get formatted XML
            $formattedXml = ""
            try {
                $rawXml = $logEvent.ToXml()
                $formattedXml = Format-EventXml -XmlString $rawXml -TruncateLength $xmlTruncateLength
            }
            catch {
                $formattedXml = "[XML Unavailable]"
            }

            # Check MaxPrint limit before displaying
            if ($MaxPrint -gt 0) {
                $eventOutputSize = 300 + $displayMessage.Length + $logEvent.LogName.Length + $formattedTime.Length + $formattedXml.Length
                if (($Search.Count -gt 0) -and $logEvent.MatchedStrings) {
                    $eventOutputSize += $logEvent.MatchedStrings.Length + 50
                }

                if ($totalOutputChars + $eventOutputSize -gt $MaxPrint) {
                    $remainingEvents = $sortedEvents.Count - $sortedEvents.IndexOf($logEvent)
                    Write-Host ""
                    Write-Host "Output truncated: MaxPrint limit ($MaxPrint chars) reached. $remainingEvents more events available." -ForegroundColor DarkRed
                    break
                }
                $totalOutputChars += $eventOutputSize
            }

            # Display event information
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor Gray
            Write-Host "Time     : " -NoNewline -ForegroundColor Yellow
            Write-Host $formattedTime -ForegroundColor White
            Write-Host "Log Name : " -NoNewline -ForegroundColor Yellow
            Write-Host $logEvent.LogName -ForegroundColor Cyan
            Write-Host "Event ID : " -NoNewline -ForegroundColor Yellow
            Write-Host $logEvent.Id -ForegroundColor White
        
            if (($Search.Count -gt 0) -and $logEvent.MatchedStrings) {
                Write-Host "Match    : " -NoNewline -ForegroundColor Yellow
                Write-Host $logEvent.MatchedStrings -ForegroundColor Red
            }
        
            Write-Host "Message  : " -NoNewline -ForegroundColor Yellow
            Write-Host $displayMessage -ForegroundColor Green

            # Display XML data if enabled and available
            if (($xmlTruncateLength -ne 0) -and (-not [string]::IsNullOrWhiteSpace($formattedXml)) -and ($formattedXml -ne "[No XML Data]")) {
                Write-Host "XML Data : " -NoNewline -ForegroundColor Yellow
                $xmlLines = $formattedXml -split "`n"
                if ($xmlLines.Count -eq 1) {
                    Write-Host $formattedXml -ForegroundColor Gray
                }
                else {
                    Write-Host ""
                    foreach ($line in $xmlLines) {
                        if ($line.Trim()) {
                            Write-Host "  $line" -ForegroundColor Gray
                        }
                    }
                }
            }
        }
    }

    # Handle aggressive results display and collection
    if ($aggressiveResults.Count -gt 0) {
        # Always collect aggressive results for CSV export
        foreach ($result in $aggressiveResults) {
            $aggressiveResult = New-LogResult -LogEvent $result -TargetTimeZone $targetTimeZone -IsAggressive $true -FilePath $result.FilePath -Match $result.Match
            $script:HuntLogResults += $aggressiveResult
        }

        # Display aggressive results only if not Quiet
        if (-not $Quiet) {
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
        }
    }
    elseif ($PSBoundParameters.ContainsKey('Aggressive') -and -not $Quiet) {
        Write-Host "`n[X] No Filesystem Logs Found" -ForegroundColor Red
    }

    # Handle CSV Export
    if ($PSBoundParameters.ContainsKey('OutputCSV')) {
        try {
            # Determine export path
            $csvPath = ""
            if ([string]::IsNullOrWhiteSpace($OutputCSV)) {
                # Handle switch usage (just -OutputCSV with no value)
                $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $hostname = $env:COMPUTERNAME
                $csvFilename = "HuntLogs_${hostname}_${timestamp}.csv"
                $csvPath = Join-Path (Get-Location) $csvFilename
            }
            elseif (Test-Path $OutputCSV -PathType Container) {
                # Directory provided, generate filename
                $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $hostname = $env:COMPUTERNAME
                $csvFilename = "HuntLogs_${hostname}_${timestamp}.csv"
                $csvPath = Join-Path $OutputCSV $csvFilename
            }
            elseif ($OutputCSV -match '\.csv$') {
                # Full path with .csv extension
                $csvPath = $OutputCSV
            }
            else {
                # Assume it's a path, add .csv extension
                $csvPath = $OutputCSV + ".csv"
            }
        
            # Validate directory exists
            $csvDir = Split-Path $csvPath -Parent
            if (![string]::IsNullOrWhiteSpace($csvDir) -and !(Test-Path $csvDir)) {
                New-Item -Path $csvDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        
            # Export data if we have results
            if ($script:HuntLogResults.Count -gt 0) {
                # Sanitize data for CSV export
                $sanitizedResults = @()
                foreach ($result in $script:HuntLogResults) {
                    $sanitizedResult = [PSCustomObject]@{
                        Type             = Format-CSVValue $result.Type
                        FormattedTime    = Format-CSVValue $result.FormattedTime
                        TimeCreated      = Format-CSVValue $result.TimeCreated
                        LogName          = Format-CSVValue $result.LogName
                        EventId          = Format-CSVValue $result.EventId
                        RecordId         = Format-CSVValue $result.RecordId
                        LevelDisplayName = Format-CSVValue $result.LevelDisplayName
                        ProcessId        = Format-CSVValue $result.ProcessId
                        ThreadId         = Format-CSVValue $result.ThreadId
                        UserId           = Format-CSVValue $result.UserId
                        Message          = Format-CSVValue $result.Message
                        MatchedStrings   = Format-CSVValue $result.MatchedStrings
                        Match            = Format-CSVValue $result.Match
                        Text             = Format-CSVValue $result.Text
                        XML              = Format-CSVValue $result.XML
                        FilePath         = Format-CSVValue $result.FilePath
                        FileName         = Format-CSVValue $result.FileName
                        CreationDate     = Format-CSVValue $result.CreationDate
                        LastModifiedDate = Format-CSVValue $result.LastModifiedDate
                        Hostname         = Format-CSVValue $result.Hostname
                    }
                    $sanitizedResults += $sanitizedResult
                }
            
                # Export to CSV
                $sanitizedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            
                if (-not $Quiet) {
                    Write-Host "Results exported to CSV: $csvPath" -ForegroundColor Green
                    Write-Host "Total records exported: $($sanitizedResults.Count)" -ForegroundColor Cyan
                }
            }
            else {
                if (-not $Quiet) {
                    Write-Host "No results to export to CSV" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Error "CSV Export Error: $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity "Hunt-Logs" -Completed
    # Summary and filtering info
    if (-not $Quiet) {
        if ((($ExcludeEventId.Count -gt 0) -or ($Exclude.Count -gt 0)) -and ($filteredCount -gt 0)) {
            Write-Host ""
            Write-Host "[INFO]: $filteredCount event logs filtered out by exclude parameters." -ForegroundColor DarkYellow
        }
    }

    # Return objects only if PassThru is specified
    if ($PassThru) {
        if ($script:HuntLogResults.Count -eq 0) {
            if (-not $Quiet) { Write-Verbose "No results to return via PassThru" }
            return @()
        }
        return $script:HuntLogResults
    }

    if (-not $Quiet) {
        Write-Host ""
    }
    Write-Host "`n"
}


function Hunt-Browser {
    <#
.SYNOPSIS
Hunts for browser artifacts, history, and network indicators across user profiles and DNS logs.

.DESCRIPTION
Hunt-Browser is a digital forensics function that extracts and analyzes browser history, cache data, and DNS logs to identify suspicious network activity, malicious URLs, and file system artifacts. It supports multiple browsers including Chrome, Firefox, Edge, and their variants.

.PARAMETER Cache
Preserves extracted browser databases for manual analysis without processing strings.

.PARAMETER Auto
Uses predefined suspicious patterns to identify potentially malicious artifacts (default mode).

.PARAMETER Aggressive
Expands detection to Search broader patterns that may generate more false positives.

.PARAMETER All
Returns all discovered browser artifacts without filtering.

.PARAMETER FetchTools
Downloads and uses BrowsingHistoryView tool from NirSoft for comprehensive history extraction.

.PARAMETER Truncate
Limits the display length of discovered strings to specified number of characters.

.PARAMETER Search
Array of patterns to specifically Search in results (wildcards supported).

.PARAMETER Exclude
Array of patterns to exclude from results (wildcards supported).

.PARAMETER OutputDir
Directory for temporary files (default: $env:TEMP\ForensicHunter\Hunt-Browser).

.PARAMETER OutputCSV
Export results to CSV file. Accepts file path or directory path (auto-generates filename).

.PARAMETER Quiet
Suppresses console output except for errors and critical information.

.PARAMETER PassThru
Returns PowerShell objects for programmatic use instead of displaying results.

.PARAMETER SkipConfirmation
Skips user confirmation prompt when using FetchTools mode.

.EXAMPLE
Hunt-Browser
Runs in Auto mode, scanning all user profiles for suspicious browser artifacts.

.EXAMPLE
Hunt-Browser -All -OutputCSV "C:\Reports\browser_analysis.csv" -Quiet
Extracts all browser artifacts and exports to CSV with minimal console output.

.EXAMPLE
Hunt-Browser -Include "*.evil.com*","*malware*" -Exclude "*google*" -PassThru | Where-Object Count -gt 5
Filters for specific patterns and returns objects for further PowerShell processing.

.EXAMPLE
Hunt-Browser -FetchTools "C:\Investigation\browser_history.csv" -SkipConfirmation
Uses third-party tool to extract comprehensive browser history to specified file.

.NOTES
- Requires PowerShell 5.0 or higher
- Administrator privileges recommended for complete system access
- Some browser databases may be locked if browsers are currently running
- FetchTools mode downloads third-party executable from NirSoft
#>
    param(
        [switch]$Cache,
        [switch]$Auto,
        [switch]$Aggressive,
        [switch]$All,
        [string]$FetchTools,
        [int]$Truncate = 0,
        [string[]]$Search = @(),
        [string[]]$Exclude = @(),
        [string]$OutputDir = "$env:TEMP\ForensicHunter\Hunt-Browser",
        [string]$OutputCSV,
        [switch]$Quiet,
        [switch]$PassThru,
        [switch]$SkipConfirmation
    )

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($null -eq $isAdmin -or -not $isAdmin) {
        Write-Warning "Not running as Administrator, insufficient privileges may cause detection issues..."
    }

    # Validate output paths early
    if ($OutputCSV) {
        try {
            $testPath = Split-Path $OutputCSV -Parent
            if ($null -ne $testPath -and -not (Test-Path $testPath -ErrorAction SilentlyContinue)) {
                $null = New-Item -Path $testPath -ItemType Directory -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Cannot access output path for CSV: $OutputCSV"
            return
        }
    }

    # Initialize script variables
    $script:AllFilesToCleanup = @()
    $script:CreatedDirectories = @()
    $script:PersistentFiles = @()


    function Sanitize-SearchPattern {
        param([string]$Pattern)
    
        if ([string]::IsNullOrWhiteSpace($Pattern)) { return "" }
    
        # Remove potentially dangerous characters
        $sanitized = $Pattern -replace '[`$();{}|&<>]', ''
        return $sanitized.Trim()
    }

    function Resolve-SafePath {
        param(
            [string]$Path,
            [string]$DefaultPath,
            [switch]$AllowNew,
            [string]$Extension
        )
    
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $DefaultPath
        }
    
        try {
            # Prevent path traversal
            $normalizedPath = [System.IO.Path]::GetFullPath($Path)
        
            # Basic validation - ensure it's within reasonable system paths
            if ($normalizedPath -notmatch '^[A-Za-z]:\\' -and $normalizedPath -notmatch '^\\\\[^\\]+\\[^\\]+') {
                throw "Invalid path format"
            }
        
            # Check for suspicious patterns
            if ($normalizedPath -match '\.\.' -or $normalizedPath -match '[<>"|?*]') {
                throw "Path contains invalid characters"
            }
        
            # Add extension if specified
            if ($Extension -and -not $normalizedPath.EndsWith($Extension, [StringComparison]::OrdinalIgnoreCase)) {
                $normalizedPath += $Extension
            }
        
            # For new files, ensure parent directory is valid
            if ($AllowNew) {
                $parentDir = Split-Path $normalizedPath -Parent
                if ($parentDir -and -not (Test-Path $parentDir -ErrorAction SilentlyContinue)) {
                    # Don't create here, just validate the path structure is reasonable
                    if ($parentDir.Length -lt 3 -or $parentDir.Length -gt 248) {
                        throw "Invalid parent directory path length"
                    }
                }
            }
        
            return $normalizedPath
        }
        catch {
            return $DefaultPath
        }
    }

    function Sanitize-Output {
        param($Input)

        # Convert to string safely
        $stringValue = $Input.ToString()    
        # Only remove characters that break CSV/Excel files
        $sanitized = $stringValue -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''  # Control characters
        $sanitized = $sanitized -replace '"', '""'  # Escape double quotes for CSV    
        $sanitized = $sanitized.Trim()
        # Limit length to prevent memory issues
        if ($sanitized.Length -gt 32767) {
            $sanitized = $sanitized.Substring(0, 32767) + "...[TRUNCATED]"
            Write-Host "[DEBUG] Truncated to 32767 chars" -ForegroundColor DarkYellow
        }
    
        return $sanitized
    }

    function Export-ResultsToCSV {
        param(
            [array]$Results,
            [string]$Path,
            [switch]$Quiet
        )
    
        if ($null -eq $Results -or $Results.Count -eq 0) {
            if (-not $Quiet) {
                Write-Host "[CSV] No results to export" -ForegroundColor Yellow
            }
            return
        }
    
        try {
            # Handle directory vs file path
            if (Test-Path $Path -PathType Container -ErrorAction SilentlyContinue) {
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $Path = Join-Path $Path "Hunt-Browser-Results-$timestamp.csv"
            }
        
            # Ensure the parent directory exists
            $parentDir = Split-Path $Path -Parent
            if ($null -ne $parentDir -and -not (Test-Path $parentDir -ErrorAction SilentlyContinue)) {
                New-Item -Path $parentDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                if (-not $Quiet) {
                    Write-Host "[CSV] Created directory: $parentDir" -ForegroundColor Green
                }
            }
        
            $csvData = $Results | ForEach-Object {
                $result = $_
            
                # Excel-safe sanitization function
                $sanitizeForExcel = {
                    param($value)
                    if ($null -eq $value) { return "" }
                
                    $stringValue = $value.ToString()
                    # Escape leading = to prevent formula injection
                    if ($stringValue.StartsWith("=")) {
                        $stringValue = "'" + $stringValue
                    }
                    # Remove or escape other formula triggers
                    $stringValue = $stringValue -replace '^[@+\-]', "'$&"
                    # Remove control characters but preserve newlines as spaces
                    $stringValue = $stringValue -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''
                    # Escape double quotes for CSV
                    $stringValue = $stringValue -replace '"', '""'
                    # Limit length to Excel's cell limit
                    if ($stringValue.Length -gt 32767) {
                        $stringValue = $stringValue.Substring(0, 32764) + "..."
                    }
                    return $stringValue
                }
            
                $csvRow = [PSCustomObject]@{
                    Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Hostname     = & $sanitizeForExcel $result.Hostname
                    User         = & $sanitizeForExcel $result.User
                    Source       = & $sanitizeForExcel $result.Source
                    Browser      = & $sanitizeForExcel $result.Browser
                    String       = & $sanitizeForExcel $result.String
                    FullString   = & $sanitizeForExcel $result.FullString
                    MatchPattern = & $sanitizeForExcel $result.MatchPattern
                    Length       = $result.Length
                    Count        = if ($null -ne $result.Count) { $result.Count } else { 1 }
                    Title        = if ($null -ne $result.Title) { & $sanitizeForExcel $result.Title } else { "" }
                    VisitTime    = if ($null -ne $result.VisitTime) { & $sanitizeForExcel $result.VisitTime } else { "" }
                }
            
                return $csvRow
            }
                
            $csvData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        
            if (-not $Quiet) {
                Write-Host "[CSV] Exported $($Results.Count) results to: $Path" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to export CSV: $($_.Exception.Message)"
        }
    }
    function Process-BrowserData {
        param(
            [string]$UserProfile,
            [string]$UserName,
            [hashtable]$Browser,
            [string]$OutputDir,
            [string]$Timestamp,
            [string]$Hostname,
            [switch]$Cache,
            [string]$EffectiveMode,
            [string[]]$Search,
            [string[]]$Exclude,
            [int]$Truncate,
            [switch]$Quiet
        )
    
        $results = @()
    
        try {
            if (-not (Test-Path $UserProfile -PathType Container -ErrorAction SilentlyContinue)) {
                return @()
            }
        
            # Determine base paths based on browser type
            $searchPaths = @()
        
            if ($Browser.Type -eq "Firefox") {
                $firefoxBase = Join-Path $UserProfile "AppData\Roaming\Mozilla\Firefox\Profiles"
                if (Test-Path $firefoxBase -ErrorAction SilentlyContinue) {
                    $profileDirs = Get-ChildItem $firefoxBase -Directory -ErrorAction SilentlyContinue
                    foreach ($profileDir in $profileDirs) {
                        $placesPath = Join-Path $profileDir.FullName "places.sqlite"
                        if (Test-Path $placesPath -ErrorAction SilentlyContinue) {
                            $searchPaths += $placesPath
                        }
                    }
                }
            
                # Check other Firefox variants
                $otherFirefoxPaths = @(
                    "AppData\Roaming\Waterfox\Profiles",
                    "AppData\Roaming\Moonchild Productions\Pale Moon\Profiles",
                    "AppData\Roaming\Mozilla\SeaMonkey\Profiles"
                )
            
                foreach ($ffPath in $otherFirefoxPaths) {
                    $fullPath = Join-Path $UserProfile $ffPath
                    if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                        $profileDirs = Get-ChildItem $fullPath -Directory -ErrorAction SilentlyContinue
                        foreach ($profileDir in $profileDirs) {
                            $placesPath = Join-Path $profileDir.FullName "places.sqlite"
                            if (Test-Path $placesPath -ErrorAction SilentlyContinue) {
                                $searchPaths += $placesPath
                            }
                        }
                    }
                }
            }
            else {
                # Chromium-based browsers
                $basePath = Join-Path $UserProfile "AppData\Local$($Browser.Path)"
                if (Test-Path $basePath -ErrorAction SilentlyContinue) {
                    $searchPaths += $basePath
                }
            
                # Check for multiple profiles in Chromium browsers
                $profilesDir = Split-Path $basePath -Parent
                if (Test-Path $profilesDir -ErrorAction SilentlyContinue) {
                    $profileDirs = Get-ChildItem $profilesDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(Default|Profile \d+)$" }
                    foreach ($profileDir in $profileDirs) {
                        $historyPath = Join-Path $profileDir.FullName "History"
                        if (Test-Path $historyPath -ErrorAction SilentlyContinue) {
                            $searchPaths += $historyPath
                        }
                    }
                }
            }
        
            # Process all found paths
            foreach ($filePath in $searchPaths) {
                try {
                    if (Test-Path $filePath -ErrorAction SilentlyContinue) {
                        $fileResults = Process-SingleBrowserFile -FilePath $filePath -BrowserName $Browser.Name -UserName $UserName -OutputDir $OutputDir -Timestamp $Timestamp -Cache:$Cache -EffectiveMode $EffectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Hostname $Hostname -Quiet:$Quiet
                        if ($fileResults) {
                            $results += $fileResults
                        }
                    }
                }
                catch { 
                    if (-not $Quiet) {
                        Write-Warning "Failed to process $filePath`: $($_.Exception.Message)"
                    }
                    continue 
                }
            }
        }
        catch { }
    
        return $results
    }

    function Process-SingleBrowserFile {
        param(
            [string]$FilePath,
            [string]$BrowserName,
            [string]$UserName,
            [string]$OutputDir,
            [string]$Timestamp,
            [string]$Hostname,
            [switch]$Cache,
            [string]$EffectiveMode,
            [string[]]$Search,
            [string[]]$Exclude,
            [int]$Truncate,
            [switch]$Quiet
        )
    
        # Validate file path
        try {
            $FilePath = [System.IO.Path]::GetFullPath($FilePath)
        }
        catch {
            return @()
        }
    
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
            if (-not $Quiet) {
                # Write-Host "[DEBUG] File not found: $FilePath" -ForegroundColor Red
            }
            return @()
        }
    
        if (-not $Quiet) {
            # Write-Host "[DEBUG] Processing file: $FilePath" -ForegroundColor Green
        }
    
        # Check file size to prevent memory issues
        try {
            $fileInfo = Get-Item $FilePath -ErrorAction Stop
            if (-not $Quiet) {
                # Write-Host "[DEBUG] File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Cyan
            }
        
            if ($fileInfo.Length -gt 100MB) {
                if (-not $Quiet) {
                    Write-Warning "Skipping large file (>100MB): $FilePath"
                }
                return @()
            }
        
            if ($fileInfo.Length -eq 0) {
                if (-not $Quiet) {
                    # Write-Host "[DEBUG] Empty file, skipping: $FilePath" -ForegroundColor Yellow
                }
                return @()
            }
        }
        catch {
            return @()
        }
    
        try {
            # Handle Cache mode
            if ($Cache) {
                try {
                    $sanitizedUser = $UserName -replace '[^\w\-]', '_'
                    $sanitizedBrowser = $BrowserName -replace '[^\w\-]', '_'
                    $cacheFile = Join-Path $OutputDir "$Timestamp-$sanitizedUser-$sanitizedBrowser-CACHE.txt"
                
                    # Ensure cache file path is safe
                    $cacheFile = [System.IO.Path]::GetFullPath($cacheFile)
                
                    Copy-Item $FilePath $cacheFile -Force -ErrorAction Stop
                    $script:AllFilesToCleanup += $cacheFile
                    Set-Variable -Name "Cache_$($UserName)_$BrowserName" -Value $cacheFile -Scope Script -ErrorAction SilentlyContinue
                
                    if (-not $Quiet) {
                        Write-Host "[CACHE] $BrowserName for $UserName cached" -ForegroundColor Cyan
                    }
                    return @()
                }
                catch {
                    return @()
                }
            }
        
            # Get source file
            $sourceFile = Get-CachedPath -UserName $UserName -BrowserName $BrowserName
            if (-not $sourceFile -or -not (Test-Path $sourceFile -ErrorAction SilentlyContinue)) {
                $tempFile = Join-Path $env:TEMP "browser_temp_$([guid]::NewGuid())"
                try {
                    Copy-Item $FilePath $tempFile -Force -ErrorAction Stop
                    $script:AllFilesToCleanup += $tempFile
                    $sourceFile = $tempFile
                }
                catch {
                    return @()
                }
            }
        
            # Extract and filter strings

            try {
                if (-not $Quiet) {
                    # Write-Host "[DEBUG] Extracting strings from: $sourceFile" -ForegroundColor Magenta
        
                    # Check if file is readable
                    $testBytes = [System.IO.File]::ReadAllBytes($sourceFile)
                    # Write-Host "[DEBUG] Successfully read $($testBytes.Length) bytes" -ForegroundColor Cyan
        
                    # Show first 100 bytes as hex to see if it's a valid file
                    $hexSample = ($testBytes[0..99] | ForEach-Object { $_.ToString("X2") }) -join " "
                    # Write-Host "[DEBUG] First 100 bytes (hex): $($hexSample.Substring(0, [Math]::Min(50, $hexSample.Length)))..." -ForegroundColor Gray
                }
    
                $strings = Extract-CleanStrings -FilePath $sourceFile
    
                if (-not $Quiet) {
                    # Write-Host "[DEBUG] Extracted $($strings.Count) raw strings" -ForegroundColor Cyan
                    if ($strings.Count -gt 0) {
                        # Write-Host "[DEBUG] Sample strings:" -ForegroundColor Yellow
                        #$strings[0..4] | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
                    }
                }
    
                if ($strings) {
                    $filtered = Filter-Strings -Strings $strings -UserName $UserName -BrowserName $BrowserName -EffectiveMode $EffectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Source "Browser" -Hostname $Hostname
        
                    if (-not $Quiet) {
                        # Write-Host "[DEBUG] Filtered to $($filtered.Count) matching strings" -ForegroundColor Green
                    }
        
                    return $filtered
                }
            }
            catch {
                if (-not $Quiet) {
                    # Write-Host "[DEBUG] String extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        
        }
        catch {
            if (-not $Quiet) {
                # Write-Host "[DEBUG] Processing failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    
        return @()
    }

    function Extract-CleanStrings {
        param([string]$FilePath)
    
        try {
            # Read file as bytes
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            if (-not $bytes -or $bytes.Length -eq 0) { return @() }
    
            # Convert to string and find printable ASCII strings
            $content = [System.Text.Encoding]::ASCII.GetString($bytes)
            if (-not $content) { return @() }
        
            # Use a simpler regex to find strings of printable characters
            $stringMatches = [regex]::Matches($content, '[ -~]{4,1000}')
        
            $cleanedStrings = @()
            $seen = @{}
        
            foreach ($match in $stringMatches) {
                $rawString = $match.Value.Trim()
                if ($rawString.Length -ge 4 -and -not $seen.ContainsKey($rawString)) {
                    $seen[$rawString] = $true
                
                    # Basic cleaning
                    $cleanString = $rawString -replace '[\x00-\x1F\x7F]+', ' '
                    $cleanString = $cleanString.Trim()
                    if ([string]::IsNullOrWhiteSpace($cleanString)) { continue }

                
                    if ($cleanString.Length -ge 4) {
                        $cleanedStrings += $cleanString
                    }
                }
            
                # Limit to prevent memory issues
                if ($cleanedStrings.Count -gt 5000) {
                    break
                }
            }
        
            return $cleanedStrings
        }
        catch {
            return @()
        }
    }

    function Filter-Strings {
        param(
            [array]$Strings,
            [string]$UserName,
            [string]$BrowserName,
            [string]$EffectiveMode,
            [string[]]$Search,
            [string[]]$Exclude,
            [int]$Truncate,
            [string]$Source = "Browser",
            [string]$Hostname
        )
    
        $results = @()
        
        if (-not $Strings -or $Strings.Count -eq 0) {
            return @()
        }

        foreach ($string in $Strings) {
            try {
                $match = $null
                $shouldInclude = $false
            
                # Apply Search/Exclude filters first if they exist
                if ($null -ne $Search -and $Search.Count -gt 0) {
                    $shouldInclude = $false
                    foreach ($includePattern in $Search) {
                        try {
                            if ($string -like "*$includePattern*") {
                                $shouldInclude = $true
                                $match = $includePattern
                                break
                            }
                        }
                        catch { continue }
                    }
                    # If we have Search filters but nothing matched, skip this string
                    if (-not $shouldInclude) {
                        continue
                    }
                }
                else {
                    # No Search filters, so Search by default
                    $shouldInclude = $true
                }
            
                # Apply exclude filters
                if ($shouldInclude -and $Exclude.Count -gt 0) {
                    foreach ($excludePattern in $Exclude) {
                        try {
                            if ($string -like "*$excludePattern*") {
                                $shouldInclude = $false
                                break
                            }
                        }
                        catch { continue }
                    }
                }
            
                # If we failed Search/exclude filters, skip
                if (-not $shouldInclude) {
                    continue
                }
            
                # Test for network indicators (always flag IPs and URLs)
                if (-not $match) {
                    try {
                        $networkIndicator = Test-NetworkIndicators -InputString $string
                        if ($networkIndicator) {
                            $match = "Network Indicator"
                        }
                    }
                    catch { }
                }
            
                # Test for filesystem paths (always flag)
                if (-not $match) {
                    try {
                        $filesystemPath = Test-FilesystemPaths -InputString $string
                        if ($filesystemPath) {
                            $match = "Filesystem Path"
                        }
                    }
                    catch { }
                }
            
                # Apply mode-based filtering
                if (-not $match) {
                    switch ($EffectiveMode) {
                        "All" {
                            # In All mode, Search everything that passed Search/exclude filters
                            $match = "All strings mode"
                        }
                        "Auto" {
                            # Check suspicious strings
                            foreach ($pattern in $script:suspiciousBrowserStrings) {
                                try {
                                    if ($string -like "*$pattern*") {
                                        $match = $pattern
                                        break
                                    }
                                }
                                catch { continue }
                            }
                            # Check suspicious TLDs
                            if (-not $match) {
                                foreach ($tld in $script:suspiciousTLDs) {
                                    try {
                                        if ($string -like "*$tld*") {
                                            $match = $tld
                                            break
                                        }
                                    }
                                    catch { continue }
                                }
                            }
                        }
                        "Aggressive" {
                            # Check aggressive strings
                            foreach ($pattern in $script:aggressiveBrowserStrings) {
                                try {
                                    if ($string -like "*$pattern*") {
                                        $match = $pattern
                                        break
                                    }
                                }
                                catch { continue }
                            }
                            # Also Search Auto mode patterns
                            if (-not $match) {
                                foreach ($pattern in $script:suspiciousBrowserStrings) {
                                    try {
                                        if ($string -like "*$pattern*") {
                                            $match = $pattern
                                            break
                                        }
                                    }
                                    catch { continue }
                                }
                            }
                            # Check suspicious TLDs
                            if (-not $match) {
                                foreach ($tld in $script:suspiciousTLDs) {
                                    try {
                                        if ($string -like "*$tld*") {
                                            $match = $tld
                                            break
                                        }
                                    }
                                    catch { continue }
                                }
                            }
                        }
                    }
                }
            
                # If we have a match, add the result
                if ($match) {
                    try {
                        $displayString = $string
                        if ($Truncate -gt 0 -and $string.Length -gt $Truncate) {
                            $displayString = $string.Substring(0, $Truncate) + "..."
                        }
                    
                        $results += [PSCustomObject]@{
                            User         = $UserName
                            Browser      = $BrowserName
                            String       = $displayString
                            FullString   = $string
                            MatchPattern = $match
                            Length       = $string.Length
                            Source       = $Source
                            Hostname     = $Hostname
                        }
                    }
                    catch {
                        continue
                    }
                }
            }
            catch {
                continue
            }
        }
    
        return $results
    }

    function Process-DNSLogs {
        param(
            [string]$EffectiveMode,
            [string[]]$Search,
            [string[]]$Exclude,
            [int]$Truncate,
            [string]$Hostname,
            [switch]$Quiet
        )
    
        $results = @()
        $dnsLogPaths = @(
            "$env:SystemRoot\System32\dns\dns.log",
            "$env:SystemRoot\System32\LogFiles\dns\dns.log",
            "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx"
        )
    
        foreach ($logPath in $dnsLogPaths) {
            try {
                # Validate path
                try {
                    $logPath = [System.IO.Path]::GetFullPath($logPath)
                }
                catch {
                    continue
                }
            
                if (Test-Path $logPath -ErrorAction SilentlyContinue) {
                    if (-not $Quiet) {
                        Write-Host "[DNS] Processing: $logPath" -ForegroundColor Cyan
                    }
                
                    if ($logPath -like "*.evtx") {
                        try {
                            $events = Get-WinEvent -Path $logPath -ErrorAction Stop | 
                            Where-Object { $_.Id -eq 3008 -or $_.Id -eq 3010 } | 
                            Select-Object -First 1000
                        
                            foreach ($event in $events) {
                                try {
                                    $dnsStrings = @(Sanitize-Output $event.Message)
                                    $filteredResults = Filter-Strings -Strings $dnsStrings -UserName "System" -BrowserName "DNS" -EffectiveMode $EffectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Source "DNS" -Hostname $Hostname
                                    if ($filteredResults) {
                                        $results += $filteredResults
                                    }
                                }
                                catch { continue }
                            }
                        }
                        catch { }
                    }
                    else {
                        try {
                            $dnsStrings = Get-Content $logPath -ErrorAction Stop | 
                            Select-Object -First 1000 | 
                            ForEach-Object { Sanitize-Output $_ }
                        
                            $filteredResults = Filter-Strings -Strings $dnsStrings -UserName "System" -BrowserName "DNS" -EffectiveMode $EffectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Source "DNS" -Hostname $Hostname
                            if ($filteredResults) {
                                $results += $filteredResults
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    
        return $results
    }

    function Invoke-FetchToolsMode {
        param(
            [string]$OutputPath,
            [string]$Hostname,
            [switch]$Quiet,
            [switch]$SkipConfirmation
        )
    
        if (-not $Quiet) {
            Write-Host "[TOOL] Initializing FetchTools mode..." -ForegroundColor Cyan
        }
    
        # Security confirmation for third-party executable download
        if (-not $SkipConfirmation) {
            Write-Host ""
            Write-Host "[ CONFIRMATION REQUIRED ]" -ForegroundColor Red
            Write-Host ""
            Write-Host "FetchTools mode requires downloading a third-party executable:" -ForegroundColor White
            Write-Host "  Tool: BrowsingHistoryView by NirSoft" -ForegroundColor White
            Write-Host "  URL:  https://www.nirsoft.net/utils/browsinghistoryview.zip" -ForegroundColor White
            Write-Host "  Info: https://www.nirsoft.net/utils/browsing_history_view.html" -ForegroundColor White
            Write-Host ""
            Write-Host "This tool will be downloaded, extracted, and executed to extract" -ForegroundColor White
            Write-Host "browser history data from your system." -ForegroundColor White
            Write-Host ""
            Write-Host "NirSoft is a well-known developer of Windows utilities, but you" -ForegroundColor White
            Write-Host "should verify this yourself before proceeding." -ForegroundColor White
            Write-Host ""
            Write-Host "Alternative: Use built-in Hunt-Browser modes (-Auto, -All, -Aggressive)" -ForegroundColor DarkGray
            Write-Host "or skip this confirmation with -SkipConfirmation parameter." -ForegroundColor DarkGray
            Write-Host ""
        
            do {
                $confirmation = Read-Host "Do you want to download and execute this third-party tool? (Y/N)"
                $confirmation = $confirmation.Trim().ToUpper()
            
                if ($confirmation -eq 'N' -or $confirmation -eq 'NO') {
                    Write-Host ""
                    Write-Host "[CANCELLED] FetchTools mode cancelled by user." -ForegroundColor Yellow
                    Write-Host "Consider using built-in modes: Hunt-Browser -Auto or Hunt-Browser -All" -ForegroundColor Cyan
                    return @()
                }
                elseif ($confirmation -eq 'Y' -or $confirmation -eq 'YES') {
                    Write-Host ""
                    Write-Host "[CONFIRMED] User confirmed download. Proceeding..." -ForegroundColor Green
                    break
                }
                else {
                    Write-Host "Please enter Y (yes) or N (no)." -ForegroundColor Red
                }
            } while ($true)
        }
    
        # Determine output CSV path safely
        $outputCsv = ""
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $outputCsv = Join-Path $env:TEMP "BrowsingHistory_$([guid]::NewGuid()).csv"
        }
        elseif (Test-Path $OutputPath -PathType Container -ErrorAction SilentlyContinue) {
            $outputCsv = Join-Path $OutputPath "BrowsingHistory_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        }
        elseif ($OutputPath -match '\.csv$') {
            $outputCsv = $OutputPath
        }
        else {
            $outputCsv = $OutputPath + ".csv"
        }
    
        # Sanitize and resolve output path
        try {
            $outputCsv = Resolve-SafePath -Path $outputCsv -AllowNew -Extension ".csv"
        }
        catch {
            Write-Error "Invalid output path specified"
            return @()
        }
    
        # Ensure output directory exists
        try {
            $outputDir = Split-Path $outputCsv -Parent
            if (-not (Test-Path $outputDir -ErrorAction SilentlyContinue)) {
                New-Item -Path $outputDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            $script:PersistentFiles += $outputCsv
        }
        catch {
            Write-Error "Failed to create output directory for CSV: $($_.Exception.Message)"
            return @()
        }
    
        $tempDir = Join-Path -Path $env:TEMP -ChildPath ("Hunt-Browser-Tools-" + [guid]::NewGuid().ToString())
        $script:AllFilesToCleanup += $tempDir
    
        try {
            New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        
            # Download and extract BrowsingHistoryView
            $downloadUrl = "https://www.nirsoft.net/utils/browsinghistoryview.zip"
            $infoUrl = "https://www.nirsoft.net/utils/browsing_history_view.html"
            $zipPath = Join-Path -Path $tempDir -ChildPath "browsinghistoryview.zip"
        
            if (-not $Quiet) {
                Write-Host "[DOWNLOAD] Downloading BrowsingHistoryView from NirSoft..." -ForegroundColor Yellow
                Write-Host "[SOURCE]   Download URL: $downloadUrl" -ForegroundColor Gray
                Write-Host "[INFO]     Tool info: $infoUrl" -ForegroundColor Gray
                Write-Host "[STATUS]   Initiating secure download..." -ForegroundColor Cyan
            }
        
            try {
                # Use TLS 1.2 for security
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
            
                if (-not $Quiet) {
                    $fileSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 2)
                    Write-Host "[SUCCESS]  Downloaded $fileSize KB successfully" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to download BrowsingHistoryView: $($_.Exception.Message)"
                Write-Host "[HELP]     Check network connection and try again, or use built-in modes" -ForegroundColor Yellow
                return @()
            }
        
            if (-not $Quiet) {
                Write-Host "[EXTRACT]  Extracting archive..." -ForegroundColor Cyan
            }
        
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempDir)
            
                if (-not $Quiet) {
                    Write-Host "[SUCCESS]  Archive extracted successfully" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to extract BrowsingHistoryView: $($_.Exception.Message)"
                return @()
            }
        
            $exePath = Join-Path -Path $tempDir -ChildPath "BrowsingHistoryView.exe"
        
            if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                try {
                    # Sanitize arguments to prevent command injection
                    $safeOutputPath = "`"$outputCsv`""
                    $arguments = @("/HistorySource", "1", "/VisitTimeFilterType", "1", "/SaveDirect", "/scomma", $safeOutputPath)
                
                    if (-not $Quiet) {
                        Write-Host "[EXEC]     Executing BrowsingHistoryView..." -ForegroundColor Green
                        Write-Host "[OUTPUT]   Results will be saved to: $outputCsv" -ForegroundColor Cyan
                    }
                
                    $proc = Start-Process -FilePath $exePath -ArgumentList $arguments -Wait -PassThru -NoNewWindow -ErrorAction Stop
                
                    if ($proc.ExitCode -eq 0 -and (Test-Path $outputCsv -ErrorAction SilentlyContinue)) {
                        try {
                            $csvData = Import-Csv $outputCsv -ErrorAction Stop
                        
                            # Convert to standardized objects with sanitization
                            $currentUser = if ($env:USERNAME) { $env:USERNAME } else { "Unknown" }
                            $results = $csvData | ForEach-Object {
                                [PSCustomObject]@{
                                    User         = Sanitize-Output $currentUser
                                    Browser      = Sanitize-Output ($_.WebBrowser -replace '\s+', ' ')
                                    String       = Sanitize-Output ($_.URL)
                                    FullString   = Sanitize-Output ($_.URL)
                                    MatchPattern = "FetchTools"
                                    Length       = if ($_.URL) { ($_.URL -replace '[^\w]', '').Length } else { 0 }
                                    Source       = "FetchTools"
                                    Hostname     = Sanitize-Output $Hostname
                                    Count        = 1
                                    Title        = Sanitize-Output ($_.Title)
                                    VisitTime    = Sanitize-Output ($_.VisitTime)
                                }
                            }
                        
                            if (-not $Quiet) {
                                Write-Host "[SUCCESS]  Extracted $($results.Count) browser history entries" -ForegroundColor Green
                                Write-Host "[SAVED]    CSV file preserved at: $outputCsv" -ForegroundColor Green
                            }
                        
                            return $results
                        }
                        catch {
                            if (-not $Quiet) {
                                Write-Host "[SAVED]    CSV file preserved at: $outputCsv" -ForegroundColor Green
                            }
                            return @()
                        }
                    }
                    else {
                        Write-Error "BrowsingHistoryView failed to generate output (Exit Code: $($proc.ExitCode))"
                        return @()
                    }
                }
                catch {
                    Write-Error "Failed to execute BrowsingHistoryView: $($_.Exception.Message)"
                    return @()
                }
            }
            else {
                Write-Error "BrowsingHistoryView.exe not found after extraction"
                return @()
            }
        
        }
        catch {
            Write-Error "FetchTools mode failed: $($_.Exception.Message)"
            return @()
        }
    }

    # Keep all other existing functions (Get-InstalledBrowsers, Get-UserProfiles, etc.) unchanged
    # but add the missing functions referenced above:

    function Get-InstalledBrowsers {
        $browsers = @()
    
        # Comprehensive browser definitions
        $browserDefinitions = @(
            # Chrome variants
            @{ Name = "Chrome"; Path = "\Google\Chrome\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Chrome Beta"; Path = "\Google\Chrome Beta\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Chrome Dev"; Path = "\Google\Chrome Dev\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Chrome Canary"; Path = "\Google\Chrome SxS\User Data\Default\History"; Type = "Chromium" },
        
            # Edge variants
            @{ Name = "Edge"; Path = "\Microsoft\Edge\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Edge Beta"; Path = "\Microsoft\Edge Beta\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Edge Dev"; Path = "\Microsoft\Edge Dev\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Edge Canary"; Path = "\Microsoft\Edge SxS\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Edge Legacy"; Path = "\Microsoft\Windows\WebCache\WebCacheV*.dat"; Type = "Edge" },
        
            # Firefox variants
            @{ Name = "Firefox"; Path = "\Mozilla\Firefox\Profiles\*\places.sqlite"; Type = "Firefox" },
            @{ Name = "Firefox ESR"; Path = "\Mozilla\Firefox\Profiles\*\places.sqlite"; Type = "Firefox" },
            @{ Name = "Firefox Developer"; Path = "\Mozilla\Firefox\Profiles\*\places.sqlite"; Type = "Firefox" },
        
            # Other browsers
            @{ Name = "Opera"; Path = "\Opera Software\Opera Stable\History"; Type = "Chromium" },
            @{ Name = "Opera GX"; Path = "\Opera Software\Opera GX Stable\History"; Type = "Chromium" },
            @{ Name = "Brave"; Path = "\BraveSoftware\Brave-Browser\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Vivaldi"; Path = "\Vivaldi\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Yandex"; Path = "\Yandex\YandexBrowser\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Tor Browser"; Path = "\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\places.sqlite"; Type = "Firefox" },
            @{ Name = "Waterfox"; Path = "\Waterfox\Profiles\*\places.sqlite"; Type = "Firefox" },
            @{ Name = "Pale Moon"; Path = "\Moonchild Productions\Pale Moon\Profiles\*\places.sqlite"; Type = "Firefox" },
            @{ Name = "SeaMonkey"; Path = "\Mozilla\SeaMonkey\Profiles\*\places.sqlite"; Type = "Firefox" },
            @{ Name = "Maxthon"; Path = "\Maxthon5\Users\*\History"; Type = "Chromium" },
            @{ Name = "UC Browser"; Path = "\UCBrowser\User Data\Default\History"; Type = "Chromium" },
            @{ Name = "Comodo Dragon"; Path = "\Comodo\Dragon\User Data\Default\History"; Type = "Chromium" }
        )
    
        # Test all browsers against all user profiles
        $userProfiles = Get-UserProfiles
        foreach ($browser in $browserDefinitions) {
            $found = $false
            foreach ($userProfile in $userProfiles) {
                try {
                    $testPath = if ($browser.Type -eq "Firefox") {
                        Join-Path $userProfile "AppData\Roaming$($browser.Path)"
                    }
                    else {
                        Join-Path $userProfile "AppData\Local$($browser.Path)"
                    }
                
                    $testPath = [System.IO.Path]::GetFullPath($testPath)
                
                    # Check if browser data exists for this user
                    if ($browser.Type -eq "Firefox" -or $browser.Path -like "*\*\*") {
                        # For Firefox and wildcard paths, check parent directory
                        $parentDir = Split-Path $testPath -Parent
                        if (Test-Path $parentDir -ErrorAction SilentlyContinue) {
                            $found = $true
                            break
                        }
                    }
                    else {
                        # For specific files, check file or parent directory
                        if ((Test-Path $testPath -ErrorAction SilentlyContinue) -or 
                            (Test-Path (Split-Path $testPath -Parent) -ErrorAction SilentlyContinue)) {
                            $found = $true
                            break
                        }
                    }
                }
                catch { continue }
            }
        
            if ($found) {
                $browsers += $browser
            }
        }
    
        return $browsers
    }

    function Get-UserProfiles {
        $profiles = @()
    
        try {
            # Method 1: Direct enumeration of C:\Users (most reliable)
            if (Test-Path "C:\Users" -ErrorAction SilentlyContinue) {
                $userDirs = Get-ChildItem "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.Name -notin @("Default", "Public", "All Users", "Default User") -and
                    $_.Name -notlike ".*" -and
                    $_.FullName -and
                    (Test-Path (Join-Path $_.FullName "AppData") -ErrorAction SilentlyContinue)
                }
            
                foreach ($dir in $userDirs) {
                    if ($dir.FullName -and (Test-Path $dir.FullName -ErrorAction SilentlyContinue)) {
                        $profiles += $dir.FullName
                    }
                }
            }
        
            # Method 2: Current user (always Search)
            if ($env:USERPROFILE -and (Test-Path $env:USERPROFILE -ErrorAction SilentlyContinue)) {
                if ($profiles -notcontains $env:USERPROFILE) {
                    $profiles += $env:USERPROFILE
                }
            }
        
            # Method 3: WMI as backup
            try {
                $wmiProfiles = Get-WmiObject -Class Win32_UserProfile -ErrorAction SilentlyContinue | 
                Where-Object {
                    $_.LocalPath -and
                    $_.LocalPath -like "C:\Users\*" -and
                    $_.LocalPath -notlike "*\Default*" -and
                    $_.LocalPath -notlike "*\Public*" -and
                    (Test-Path $_.LocalPath -ErrorAction SilentlyContinue)
                } | Select-Object -ExpandProperty LocalPath
            
                foreach ($profile in $wmiProfiles) {
                    if ($profile -and $profiles -notcontains $profile) {
                        $profiles += $profile
                    }
                }
            }
            catch { }
        
            # Filter and validate all profiles
            $validProfiles = @()
            foreach ($profile in $profiles) {
                if ($profile -and (Test-Path $profile -ErrorAction SilentlyContinue)) {
                    $validProfiles += $profile
                }
            }
        
            return ($validProfiles | Sort-Object -Unique)
        }
        catch {
            # Absolute fallback
            if ($env:USERPROFILE) {
                return @($env:USERPROFILE)
            }
            else {
                return @()
            }
        }
    }

    function Test-NetworkIndicators {
        param([Parameter(Mandatory = $true)][string]$InputString)

        if ([string]::IsNullOrWhiteSpace($InputString)) { return $null }

        try {
            $cleanString = $InputString.Trim()
        
            # Check for IP addresses first (higher priority)
            # IPv4 - enhanced validation
            if ($cleanString -match '\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b') {
                # Additional validation - exclude obviously invalid IPs
                if ($cleanString -notmatch '^0\.0\.0\.0$|^255\.255\.255\.255$') {
                    return Sanitize-Output $cleanString
                }
            }
        
            # IPv6 - basic validation
            if ($cleanString -match '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}') {
                return Sanitize-Output $cleanString
            }

            # URL detection with validation - more permissive
            if ($cleanString -match '\b(?:https?|ftp|ftps)://[^\s<>"\\]{2,2000}\b') {
                return Sanitize-Output $cleanString
            }
        
            # Domain detection with enhanced validation - more permissive
            foreach ($tld in $script:PossibleTLDs) {
                if ($cleanString -like "*$tld*" -and $cleanString -match '\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b') {
                    $matches = [regex]::Matches($cleanString, '\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b')
                    foreach ($match in $matches) {
                        $domain = $match.Value
                        $parts = $domain.Split('.')
                    
                        if ($parts.Count -ge 2 -and $domain.Length -ge 4 -and $domain.Length -lt 255 -and -not ($domain -match '^\d+\.\d+')) {
                            if ($domain -like "*$tld*") {
                                return Sanitize-Output $domain
                            }
                        }
                    }
                }
            }

            return $null
        }
        catch {
            return $null
        }
    }

    function Test-FilesystemPaths {
        param([Parameter(Mandatory = $true)][string]$InputString)

        if ([string]::IsNullOrWhiteSpace($InputString)) { return $null }

        try {
            $cleanString = $InputString.Trim().Trim('"', "'", '(', ')', '[', ']')
        
            if ($cleanString.Length -lt 3 -or $cleanString.Length -gt 32767) { return $null }
        
            # Exclude patterns that aren't filesystem paths - more permissive
            $excludePatterns = @(
                '^\d+\.\d+\.\d+\.\d+',  # IP addresses
                '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Simple domains only
                '@'  # Email addresses
            )
        
            foreach ($pattern in $excludePatterns) {
                if ($cleanString -match $pattern) {
                    return $null
                }
            }
        
            # Windows paths with validation - more permissive
            if ($cleanString -match '\b[A-Za-z]:\\') {
                # Look for drive letter pattern anywhere in string
                if ($cleanString -notmatch '\.\.' -and $cleanString.Length -gt 3) {
                    return Sanitize-Output $cleanString
                }
            }
        
            # UNC paths with validation - more permissive
            if ($cleanString -match '\\\\[^\\]{2,}\\[^\\]{1,}' -and $cleanString -notmatch '\.\.') {
                return Sanitize-Output $cleanString
            }
        
            # Registry paths - more permissive
            if ($cleanString -match '\bHKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\') {
                return Sanitize-Output $cleanString
            }
        
            # Executable patterns - more permissive
            if ($cleanString -match '\.(exe|bat|cmd|ps1|vbs|scr|com|pif|dll|sys|msi)' -and 
                ($cleanString -match '\\' -or $cleanString -match '/') -and 
                $cleanString -notmatch '\.\.' -and
                $cleanString.Length -gt 5) {
                return Sanitize-Output $cleanString
            }
        
            # Unix paths with validation - more permissive
            if ($cleanString -match '\b/[^/\s]+/[^/\s]+' -and 
                $cleanString -notmatch '\.\.' -and
                $cleanString.Length -gt 3) {
                return Sanitize-Output $cleanString
            }
        
            return $null
        }
        catch {
            return $null
        }
    }

    function Get-CachedPath {
        param([string]$UserName, [string]$BrowserName)
        try {
            return Get-Variable -Name "Cache_$($UserName)_$BrowserName" -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        }
        catch {
            return $null
        }
    }

    function Get-UniqueResults {
        param([array]$Results)
    
        try {
            if (-not $Results -or $Results.Count -eq 0) {
                return @()
            }
        
            $uniqueResults = @()
            $stringCounts = @{}
        
            # Group by full string content
            foreach ($result in $Results) {
                try {
                    $key = $result.FullString
                    if ($stringCounts.ContainsKey($key)) {
                        $stringCounts[$key].Count++
                    }
                    else {
                        $stringCounts[$key] = @{
                            Count  = 1
                            Result = $result
                        }
                    }
                }
                catch {
                    continue
                }
            }
        
            # Create unique results with counts
            foreach ($key in $stringCounts.Keys) {
                try {
                    $item = $stringCounts[$key]
                    $uniqueResult = $item.Result.PSObject.Copy()
                    $uniqueResult | Add-Member -MemberType NoteProperty -Name "Count" -Value $item.Count -Force
                    $uniqueResults += $uniqueResult
                }
                catch {
                    continue
                }
            }
        
            return $uniqueResults | Sort-Object Count -Descending
        }
        catch {
            return @()
        }
    }

    function Write-ColoredBrowserResult {
        param($BrowserResult)
    
        try {
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor Gray
            Write-Host "User             : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.User -ForegroundColor DarkYellow
        
            Write-Host "Source           : " -NoNewline -ForegroundColor Yellow
            Write-Host "$($BrowserResult.Source) ($($BrowserResult.Browser))" -ForegroundColor White

            Write-Host "String           : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.String -ForegroundColor Cyan
        
            Write-Host "Match            : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.MatchPattern -ForegroundColor Red
        
            Write-Host "Length           : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.Length -ForegroundColor DarkGray

            Write-Host "Hostname         : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.Hostname -ForegroundColor DarkGray
        
            Write-Host "Count            : " -NoNewline -ForegroundColor Yellow
            Write-Host $BrowserResult.Count -ForegroundColor DarkGray
        }
        catch { }
    }


    function Complete-Cleanup {
        param([switch]$Quiet)
    
        $cleanupReport = @{
            FilesRemoved        = @()
            FilesSkipped        = @()
            DirectoriesRemoved  = @()
            DirectoriesSkipped  = @()
            PersistentFilesKept = @()
            Errors              = @()
        }
    
        try {
            # Remove all tracked files (except persistent ones)
            foreach ($file in $script:AllFilesToCleanup) {
                try {
                    if ($file -in $script:PersistentFiles) {
                        $cleanupReport.PersistentFilesKept += $file
                        continue
                    }
                
                    if (Test-Path $file -ErrorAction SilentlyContinue) {
                        if (Test-Path $file -PathType Container) {
                            # It's a directory - use -Recurse and -Force
                            Remove-Item $file -Recurse -Force -ErrorAction Stop
                            $cleanupReport.DirectoriesRemoved += $file
                        }
                        else {
                            # It's a file
                            Remove-Item $file -Force -ErrorAction Stop
                            $cleanupReport.FilesRemoved += $file
                        }
                    }
                    else {
                        $cleanupReport.FilesSkipped += "$file (not found)"
                    }
                }
                catch {
                    $cleanupReport.Errors += "Failed to remove $file`: $($_.Exception.Message)"
                }
            }
        
            # Remove created directories if empty (check this after file cleanup)
            foreach ($dir in $script:CreatedDirectories) {
                try {
                    if (Test-Path $dir -ErrorAction SilentlyContinue) {
                        $items = Get-ChildItem $dir -Force -ErrorAction SilentlyContinue
                        $containsPersistent = $false
                        foreach ($item in $items) {
                            if ($item.FullName -in $script:PersistentFiles) {
                                $containsPersistent = $true
                                break
                            }
                        }
                        if (-not $items -or -not $containsPersistent) {
                            Remove-Item $dir -Recurse -Force -ErrorAction Stop
                            $cleanupReport.DirectoriesRemoved += $dir
                        }
                        else {
                            $cleanupReport.DirectoriesSkipped += "$dir (contains persistent files)"
                        }
                    }
                    else {
                        $cleanupReport.DirectoriesSkipped += "$dir (not found)"
                    }
                }
                catch {
                    $cleanupReport.Errors += "Failed to remove directory $dir`: $($_.Exception.Message)"
                }
            }
        
            # Display cleanup report
            if (-not $Quiet) {
                write-host""
                # if ($cleanupReport.FilesRemoved.Count -gt 0) {
                #     Write-Host "[REMOVED] $($cleanupReport.FilesRemoved.Count) temporary files:" -ForegroundColor Green
                #     $cleanupReport.FilesRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
                # }
            
                # if ($cleanupReport.DirectoriesRemoved.Count -gt 0) {
                #     Write-Host "[REMOVED] $($cleanupReport.DirectoriesRemoved.Count) temporary directories:" -ForegroundColor Green
                #     $cleanupReport.DirectoriesRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
                # }
            
                if ($cleanupReport.PersistentFilesKept.Count -gt 0) {
                    Write-Host "[KEPT] $($cleanupReport.PersistentFilesKept.Count) persistent files:" -ForegroundColor Yellow
                    $cleanupReport.PersistentFilesKept | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
                }
            
                if ($cleanupReport.FilesSkipped.Count -gt 0 -or $cleanupReport.DirectoriesSkipped.Count -gt 0) {
                    $skippedTotal = $cleanupReport.FilesSkipped.Count + $cleanupReport.DirectoriesSkipped.Count
                    Write-Host "[SKIPPED] $skippedTotal items already removed or not found:" -ForegroundColor DarkYellow
                    ($cleanupReport.FilesSkipped + $cleanupReport.DirectoriesSkipped) | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
                }
            
                if ($cleanupReport.Errors.Count -gt 0) {
                    Write-Host "[ERRORS] $($cleanupReport.Errors.Count) cleanup errors:" -ForegroundColor Red
                    $cleanupReport.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                }
            
                if ($cleanupReport.FilesRemoved.Count -eq 0 -and $cleanupReport.DirectoriesRemoved.Count -eq 0 -and $cleanupReport.Errors.Count -eq 0) {
                    Write-Host "[INFO] No temporary files to clean up" -ForegroundColor Green
                }
                else {
                    Write-Host "[COMPLETE] Cleanup finished successfully" -ForegroundColor Green
                }
            
            }
        
            $script:AllFilesToCleanup = @()
            $script:CreatedDirectories = @()
            write-host ""
            return $cleanupReport
        }
        catch {
            if (-not $Quiet) {
                Write-Host "[ERROR] Cleanup failed: $($_.Exception.Message)`n" -ForegroundColor Red
            }
            return $cleanupReport
        }
    }


    # Initialize progress tracking
    $progressId = Get-Random
    Write-Progress -Id $progressId -Activity "Hunt-Browser Analysis" -Status "Initializing..." -PercentComplete 0
    
    # Input validation and sanitization
    if ($null -ne $Search -and $Search.Count -gt 0) {
        $Search = $Search | ForEach-Object { Sanitize-SearchPattern $_ }
    }
    if ($null -ne $Exclude -and $Exclude.Count -gt 0) {
        $Exclude = $Exclude | ForEach-Object { Sanitize-SearchPattern $_ }
    }
    
    # Validate and sanitize paths
    $OutputDir = Resolve-SafePath -Path $OutputDir -DefaultPath "$env:TEMP\ForensicHunter\Hunt-Browser"
    if ($OutputCSV) {
        $OutputCSV = Resolve-SafePath -Path $OutputCSV -AllowNew -Extension ".csv"
    }
    if ($FetchTools) {
        $FetchTools = Resolve-SafePath -Path $FetchTools -AllowNew
    }
    
    # Determine mode logic
    $effectiveMode = $null
    $modeCount = @($Auto, $Aggressive, $All).Where({ $_ }).Count
    
    if ($modeCount -gt 1) {
        Write-Error "Cannot use multiple modes simultaneously. Choose only one: -Auto, -Aggressive, or -All"
        if ($PassThru) { return @() }
        return
    }
    
    if ($Search.Count -gt 0 -or $Exclude.Count -gt 0) {
        $effectiveMode = if ($modeCount -eq 0) { "All" } else {
            switch ($true) {
                $Auto { "Auto" }
                $Aggressive { "Aggressive" }
                $All { "All" }
            }
        }
    }
    elseif ($modeCount -eq 0 -and -not $Cache -and -not $FetchTools) {
        $effectiveMode = "Auto"
    }
    else {
        $effectiveMode = switch ($true) {
            $Auto { "Auto" }
            $Aggressive { "Aggressive" }
            $All { "All" }
            $Cache { "Cache" }
            default { "Auto" }
        }
    }
    
    if (-not $effectiveMode -and -not $Cache -and -not $FetchTools) {
        Write-Error "Unable to determine operation mode"
        if ($PassThru) { return @() }
        return
    }
    
    # Initialize cleanup tracking
    $script:AllFilesToCleanup = @()
    $script:CreatedDirectories = @()
    $script:PersistentFiles = @()
    $fullhostname = ([Net.Dns]::GetHostByName($env:computerName)).HostName
    $hostname = if ($fullhostname) { $fullhostname } else { "Unknown" }
    
    try {
        # Handle FetchTools mode
        if ($FetchTools) {
            $results = Invoke-FetchToolsMode -OutputPath $FetchTools -Hostname $hostname -Quiet:$Quiet -SkipConfirmation:$SkipConfirmation
            if ($OutputCSV) {
                Export-ResultsToCSV -Results $results -Path $OutputCSV -Quiet:$Quiet
            }
    
            # FetchTools mode always returns objects (legacy behavior)
            # But respect PassThru for consistency
            if ($PassThru) {
                return $results
            }
            return
        }
        
        # Create output directory safely
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        if (-not (Test-Path $OutputDir -ErrorAction SilentlyContinue)) {
            try {
                New-Item -Path $OutputDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                $script:CreatedDirectories += $OutputDir
            }
            catch {
                Write-Error "Failed to create output directory: $($_.Exception.Message)"
                if ($PassThru) { return @() }
                return
            }
        }
        
        # Auto-detect browsers
        try {
            $browsers = Get-InstalledBrowsers
            $userProfiles = Get-UserProfiles
            $allResults = @()

            if (-not $userProfiles -or $userProfiles.Count -eq 0) {
                throw "No user profiles found"
            }

            # Initialize progress tracking variables AFTER userProfiles is defined
            $totalUsers = $userProfiles.Count
            $currentUserIndex = 0
        }
        catch {
            if (-not $Quiet) {
                Write-Warning "Error detecting browsers: $($_.Exception.Message)"
            }
            if ($PassThru) { return @() }
            return
        }
        
        # Process browser histories
        foreach ($userProfile in $userProfiles) {
            $currentUserIndex++
            $percentComplete = [math]::Round(($currentUserIndex / $totalUsers) * 80, 0)
            Write-Progress -Id $progressId -Activity "Hunt-Browser Analysis" -Status "Processing user $currentUserIndex of $totalUsers" -PercentComplete $percentComplete
    
            try {
                # Extract username from profile path - handle different path formats
                $userName = "Unknown"
                if ($userProfile -and ![string]::IsNullOrWhiteSpace($userProfile)) {
                    try {
                        $leafName = Split-Path $userProfile.Trim() -Leaf
                        if (![string]::IsNullOrWhiteSpace($leafName)) {
                            $userName = $leafName
                        }
                    }
                    catch {
                        # If Split-Path fails, try manual extraction
                        if ($userProfile -like "*\*") {
                            $lastSlash = $userProfile.LastIndexOf('\')
                            if ($lastSlash -ge 0 -and $lastSlash -lt ($userProfile.Length - 1)) {
                                $userName = $userProfile.Substring($lastSlash + 1)
                            }
                        }
                    }
                }
        
                # Don't sanitize the username too aggressively
                if (![string]::IsNullOrWhiteSpace($userName)) {
                    $userName = $userName.Trim()
                }
                else {
                    $userName = "Unknown"
                }
        
                if (-not $Quiet) {
                    Write-Host "[USER] Processing: $userName" -ForegroundColor Yellow
                }

                foreach ($browser in $browsers) {
                    try {
                        $browserResults = Process-BrowserData -UserProfile $userProfile -UserName $userName -Browser $browser -OutputDir $OutputDir -Timestamp $timestamp -Cache:$Cache -EffectiveMode $effectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Hostname $hostname -Quiet:$Quiet
                
                        if ($browserResults) {
                            if (-not $Quiet) {
                                Write-Host "[FOUND] $($browserResults.Count) entries from $($browser.Name) for $userName" -ForegroundColor Green
                            }
                            $allResults += $browserResults
                        }
                    }
                    catch {
                        if (-not $Quiet) {
                            Write-Warning "Failed $($browser.Name) for $userName (Access Denied - Normal)"
                        }
                        continue
                    }
                }
            }
            catch {
                if (-not $Quiet) {
                    Write-Warning "Failed to process user profile: $userProfile (Access Denied - Normal)"
                }
                continue
            }
        }
        
        # Process DNS logs
        try {
            $dnsResults = Process-DNSLogs -EffectiveMode $effectiveMode -Include $Search -Exclude $Exclude -Truncate $Truncate -Hostname $hostname -Quiet:$Quiet
            if ($dnsResults) {
                $allResults += $dnsResults
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Warning "DNS processing failed: $($_.Exception.Message)"
            }
        }
        
        # Process and display results
        try {
            $uniqueResults = Get-UniqueResults -Results $allResults
            
            if ($uniqueResults -and $uniqueResults.Count -gt 0) {
                # Always show colored output unless -Quiet is specified
                if (-not $Quiet) {
                    Write-Host "[RESULTS] Found $($uniqueResults.Count) unique browser and DNS artifacts" -ForegroundColor Green
        
                    # Group and sort results: User -> Browser -> Count (highest first)
                    $groupedByUser = $uniqueResults | Group-Object User | Sort-Object Name
        
                    foreach ($userGroup in $groupedByUser) {
                        $groupedByBrowser = $userGroup.Group | Group-Object Browser | Sort-Object Name
            
                        foreach ($browserGroup in $groupedByBrowser) {
                            $sortedResults = $browserGroup.Group | Sort-Object Count -Descending
                
                            $sortedResults | ForEach-Object {
                                try {
                                    Write-ColoredBrowserResult $_
                                }
                                catch {
                                    Write-Warning "Failed to display result: $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
                
                # Export to CSV if requested
                if ($OutputCSV) {
                    Export-ResultsToCSV -Results $uniqueResults -Path $OutputCSV -Quiet:$Quiet
                }
                
                # Complete progress
                Write-Progress -Id $progressId -Activity "Hunt-Browser Analysis" -Status "Complete" -PercentComplete 100 -Completed
                
                # Return objects based on PassThru parameter
                if ($PassThru) {
                    return $uniqueResults
                }
            }
            else {
                if (-not $Quiet) {
                    Write-Host "`n[INFO] No matching browser or DNS activity detected" -ForegroundColor Green
                }
                
                # Complete progress
                Write-Progress -Id $progressId -Activity "Hunt-Browser Analysis" -Status "Complete - No Results" -PercentComplete 100 -Completed
                
                # Return empty array only if PassThru is specified
                if ($PassThru) {
                    return @()
                }
            }
        }
        catch {
            Write-Error "Failed to process results: $($_.Exception.Message)"
            if ($PassThru) {
                return @()
            }
        }
        
    }
    catch {
        Write-Error "Hunt-Browser failed: $($_.Exception.Message)"
        if ($PassThru) {
            return @()
        }
    }
    finally {
        if (-not $Cache) {
            try {
                Complete-Cleanup -Quiet:$Quiet | out-null
            }
            catch {
                if (-not $Quiet) {
                    Write-Warning "Cleanup failed: $($_.Exception.Message)"
                }
            }
        }
    }
}


Function Hunt-Files {
    <#
.SYNOPSIS
Hunt for files and directories on the filesystem based on multiple criteria including timestamps, content, hashes, Search, extensions, and file attributes.

.DESCRIPTION
Hunt-Files is a comprehensive DFIR tool for searching and analyzing files across Windows systems. It supports searching by creation/modification dates, file content, cryptographic hashes, filenames, extensions, alternate data streams, and special attributes like hidden or deleted files. Results can be exported to CSV for further analysis.

.PARAMETER StartDate
Start date for timestamp filtering. Accepts datetime objects, strings, or relative formats (e.g., "3D" for 3 days ago).

.PARAMETER EndDate
End date for timestamp filtering. Defaults to "Now". Accepts same formats as StartDate.

.PARAMETER Extensions
Array of file extensions to search for (e.g., @(".exe", ".dll", ".ps1")).

.PARAMETER Content
Array of content strings to search for within files and alternate data streams.

.PARAMETER Search
Array of filename patterns to search for. Supports wildcards (* and ?).

.PARAMETER Hashes
Array of file hashes (MD5, SHA1, SHA256) to search for.

.PARAMETER MaxSizeMB
Maximum file size in MB to process for content searching. Default is 30MB.

.PARAMETER Timezone
Target timezone for date conversions. Supports common abbreviations (UTC, EST, PST, etc.).

.PARAMETER Path
Specific path to search. If not specified, searches current drive or all drives with -AllDrives.

.PARAMETER AllDrives
Search all available drives instead of just the current drive.

.PARAMETER IncludeSystemFolders
Include Windows system folders (Windows, Program Files) in search.

.PARAMETER Hidden
Search for hidden files and folders.

.PARAMETER Recycled
Search in recycle bin folders.

.PARAMETER Streams
Search for files with alternate data streams (ADS).

.PARAMETER MaxPrint
Maximum characters to output to console. Use 0 for unlimited.

.PARAMETER Auto
Predefined search modes: 1=Recent executables (3 days), 2=Suspicious files (7 days), 3=Comprehensive (30 days).

.PARAMETER Type
Filter results by type: FILE/F for files only, DIR/DIRECTORY/D for directories only.

.PARAMETER VerboseOutput
Show detailed error messages during processing.

.PARAMETER Aggressive
Enable more thorough searching with relaxed date requirements.

.PARAMETER OutputCSV
Export results to CSV file. Can specify file path or directory (auto-generates filename).

.PARAMETER PassThru
Return PowerShell objects instead of just displaying results.

.PARAMETER Quiet
Suppress console output (useful with -PassThru and -OutputCSV).

.EXAMPLE
Hunt-Files -Search @("malware", "*.exe") -StartDate "2024-01-01"
Search for files containing "malware" in name or with .exe extension since January 1, 2024.

.EXAMPLE
Hunt-Files -Content @("password", "secret") -Hidden -OutputCSV "C:\investigation"
Search hidden files containing "password" or "secret" and export to CSV.

.EXAMPLE
Hunt-Files -Auto 2 -AllDrives -OutputCSV "results.csv" -PassThru | Where-Object {$_.SizeMB -gt 10}
Run predefined suspicious file search across all drives, export to CSV, and return objects for files larger than 10MB.

.EXAMPLE
Hunt-Files -Hashes @("d41d8cd98f00b204e9800998ecf8427e") -Streams -Quiet -PassThru
Silently search for specific hash and files with alternate data streams, returning objects only.

.NOTES
Requires PowerShell 5.0 or later. Administrator privileges recommended for complete filesystem access and system folder searches.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        $StartDate,
    
        [Parameter(Mandatory = $false)]
        $EndDate = "Now",
    
        [Parameter(Mandatory = $false)]
        [string[]]$Extensions = @(),
    
        [Parameter(Mandatory = $false)]
        [string[]]$Content = @(),
    
        [Parameter(Mandatory = $false)]
        [string[]]$Search = @(),
    
        [Parameter(Mandatory = $false)]
        [string[]]$Hashes = @(),
    
        [Parameter(Mandatory = $false)]
        [int]$MaxSizeMB = 30,
    
        [Parameter(Mandatory = $false)]
        [string]$Timezone = "",
    
        [Parameter(Mandatory = $false)]
        [string]$Path = "",
    
        [Parameter(Mandatory = $false)]
        [switch]$AllDrives,
    
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSystemFolders,
    
        [Parameter(Mandatory = $false)]
        [switch]$Hidden,
    
        [Parameter(Mandatory = $false)]
        [switch]$Recycled,
    
        [Parameter(Mandatory = $false)]
        [switch]$Streams,
    
        [Parameter(Mandatory = $false)]
        [int]$MaxPrint = 0,
    
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Auto,
    
        [Parameter(Mandatory = $false)]
        [string]$Type = "",
    
        [Parameter(Mandatory = $false)]
        [switch]$VerboseOutput,
    
        [Parameter(Mandatory = $false)]
        [switch]$Aggressive,
    
        [Parameter(Mandatory = $false)]
        [string]$OutputCSV = "",
    
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
    
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    Write-Progress -Activity "Hunt-Files" -Status "Initializing..." -PercentComplete 0

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "Not running as Administrator, insufficient privileges may cause detection issues..."
    }

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
        }
        else { 
            $TimezoneName 
        }
        
        try {
            if ($mappedName -eq 'UTC') {
                return [System.TimeZoneInfo]::Utc
            }
            else {
                return [System.TimeZoneInfo]::FindSystemTimeZoneById($mappedName)
            }
        }
        catch {
            throw "Invalid timezone: $TimezoneName"
        }
    }

    $targetTimeZone = if ([string]::IsNullOrWhiteSpace($Timezone)) { 
        $systemTimeZone 
    }
    else { 
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
            }
            catch {
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
        }
        else {
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


    # CSV sanitization function
    function Sanitize-CSVValue {
        param($Value)

        if ($null -eq $Value) { return "" }

        $stringValue = $Value.ToString()

        # Truncate if too long for Excel (32,767 character limit per cell)
        if ($stringValue.Length -gt 32000) {
            $stringValue = $stringValue.Substring(0, 32000) + "...[TRUNCATED]"
        }

        # Remove or escape problematic characters
        $stringValue = $stringValue -replace '"', '""'  # Escape quotes
        $stringValue = $stringValue -replace '^=', "'="  # Prevent formula injection
        $stringValue = $stringValue -replace '^@', "'@"  # Prevent formula injection
        $stringValue = $stringValue -replace '^\+', "'+"  # Prevent formula injection
        $stringValue = $stringValue -replace '^-', "'-"  # Prevent formula injection
        $stringValue = $stringValue -replace '\r\n|\r|\n', ' '  # Replace line breaks
        $stringValue = $stringValue -replace '\t', ' '  # Replace tabs

        return $stringValue
    }

    # Stream handling function - optimized for PS5+
    function Get-FileStreams {
        param($FilePath)
        
        $streams = @()
        try {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $allStreams = @(Get-Item -Path $FilePath -Stream * -ErrorAction SilentlyContinue)
                foreach ($stream in $allStreams) {
                    if ($stream.Stream -ne ':$DATA') {
                        $streams += [PSCustomObject]@{
                            StreamName = $stream.Stream
                            Size       = $stream.Length
                        }
                    }
                }
            }
        }
        catch {
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
            }
            else {
                "${FilePath}:${StreamName}"
            }
            
            $fileInfo = Get-Item -Path $FilePath -Force -ErrorAction Stop
            if ($fileInfo.Length -gt $MaxSize -or $fileInfo.Length -eq 0) { 
                return '' 
            }
            
            $content = Get-Content -Path $streamPath -Raw -Encoding UTF8 -ErrorAction Stop
            return $content
        }
        catch {
            return ''
        }
    }

    # Hash computation function - optimized
    function Get-FileHashCustom {
        param($FilePath, $StreamName = '', $Algorithm)
        
        try {
            $streamPath = if ([string]::IsNullOrEmpty($StreamName) -or $StreamName -eq ':$DATA') {
                $FilePath
            }
            else {
                "${FilePath}:${StreamName}"
            }
            
            $hash = Get-FileHash -Path $streamPath -Algorithm $Algorithm -ErrorAction Stop
            return $hash.Hash.ToLower()
        }
        catch {
            return ""
        }
    }

    # LNK shortcut resolution function
    function Get-LnkTarget {
        param($LnkPath)
        
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($LnkPath)
            $targetPath = $shortcut.TargetPath
            
            # Release COM object
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
            
            if (![string]::IsNullOrWhiteSpace($targetPath) -and (Test-Path $targetPath -ErrorAction SilentlyContinue)) {
                return $targetPath
            }
            return ""
        }
        catch {
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
            }
            catch {
                Write-Error "Failed to get drive information: $($_.Exception.Message)"
                return
            }
        }
        else {
            $searchPaths = @("$((Get-Location).Drive.Name):\")
        }
    }
    else {
        $searchPath = $Path.TrimEnd('\')
        if (-not (Test-Path $searchPath)) {
            Write-Error "Specified path does not exist: $searchPath"
            return
        }
        $searchPaths = @($searchPath)
    }

    # Date range handling - simplified logic
    $hasDateRange = $null -ne $StartDate -or $EndDate -ne "Now"
    $hasOtherCriteria = $Extensions.Count -gt 0 -or $Content.Count -gt 0 -or $Search.Count -gt 0 -or $Hashes.Count -gt 0 -or $Hidden -or $Recycled -or $Streams -or $Auto

    # Only enforce date requirements in Auto mode
    if ($Auto -and !$hasDateRange) {
        # Auto mode sets its own dates, this is already handled above
    }
    elseif ($null -ne $StartDate -and $EndDate -eq "Now") {
        $EndDate = Get-Date
    }
    elseif ($null -eq $StartDate -and $EndDate -ne "Now") {
        throw "EndDate specified but StartDate is missing. Please provide both dates or neither."
    }

    # Convert dates
    $parsedStartDate = $null
    $parsedEndDate = $null

    if ($hasDateRange) {
        try {
            $parsedStartDate = if ($null -ne $StartDate) { ConvertTo-DateTime -InputValue $StartDate -TargetTimeZone $targetTimeZone } else { $null }
            $parsedEndDate = if ($EndDate -ne "Now") { ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone $targetTimeZone } else { ConvertTo-DateTime -InputValue $EndDate -TargetTimeZone $targetTimeZone }
        }
        catch {
            throw "Date parsing error: $($_.Exception.Message)"
        }
    }
    
    # If no criteria specified, treat as "return all files"
    $hasSearchCriteria = $null -ne $parsedStartDate -or $null -ne $parsedEndDate -or $Extensions.Count -gt 0 -or $Content.Count -gt 0 -or $Search.Count -gt 0 -or $Hashes.Count -gt 0 -or $Auto -or $Hidden -or $Recycled -or $Streams
    
    # Set a flag for "match everything" mode
    $matchEverything = -not $hasSearchCriteria

    Write-Progress -Activity "Hunt-Files" -Status "Processing criteria..." -PercentComplete 20

    # Normalize search criteria
    $normalizedHashes = @{}
    foreach ($hash in $Hashes) {
        try {
            $cleanHash = $hash.Trim().ToLower() -replace '[^a-f0-9]', ''
            $hashType = switch ($cleanHash.Length) {
                32 { 'MD5' }
                40 { 'SHA1' }
                64 { 'SHA256' }
                default { 
                    Write-Warning "Invalid hash format: $hash"
                    continue 
                }
            }
            $normalizedHashes[$cleanHash] = $hashType
        }
        catch {
            Write-Warning "Error processing hash '$hash': $($_.Exception.Message)"
        }
    }

    # Normalize extensions and Search
    if ($Extensions.Count -gt 0) {
        $Extensions = @($Extensions | ForEach-Object { 
                $ext = $_.ToLower().Trim()
                if (-not $ext.StartsWith('.')) { ".$ext" } else { $ext }
            })
    }

    if ($Search.Count -gt 0) {
        $Search = @($Search | ForEach-Object { $_.Trim() })
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

    Write-Progress -Activity "Hunt-Files" -Status "Scanning filesystem..." -PercentComplete 50

    # Main scanning loop - optimized
    foreach ($currentSearchPath in $searchPaths) {
        try {
            $searchSubPaths = @()
            
            # If -Recycled is specified, ONLY search recycle bin paths
            if ($Recycled) {
                $driveLetter = $currentSearchPath.Substring(0, 1)
                $recycleBinPaths = @("${driveLetter}:\`$Recycle.Bin", "${driveLetter}:\RECYCLER")
                $searchSubPaths = @($recycleBinPaths | Where-Object { Test-Path $_ })
            
                if ($searchSubPaths.Count -eq 0) {
                    Write-Warning "No recycle bin found on drive ${driveLetter}:"
                    continue
                }
            }
            else {
                # Normal search path
                $searchSubPaths = @($currentSearchPath)
            }

            foreach ($subPath in $searchSubPaths) {
                try {
                    # Optimized file enumeration
                    try {
                        # Apply date filter at enumeration level if dates specified
                        if ($null -ne $parsedStartDate -and $null -ne $parsedEndDate) {
                            $pathItems = @(Get-ChildItem -Path $subPath -Recurse -Force -ErrorAction SilentlyContinue |
                                Where-Object {
                                    ($_.LastWriteTime -ge $parsedStartDate -and $_.LastWriteTime -le $parsedEndDate) -or
                                    ($_.CreationTime -ge $parsedStartDate -and $_.CreationTime -le $parsedEndDate) -or
                                    ($_.LastAccessTime -ge $parsedStartDate -and $_.LastAccessTime -le $parsedEndDate)
                                })
                        }
                        else {
                            $pathItems = @(Get-ChildItem -Path $subPath -Recurse -Force -ErrorAction SilentlyContinue)
                        }
                    }
                    catch {
                        if ($VerboseOutput) {
                            Write-Warning "Error enumerating path $subPath : $($_.Exception.Message)"
                        }
                        continue
                    }
                    # Skip recycle bin metadata files ($I files) - we only need $R files
                    if ($Recycled) {
                        $pathItems = @($pathItems | Where-Object { $_.Name -notlike '$I*' })
                    }
                        
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
                                }
                                catch {
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
                            # Date range matching - optimized
                            if ($null -ne $parsedStartDate -and $null -ne $parsedEndDate) {
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

                            # Name matching - fixed wildcard support
                            if ($Search.Count -gt 0) {
                                $fileName = $item.Name
                                $matchedNames = @()
    
                                foreach ($pattern in $Search) {
                                    # If pattern contains wildcards, use as-is, otherwise add implicit wildcards
                                    $searchPattern = if ($pattern -match '[*?]') { 
                                        $pattern 
                                    }
                                    else { 
                                        "*$pattern*" 
                                    }
        
                                    if ($fileName -like $searchPattern) {
                                        $matchedNames += $pattern
                                    }
                                }
    
                                if ($matchedNames.Count -gt 0) {
                                    $itemMatchReasons += "Name:$($matchedNames -join ',')"
                                    $matchedNames = $matchedNames  # Store for potential separate display
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
                                        $mainStreamMatches = @($Content | Where-Object { 
                                                try { $fileContent -like "*$_*" } catch { $false }
                                            })
                                        if ($mainStreamMatches.Count -gt 0) {
                                            $allStreamMatches += $mainStreamMatches | ForEach-Object { "$_(:DATA)" }
                                        }
                                    }
        
                                    # Check alternate streams
                                    foreach ($stream in $alternateStreams) {
                                        if ($stream.Size -le $maxSizeBytes -and $stream.Size -gt 0) {
                                            try {
                                                $streamContent = Get-ContentFromFile -FilePath $item.FullName -StreamName $stream.StreamName -MaxSize $maxSizeBytes
                                                if (![string]::IsNullOrEmpty($streamContent)) {
                                                    $streamContentMatches = @($Content | Where-Object { 
                                                            try { $streamContent -like "*$_*" } catch { $false }
                                                        })
                                                    if ($streamContentMatches.Count -gt 0) {
                                                        $allStreamMatches += $streamContentMatches | ForEach-Object { "$_($($stream.StreamName))" }
                                                    }
                                                }
                                            }
                                            catch {
                                                if ($VerboseOutput) {
                                                    Write-Warning "Error reading stream $($stream.StreamName) from $($item.FullName): $($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    }
        
                                    if ($allStreamMatches.Count -gt 0) {
                                        $itemMatchReasons += "Content:$($allStreamMatches -join ',')"
                                        $matchedContent = $allStreamMatches
                                    }
                                }
                                catch {
                                    if ($VerboseOutput) {
                                        Write-Warning "Error during content search for $($item.FullName): $($_.Exception.Message)"
                                    }
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
                                        if (![string]::IsNullOrEmpty($computedHash) -and $computedHash -eq $targetHash) {
                                            $hashMatches += "$algo($targetHash):DATA"
                                        }
                                    }
                                            
                                    # Check alternate streams
                                    foreach ($stream in $alternateStreams) {
                                        foreach ($hashEntry in $normalizedHashes.GetEnumerator()) {
                                            $targetHash = $hashEntry.Key
                                            $algo = $hashEntry.Value
                                                    
                                            $computedHash = Get-FileHashCustom -FilePath $item.FullName -StreamName $stream.StreamName -Algorithm $algo
                                            if (![string]::IsNullOrEmpty($computedHash) -and $computedHash -eq $targetHash) {
                                                $hashMatches += "$algo($targetHash):$($stream.StreamName)"
                                            }
                                        }
                                    }
                                            
                                    if ($hashMatches.Count -gt 0) {
                                        $itemMatchReasons += "Hash:$($hashMatches -join ',')"
                                    }
                                            
                                    # Always compute SHA256 for matched files if not already done
                                    if ($itemMatchReasons.Count -gt 0 -and [string]::IsNullOrEmpty($sha256)) {
                                        try {
                                            $sha256 = Get-FileHashCustom -FilePath $item.FullName -Algorithm 'SHA256'
                                        }
                                        catch {
                                            if ($VerboseOutput) {
                                                Write-Warning "Error computing SHA256 for $($item.FullName): $($_.Exception.Message)"
                                            }
                                        }
                                    }
                                }
                                catch {
                                    # Skip files we can't hash
                                }
                            }
                            

                            # Include item if any criteria matched OR if in match-everything mode
                            if ($itemMatchReasons.Count -gt 0 -or $specialSwitchMatch -or $matchEverything) {
                                if ($isDirectory) {
                                    $foldersMatched++
                                }
                                else {
                                    $filesMatched++
                                    # Compute SHA256 for files if not done yet
                                    if ([string]::IsNullOrEmpty($sha256)) {
                                        try {
                                            $sha256 = Get-FileHashCustom -FilePath $item.FullName -Algorithm 'SHA256'
                                        }
                                        catch {
                                            # Skip if can't compute hash
                                        }
                                    }
                                }
                                    
                                # Handle LNK files
                                $lnkTarget = ""
                                $lnkTargetHash = ""
                                if (-not $isDirectory -and $item.Extension.ToLower() -eq '.lnk') {
                                    try {
                                        $lnkTarget = Get-LnkTarget -LnkPath $item.FullName
                                        if (![string]::IsNullOrWhiteSpace($lnkTarget)) {
                                            $lnkTargetHash = Get-FileHashCustom -FilePath $lnkTarget -Algorithm 'SHA256'
                                        }
                                    }
                                    catch {
                                        # Continue if LNK resolution fails
                                    }
                                }
                                
                                $result = [PSCustomObject]@{
                                    FullPath             = $item.FullName
                                    Name                 = $item.Name
                                    IsDirectory          = $isDirectory
                                    SizeMB               = if ($isDirectory) { 0 } else { [math]::Round($item.Length / 1MB, 4) }
                                    CreationTime         = $item.CreationTime
                                    LastWriteTime        = $item.LastWriteTime
                                    LastAccessTime       = $item.LastAccessTime
                                    SHA256               = $sha256
                                    MatchReason          = ($itemMatchReasons -join " | ")
                                    MatchedContent       = ($matchedContent -join ', ')
                                    MatchedNames         = ($matchedNames -join ', ')
                                    IsHidden             = $itemIsHidden
                                    IsRecycleBin         = $itemIsRecycleBin
                                    StreamInfo           = $streamInfo
                                    AlternateStreamCount = $alternateStreams.Count
                                    LnkTarget            = $lnkTarget
                                    LnkTargetSHA256      = $lnkTargetHash
                                }
                                    
                                $results += $result
                            }
                        }
                        catch {
                            if ($VerboseOutput) {
                                Write-Warning "Error processing item $($item.FullName): $($_.Exception.Message)"
                            }
                        }
                    }
                }
                catch {
                    if ($VerboseOutput) {
                        Write-Warning "Error accessing path $subPath : $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
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
        }
        elseif ($filterType -eq "DIR") {
            $sortedResults = @($sortedResults | Where-Object { $_.IsDirectory })
        }
    }

    # Display results only if not -Quiet
    if (-not $Quiet) {
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

            if (![string]::IsNullOrWhiteSpace($result.LnkTarget)) {
                Write-Host "LNK Target   : $($result.LnkTarget)" -ForegroundColor Magenta
                if (![string]::IsNullOrWhiteSpace($result.LnkTargetSHA256)) {
                    Write-Host "Target SHA256: $($result.LnkTargetSHA256)" -ForegroundColor Gray
                }
            }
        
            Write-Host "Match        : $($result.MatchReason)" -ForegroundColor Red
        
            if (![string]::IsNullOrWhiteSpace($result.MatchedContent)) {
                Write-Host "Content Match: $($result.MatchedContent)" -ForegroundColor Green
            }
        
            # In the display section, only show "Name Match" if there are other match reasons too
            if (![string]::IsNullOrWhiteSpace($result.MatchedNames)) {
                # Only show separate Name Match if there are other match reasons besides name
                $matchReasons = $result.MatchReason -split ' \| '
                $hasOtherReasons = $matchReasons | Where-Object { $_ -notlike 'Name:*' }
                if ($hasOtherReasons) {
                    Write-Host "Name Match   : $($result.MatchedNames)" -ForegroundColor Green
                }
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
    }
    Write-Progress -Activity "Hunt-Files" -Status "Complete" -PercentComplete 100

    if (-not $Quiet) {
        Write-Progress -Activity "Hunt-Files" -Status "Complete" -PercentComplete 100
    }

    # CSV Export
    if (![string]::IsNullOrWhiteSpace($OutputCSV)) {
        try {
            # Determine CSV path first
            $csvPath = ""
            if (Test-Path $OutputCSV -PathType Container -ErrorAction SilentlyContinue) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $csvPath = Join-Path $OutputCSV "Hunt-Files_Results_$timestamp.csv"
            }
            elseif ($OutputCSV.EndsWith('.csv')) {
                $csvPath = $OutputCSV
            }
            else {
                $csvPath = "$OutputCSV.csv"
            }

            # Ensure we have a valid path
            if ([string]::IsNullOrWhiteSpace($csvPath)) {
                throw "Unable to determine CSV output path"
            }

            # Create directory if it doesn't exist
            try {
                $csvDirectory = Split-Path $csvPath -Parent
                if (![string]::IsNullOrEmpty($csvDirectory) -and !(Test-Path $csvDirectory)) {
                    New-Item -Path $csvDirectory -ItemType Directory -Force | Out-Null
                }
            }
            catch {
                throw "Unable to create CSV output directory: $($_.Exception.Message)"
            }
        
            # Prepare CSV data
            $csvData = @()
            foreach ($result in $sortedResults) {
                $csvData += [PSCustomObject]@{
                    Type                 = if ($result.IsDirectory) { "Directory" } else { "File" }
                    FullPath             = Sanitize-CSVValue $result.FullPath
                    Name                 = Sanitize-CSVValue $result.Name
                    SizeMB               = $result.SizeMB
                    CreationTime         = Format-DateTimeWithTimeZone -DateTime $result.CreationTime -TargetTimeZone $targetTimeZone
                    LastWriteTime        = Format-DateTimeWithTimeZone -DateTime $result.LastWriteTime -TargetTimeZone $targetTimeZone
                    LastAccessTime       = Format-DateTimeWithTimeZone -DateTime $result.LastAccessTime -TargetTimeZone $targetTimeZone
                    SHA256               = Sanitize-CSVValue $result.SHA256
                    MatchReason          = Sanitize-CSVValue $result.MatchReason
                    MatchedContent       = Sanitize-CSVValue $result.MatchedContent
                    MatchedNames         = Sanitize-CSVValue $result.MatchedNames
                    IsHidden             = $result.IsHidden
                    IsRecycleBin         = $result.IsRecycleBin
                    StreamInfo           = Sanitize-CSVValue $result.StreamInfo
                    AlternateStreamCount = $result.AlternateStreamCount
                    LnkTarget            = Sanitize-CSVValue $result.LnkTarget
                    LnkTargetSHA256      = Sanitize-CSVValue $result.LnkTargetSHA256
                }
            }
        
            $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        
            if (-not $Quiet) {
                Write-Host "`n[+] Results exported to: $csvPath" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "`nFailed to export CSV: $($_.Exception.Message)"
        }
    }

    # Summary - only display if not Quiet
    if (-not $Quiet) {
        if ($results.Count -eq 0) {
            Write-Host "[!] No items found matching the specified criteria." -ForegroundColor Yellow
        }
        else {
            $totalMatched = $filesMatched + $foldersMatched
            $displayedCount = $sortedResults.Count
            write-host "----------------------------------------"
            $summaryParts = @()
    
            if (![string]::IsNullOrWhiteSpace($filterType)) {
                $filterDescription = if ($filterType -eq "FILE") { "files" } else { "directories" }
                $summaryParts += "[+] Search completed. Found $totalMatched total items ($filesMatched files, $foldersMatched folders). Showing $displayedCount $filterDescription."
            }
            else {
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

    # Return objects only if PassThru is specified
    if ($PassThru) {
        return $sortedResults
    }
}


function Hunt-Tasks {
    <#
    .SYNOPSIS
    Comprehensive enumeration and analysis of Windows scheduled tasks for DFIR investigations.
    
    .DESCRIPTION
    Hunt-Tasks provides deep forensic analysis of all scheduled tasks on a Windows system, including:
    - Complete task metadata (name, path, state, author, description)
    - Task file analysis with SHA256 hashes and timestamps  
    - Executable and script file identification with full path resolution
    - Working directory analysis
    - Trigger type enumeration
    - Runtime information (last run, next run times)
    - Support for search filtering with wildcards
    - CSV export with Excel-compatible sanitization
    - Silent operation mode for automation
    
    This function is designed for digital forensics, incident response, threat hunting, 
    and security auditing activities where comprehensive scheduled task analysis is required.
    
    .PARAMETER Search
    Filter results using wildcard patterns. Searches across task names, paths, descriptions, 
    executables, arguments, and trigger types. Case-insensitive matching.
    
    .PARAMETER IncludeDisabled  
    Include disabled tasks in the analysis. By default, disabled tasks are excluded.

    .PARAMETER PassThru
    Return PowerShell objects for further processing instead of just displaying results.
    Useful for automation and integration with other tools.

    .PARAMETER Quiet
    Suppress console output except for errors and warnings. Designed for use with -PassThru
    and -OutputCSV for silent operation.

    .PARAMETER OutputCSV
    Export results to CSV format. Accepts either:
    - Full file path: "C:\Analysis\tasks.csv"  
    - Directory path: "C:\Analysis\" (auto-generates filename with timestamp)
    Includes Excel-compatible sanitization and all forensic metadata.

    .EXAMPLE
    Hunt-Tasks
    Display all enabled scheduled tasks with full forensic analysis.

    .EXAMPLE  
    Hunt-Tasks -Search "*malware*" -IncludeDisabled
    Search for tasks containing "malware" in any field, including disabled tasks.

    .EXAMPLE
    Hunt-Tasks -OutputCSV "C:\DFIR\Analysis\"
    Export all task analysis to auto-generated CSV file in the specified directory.

    .EXAMPLE
    $suspiciousTasks = Hunt-Tasks -Search "*persist*" -PassThru -Quiet
    Silently collect tasks with "persist" in any field, return as PowerShell objects.

    .EXAMPLE
    Hunt-Tasks -Search "*powershell*" -OutputCSV ".\ps_tasks.csv" -IncludeDisabled
    Find all PowerShell-related tasks (including disabled) and export to CSV.

    .NOTES
    Requirements: PowerShell 5.0+, Windows
    Privileges: Administrator recommended for complete task enumeration
    Output: Displays forensic analysis or returns PSCustomObjects via -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Search = "",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false)]
        [string]$OutputCSV = ""        
    )

    begin {
        # Check for administrator privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if (-not $isAdmin) {
            Write-Warning "Not running as Administrator, insufficient privileges may cause detection issues..."
        }
        Write-Verbose "[INFO]: Starting scheduled task enumeration..."
        # Progress tracking
        $script:TotalTasks = 0
        $script:ProcessedTasks = 0
        
        # Add this in the begin block after existing helper functions
        $script:TaskResults = @()

        # Helper function to create task result object
        function New-TaskResult {
            param(
                $Task,
                $TaskFileDetails,
                $ExecutableDetails,
                $ScriptFileDetails,
                $WorkingDirDetails,
                $ResolvedExecutable,
                $ScriptFile,
                $Arguments,
                $TriggerTypes,
                $TaskInfo
            )
    
            return [PSCustomObject]@{
                TaskName           = $Task.TaskName
                TaskPath           = $Task.TaskPath
                State              = $Task.State
                Author             = $Task.Author
                Description        = $Task.Description
                LastRunTime        = if ($TaskInfo -and $TaskInfo.LastRunTime -ne [DateTime]::MinValue) { $TaskInfo.LastRunTime } else { $null }
                NextRunTime        = if ($TaskInfo -and $TaskInfo.NextRunTime -ne [DateTime]::MinValue) { $TaskInfo.NextRunTime } else { $null }
                TaskFilePath       = $TaskFileDetails.Path
                TaskFileExists     = $TaskFileDetails.Exists
                TaskFileSHA256     = $TaskFileDetails.SHA256
                TaskFileModified   = $TaskFileDetails.Modified
                ExecutablePath     = $ResolvedExecutable
                ExecutableExists   = if ($ExecutableDetails) { $ExecutableDetails.Exists } else { $false }
                ExecutableSHA256   = if ($ExecutableDetails) { $ExecutableDetails.SHA256 } else { 'N/A' }
                ExecutableModified = if ($ExecutableDetails) { $ExecutableDetails.Modified } else { 'N/A' }
                Arguments          = $Arguments
                ScriptFilePath     = $ScriptFile
                ScriptFileExists   = if ($ScriptFileDetails) { $ScriptFileDetails.Exists } else { $false }
                ScriptFileSHA256   = if ($ScriptFileDetails) { $ScriptFileDetails.SHA256 } else { 'N/A' }
                WorkingDirectory   = if ($WorkingDirDetails) { $WorkingDirDetails.Path } else { $null }
                TriggerTypes       = $TriggerTypes -join ', '
                Hostname           = $env:COMPUTERNAME
            }
        }


        # Helper function to sanitize CSV values for Excel compatibility
        function Sanitize-CSVValue {
            param([string]$Value)
    
            if ([string]::IsNullOrWhiteSpace($Value)) {
                return ""
            }
    
            try {
                # Remove control characters and replace with spaces
                $sanitized = $Value -replace '[\x00-\x1F\x7F]', ' '
        
                # Remove or replace problematic characters
                $sanitized = $sanitized -replace '["\r\n]', ' '
                $sanitized = $sanitized -replace '\t', ' '
        
                # Replace equals signs to prevent Excel formula injection
                $sanitized = $sanitized -replace '=', '-'
        
                # Also sanitize other potential Excel formula starters for extra security
                $sanitized = $sanitized -replace '^[\+\-@]', '_'
        
                # Trim whitespace and limit length for Excel (32767 character limit per cell)
                $sanitized = $sanitized.Trim()
                if ($sanitized.Length -gt 32000) {
                    $sanitized = $sanitized.Substring(0, 32000) + "...[TRUNCATED]"
                }
        
                return $sanitized
            }
            catch {
                return ""
            }
        }

        # Helper function to generate CSV filename
        function Get-CSVFileName {
            param([string]$OutputPath)
    
            try {
                if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                    return $null
                }
        
                # Check if path is a directory
                if (Test-Path $OutputPath -PathType Container -ErrorAction SilentlyContinue) {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $filename = "Hunt-Tasks_Results_$($env:COMPUTERNAME)_$timestamp.csv"
                    return Join-Path $OutputPath $filename
                }
                # Check if parent directory exists for file path
                elseif ($OutputPath -match '\.csv$') {
                    $parentDir = Split-Path $OutputPath -Parent
                    if ([string]::IsNullOrWhiteSpace($parentDir) -or (Test-Path $parentDir -PathType Container -ErrorAction SilentlyContinue)) {
                        return $OutputPath
                    }
                    else {
                        # Try to create parent directory
                        try {
                            New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "[INFO]: Created directory: $parentDir"
                            return $OutputPath
                        }
                        catch {
                            Write-Warning "Could not create directory: $parentDir"
                            return $null
                        }
                    }
                }
        
                Write-Warning "Invalid OutputCSV path specified: $OutputPath"
                return $null
            }
            catch {
                Write-Warning "Error processing OutputCSV path: $($_.Exception.Message)"
                return $null
            }
        }

        function Find-ExecutableInSystemPaths {
            param([string]$FileName)
    
            if ([string]::IsNullOrWhiteSpace($FileName)) { 
                return $FileName 
            }
    
            # Define search paths in order of priority
            $searchPaths = @(
                "C:\Windows\System32",
                "C:\Windows\SysWOW64", 
                "C:\Windows",
                "C:\Program Files\Windows NT\Accessories",
                "C:\Program Files\Common Files\Microsoft Shared",
                "C:\Windows\System32\WindowsPowerShell\v1.0\",
                "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\",
                "C:\Users\<YourUsername>\AppData\Local\Microsoft\PowerShell\7\",
                "C:\Program Files\PowerShell\7\"
            )
    
            foreach ($searchPath in $searchPaths) {
                $fullPath = Join-Path $searchPath $FileName
                if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                    return $fullPath
                }
            }
    
            # If not found, return the original filename
            return $FileName
        }

        function Get-FileFromCommandLine {
            param([String]$CommandLine)

            if ([string]::IsNullOrWhiteSpace($CommandLine)) {
                return $null
            }

            try {
                # Expand environment variables
                $expanded = [System.Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    
                # 1. COMPATTELRUNNER.EXE with -m: parameter - extract the executable, not the DLL
                if ($expanded -match '(.*compattelrunner\.exe)\s+-m:') {
                    return $matches[1]
                }
    
                # 2. CMD.EXE executing files - extract the target file
                if ($expanded -match 'cmd\.exe.*?/[dc]\s+([A-Za-z]:\\[^"\s]+\.(cmd|bat|ps1|vbs|js))') {
                    return $matches[1]
                }
                if ($expanded -match 'cmd\.exe.*?/[dc]\s+"([^"]+\.(cmd|bat|ps1|vbs|js))"') {
                    return $matches[1]
                }
                if ($expanded -match 'cmd\.exe.*?/[dc]\s+([^"\s]+\.(cmd|bat|ps1|vbs|js))') {
                    return $matches[1]
                }
    
                # 3. POWERSHELL.EXE executing files - extract script files or executables
                if ($expanded -match 'powershell\.exe.*?-[Ff]ile\s+"?([^"\s]+\.(ps1|bat|cmd|exe|vbs|js))"?') {
                    return $matches[1]
                }
                if ($expanded -match 'powershell\.exe.*?"[^"]*([A-Za-z]:\\[^"]*\.(ps1|bat|cmd|exe|vbs|js|dll))[^"]*"') {
                    return $matches[1]
                }
                if ($expanded -match 'powershell\.exe.*?&\s+([A-Za-z]:\\[^"\s]+\.(ps1|bat|cmd|exe|vbs|js))') {
                    return $matches[1]
                }
                if ($expanded -match 'powershell\.exe.*?\.\s+([A-Za-z]:\\[^"\s]+\.(ps1|bat|cmd|exe|vbs|js))') {
                    return $matches[1]
                }
    
                # 4. NODE.EXE executing JavaScript files
                if ($expanded -match 'node\.exe\s+"?([^"\s]+\.js)"?') {
                    return $matches[1]
                }
    
                # 5. PYTHON.EXE executing Python files
                if ($expanded -match 'python\.exe\s+"?([^"\s]+\.py)"?') {
                    return $matches[1]
                }
    
                # 6. WSCRIPT.EXE / CSCRIPT.EXE executing scripts
                if ($expanded -match '(?:wscript|cscript)\.exe\s+"?([^"\s]+\.(vbs|js|wsf))"?') {
                    return $matches[1]
                }
    
                # 7. MSHTA.EXE executing HTA files
                if ($expanded -match 'mshta\.exe\s+"?([^"\s]+\.hta)"?') {
                    return $matches[1]
                }
    
                # 8. REGSVR32.EXE registering DLLs
                if ($expanded -match 'regsvr32\.exe.*?\s+"?([^"\s]+\.dll)"?') {
                    return $matches[1]
                }
    
                # 9. RUNDLL32.EXE calling DLL functions - extract the DLL
                if ($expanded -match 'rundll32\.exe\s+([A-Za-z]:\\[^,\s]+\.dll|[^,\s]+\.dll)') {
                    $dll = $matches[1]
                    # If relative path, try to resolve it
                    if ($dll -notmatch '^[A-Za-z]:') {
                        return Find-ExecutableInSystemPaths $dll
                    }
                    return $dll
                }
    
                # 10. MSIEXEC.EXE installing MSI files
                if ($expanded -match 'msiexec\.exe.*?[/\-]i\s+"?([^"\s]+\.msi)"?') {
                    return $matches[1]
                }
    
                # 11. SCHTASKS.EXE with /RU (run as) pointing to executables
                if ($expanded -match 'schtasks\.exe.*?/TR\s+"?([^"\s]+\.(exe|bat|cmd|ps1))"?') {
                    return $matches[1]
                }
    
                # 12. NET.EXE or SC.EXE starting services - return the full path
                if ($expanded -match '^(net\.exe|sc\.exe)\s+(?:start|stop|config)') {
                    $utilityName = $matches[1]
                    return Find-ExecutableInSystemPaths $utilityName
                }
    
                # 13. Quoted paths - but exclude PowerShell script content
                if ($expanded -match '"([^"]+)"' -and $matches[1] -notlike "& *" -and $matches[1] -notlike ".*-.*") {
                    $path = $matches[1].Trim()
                    # Clean trailing punctuation
                    $path = $path -replace '[,;]+$', ''
                    # Only return if it's a file path
                    if ($path -match '\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf)$') {
                        return $path
                    }
                }
    
                # 14. Simple drive paths with any extension
                if ($expanded -match '^([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))(\s|$)') {
                    $path = $matches[1].Trim()
                    # Clean trailing punctuation
                    $path = $path -replace '[,;]+$', ''
                    return $path
                }
    
                # 15. Drive paths with arguments - capture until first argument
                if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))\s+(-|/)') {
                    return $matches[1].Trim()
                }
    
                # 16. Drive paths with space + word arguments (non-path arguments)
                if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))\s+([a-zA-Z]+)' -and $matches[3] -notmatch '^[A-Za-z]:') {
                    return $matches[1].Trim()
                }
    
                # 17. UNC paths
                if ($expanded -match '(\\\\[^\\]+\\[^\s"]+\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))') {
                    return $matches[1].Trim()
                }
    
                # 18. Simple executable names with arguments - handle cases like "BthUdTask.exe $(Arg0)"
                if ($expanded -match '^([a-zA-Z][a-zA-Z0-9]*\.(exe|com|scr|dll))(\s|$)') {
                    $file = $matches[1]
                    return Find-ExecutableInSystemPaths $file
                }
    
                # 19. Look for any executable file in command line arguments
                if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))') {
                    return $matches[1] -replace '[,;]+$', ''
                }
    
                # 20. FINAL FALLBACK - if nothing else worked and we have a non-empty string, return it
                if (![string]::IsNullOrWhiteSpace($expanded)) {
                    return $expanded.Trim()
                }
    
                return $null
    
            }
            catch {
                Write-Verbose "Error parsing command line '$CommandLine': $($_.Exception.Message)"
                # Even on error, try the fallback
                if (![string]::IsNullOrWhiteSpace($CommandLine)) {
                    return $CommandLine.Trim()
                }
                return $null
            }
        }

        # Helper function to check if a string matches search criteria (case insensitive with wildcards)
        function Test-SearchMatch {
            param(
                [string]$Text,
                [string]$SearchPattern
            )
            
            if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($SearchPattern)) {
                return $false
            }
            
            try {
                return $Text -like $SearchPattern
            }
            catch {
                # Fallback to simple contains check if wildcard pattern fails
                return $Text.ToLower().Contains($SearchPattern.ToLower())
            }
        }
        
        # Helper function to calculate SHA256
        function Get-FileSHA256 {
            param([string]$FilePath)
            try {
                if (Test-Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue) {
                    $hash = [System.Security.Cryptography.SHA256]::Create()
                    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                    $hashBytes = $hash.ComputeHash($fileBytes)
                    $hash.Dispose()
                    return [BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()
                }
                return 'N/A'
            }
            catch {
                return 'N/A'
            }
        }
        
        # Helper function to get file information
        function Get-FileDetails {
            param([string]$FilePath)
            try {
                if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
                    $file = Get-Item $FilePath -Force -ErrorAction SilentlyContinue
                    if ($file) {
                        return @{
                            Path     = $file.FullName
                            Created  = $file.CreationTime
                            Modified = $file.LastWriteTime
                            Accessed = $file.LastAccessTime
                            Size     = if ($file.PSIsContainer) { 'N/A' } else { [math]::Round($file.Length / 1MB, 2) }
                            SHA256   = if ($file.PSIsContainer) { 'N/A' } else { Get-FileSHA256 -FilePath $file.FullName }
                            Exists   = $true
                        }
                    }
                }
                return @{
                    Path     = $FilePath
                    Created  = 'N/A'
                    Modified = 'N/A' 
                    Accessed = 'N/A'
                    Size     = 'N/A'
                    SHA256   = 'N/A'
                    Exists   = $false
                }
            }
            catch {
                return @{
                    Path     = $FilePath
                    Created  = 'N/A'
                    Modified = 'N/A'
                    Accessed = 'N/A' 
                    Size     = 'N/A'
                    SHA256   = 'N/A'
                    Exists   = $false
                }
            }
        }
        
        # Helper function to format datetime
        function Format-DateTime {
            param($DateTime)
            if ($DateTime -and $DateTime -ne 'N/A' -and $DateTime -is [DateTime]) {
                return $DateTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
            return 'N/A'
        }

        # Helper function to resolve executable path
        function Resolve-ExecutablePath {
            param([string]$ExecutablePath)
            
            if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
                return $ExecutablePath
            }
            
            # If it's already a full path, return as-is
            if ($ExecutablePath -match '^[A-Za-z]:' -or $ExecutablePath.StartsWith('\\')) {
                return $ExecutablePath
            }
            
            # Try to find in system paths
            return Find-ExecutableInSystemPaths $ExecutablePath
        }
    }
    
    process {
        try {
            # Get all scheduled tasks
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
            
            if ($null -eq $tasks) {
                Write-Host "[ERROR]: Unable to retrieve scheduled tasks. Administrative privileges may be required." -ForegroundColor Red
                return
            }
            
            # Filter tasks based on parameters - apply search filter after processing each task
            if (-not $IncludeDisabled) {
                $tasks = $tasks | Where-Object { $_.State -ne 'Disabled' }
            }
            
            # Sort tasks by task file modification date, then executable modification date
            $sortedTasks = $tasks | Sort-Object {
                try {
                    $taskPath = Join-Path $env:windir "System32\Tasks\$($_.TaskPath.TrimStart('\'))\$($_.TaskName)"
                    if (Test-Path $taskPath -ErrorAction SilentlyContinue) {
                        (Get-Item $taskPath -Force -ErrorAction SilentlyContinue).LastWriteTime
                    }
                    else {
                        [DateTime]::MinValue
                    }
                }
                catch {
                    [DateTime]::MinValue
                }
            }, {
                try {
                    $executable = [Environment]::ExpandEnvironmentVariables($_.Actions[0].Execute)
                    $resolvedPath = Resolve-ExecutablePath $executable
                    if ($resolvedPath -and (Test-Path $resolvedPath -ErrorAction SilentlyContinue)) {
                        (Get-Item $resolvedPath -Force -ErrorAction SilentlyContinue).LastWriteTime
                    }
                    else {
                        [DateTime]::MinValue
                    }
                }
                catch {
                    [DateTime]::MinValue
                }
            }
            
            $taskCount = 0
            $matchCount = 0
            
            # Get total count for progress
            $script:TotalTasks = $sortedTasks.Count
            Write-Progress -Activity "Enumerating Scheduled Tasks" -Status "Processing $($script:TotalTasks) tasks..." -PercentComplete 0
            
            foreach ($task in $sortedTasks) {
                $taskCount++
                $script:ProcessedTasks = $taskCount
                
                # Update progress every 10 tasks or for small datasets
                if (($taskCount % 10 -eq 0) -or ($script:TotalTasks -lt 50)) {
                    $percentComplete = [math]::Min(100, [math]::Round(($taskCount / $script:TotalTasks) * 100, 0))
                    Write-Progress -Activity "Enumerating Scheduled Tasks" -Status "Processing task $taskCount of $($script:TotalTasks)..." -PercentComplete $percentComplete
                }
                
                try {
                    # Get task file path and details
                    $taskFilePath = Join-Path $env:windir "System32\Tasks\$($task.TaskPath.TrimStart('\'))\$($task.TaskName)"
                    $taskFileDetails = Get-FileDetails -FilePath $taskFilePath
                    
                    # Get task information
                    $taskInfo = $null
                    try {
                        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Continue without task info if it fails
                    }
                    
                    foreach ($action in $task.Actions) {
                        try {
                            # Expand environment variables
                            $executable = [Environment]::ExpandEnvironmentVariables($action.Execute)
                            $workingDir = if ($action.WorkingDirectory) { [Environment]::ExpandEnvironmentVariables($action.WorkingDirectory) } else { $null }
                            $arguments = $action.Arguments
                            
                            # Resolve executable path if it's not a full path
                            $resolvedExecutable = Resolve-ExecutablePath $executable
                            
                            # Get file details for executable and working directory
                            $executableDetails = if ($resolvedExecutable) { Get-FileDetails -FilePath $resolvedExecutable } else { $null }
                            $workingDirDetails = if ($workingDir) { Get-FileDetails -FilePath $workingDir } else { $null }
                            
                            # Try to extract script file from command line
                            $scriptFile = $null
                            $scriptFileDetails = $null
                            
                            if ($null -ne $arguments) {
                                $fullCommandLine = "$executable $arguments"
                                $extractedFile = Get-FileFromCommandLine -CommandLine $fullCommandLine
                                
                                if ($extractedFile -and $extractedFile -ne $resolvedExecutable) {
                                    $scriptFile = $extractedFile
                                    $scriptFileDetails = Get-FileDetails -FilePath $scriptFile
                                }
                            }
                            
                            # Get trigger types for search
                            $triggerTypes = @()
                            if ($task.Triggers) {
                                foreach ($trigger in $task.Triggers) {
                                    try {
                                        $triggerType = $trigger.CimClass.CimClassName -replace 'MSFT_TaskTrigger', '' -replace 'Trigger', ''
                                        $triggerTypes += $triggerType
                                    }
                                    catch {
                                        # Continue if trigger parsing fails
                                    }
                                }
                            }
                            
                            # Apply search filter if specified - check all relevant fields
                            $includeTask = $true
                            if (-not [string]::IsNullOrWhiteSpace($Search)) {
                                $includeTask = $false
                                
                                # Check all the fields you specified
                                $searchFields = @(
                                    $task.TaskName,
                                    $task.TaskPath,
                                    $task.Author,
                                    $task.Description,
                                    $arguments,
                                    $executable,
                                    $resolvedExecutable,
                                    $scriptFile
                                )
                                
                                # Add trigger types to search
                                $searchFields += $triggerTypes
                                
                                foreach ($field in $searchFields) {
                                    if (Test-SearchMatch -Text $field -SearchPattern $Search) {
                                        $includeTask = $true
                                        break
                                    }
                                }
                            }
                            
                            # Skip this task if it doesn't match search criteria
                            if (-not $includeTask) {
                                continue
                            }
                            
                            $matchCount++
                            # Create result object for PassThru or CSV export
                            if ($PassThru -or (-not [string]::IsNullOrWhiteSpace($OutputCSV))) {
                                $taskResult = New-TaskResult -Task $task -TaskFileDetails $taskFileDetails -ExecutableDetails $executableDetails -ScriptFileDetails $scriptFileDetails -WorkingDirDetails $workingDirDetails -ResolvedExecutable $resolvedExecutable -ScriptFile $scriptFile -Arguments $arguments -TriggerTypes $triggerTypes -TaskInfo $taskInfo
                                $script:TaskResults += $taskResult
                            }

                            # Display results only if not -Quiet
                            if (-not $Quiet) {
                                Write-Host ""
                                Write-Host "----------------------------------------" -ForegroundColor Gray
                                Write-Host "`nTask Name    : " -NoNewline -ForegroundColor Yellow
                                Write-Host $task.TaskName -ForegroundColor Cyan

                                if ($task.TaskPath) {
                                    Write-Host "Task Path    : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $task.TaskPath -ForegroundColor White
                                }

                                if ($task.State) {
                                    Write-Host "State        : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $task.State -ForegroundColor DarkGray
                                }

                                if ($task.Author) {
                                    Write-Host "Author       : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $task.Author -ForegroundColor White
                                }

                                if ($task.Description) {
                                    Write-Host "Description  : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $task.Description -ForegroundColor DarkGray
                                }

                                if ($null -ne $taskInfo) {
                                    if ($taskInfo.LastRunTime -and $taskInfo.LastRunTime -ne [DateTime]::MinValue) {
                                        Write-Host "Last Run     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $taskInfo.LastRunTime) -ForegroundColor DarkGray
                                    }
                                    if ($taskInfo.NextRunTime -and $taskInfo.NextRunTime -ne [DateTime]::MinValue) {
                                        Write-Host "Next Run     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $taskInfo.NextRunTime) -ForegroundColor DarkGray
                                    }
                                    if ($taskInfo.NumberOfMissedRuns -and $taskInfo.NumberOfMissedRuns -ne 0) {
                                        Write-Host "Run Count    : " -NoNewline -ForegroundColor Yellow
                                        Write-Host $taskInfo.NumberOfMissedRuns -ForegroundColor DarkGray
                                    }
                                }

                                # Task file information - always show
                                Write-Host ""
                                Write-Host "--- Task File ---" -ForegroundColor DarkCyan
                                if ($taskFileDetails.Exists) {
                                    Write-Host "Path         : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $taskFileDetails.Path -ForegroundColor White

                                    if ($taskFileDetails.Created -ne 'N/A') {
                                        Write-Host "Created      : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $taskFileDetails.Created) -ForegroundColor DarkGray
                                    }
                                    if ($taskFileDetails.Modified -ne 'N/A') {
                                        Write-Host "Modified     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $taskFileDetails.Modified) -ForegroundColor DarkGray
                                    }
                                    if ($taskFileDetails.Accessed -ne 'N/A') {
                                        Write-Host "Accessed     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $taskFileDetails.Accessed) -ForegroundColor DarkGray
                                    }
                                    if ($taskFileDetails.SHA256 -ne 'N/A') {
                                        Write-Host "SHA256       : " -NoNewline -ForegroundColor Yellow
                                        Write-Host $taskFileDetails.SHA256 -ForegroundColor Gray
                                    }
                                }
                                else {
                                    Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                    Write-Host "Task File Not Found" -ForegroundColor Red
                                }

                                # Executable information - always show
                                Write-Host ""
                                Write-Host "--- Executable ---" -ForegroundColor DarkCyan
                                if ($resolvedExecutable) {
                                    Write-Host "Execute      : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $resolvedExecutable -ForegroundColor Red

                                    if ($arguments) {
                                        Write-Host "Arguments    : " -NoNewline -ForegroundColor Yellow
                                        Write-Host $arguments -ForegroundColor DarkYellow
                                    }

                                    if ($executableDetails -and $executableDetails.Exists) {
                                        if ($executableDetails.Created -ne 'N/A') {
                                            Write-Host "Created      : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $executableDetails.Created) -ForegroundColor DarkGray
                                        }
                                        if ($executableDetails.Modified -ne 'N/A') {
                                            Write-Host "Modified     : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $executableDetails.Modified) -ForegroundColor DarkGray
                                        }
                                        if ($executableDetails.Accessed -ne 'N/A') {
                                            Write-Host "Accessed     : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $executableDetails.Accessed) -ForegroundColor DarkGray
                                        }
                                        if ($executableDetails.Size -ne 'N/A') {
                                            Write-Host "Size         : " -NoNewline -ForegroundColor Yellow
                                            Write-Host "$($executableDetails.Size) MB" -ForegroundColor DarkGray
                                        }
                                        if ($executableDetails.SHA256 -ne 'N/A') {
                                            Write-Host "SHA256       : " -NoNewline -ForegroundColor Yellow
                                            Write-Host $executableDetails.SHA256 -ForegroundColor Gray
                                        }
                                    }
                                    else {
                                        Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                        Write-Host "Executable Not Found" -ForegroundColor Red
                                    }
                                }
                                else {
                                    Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                    Write-Host "No Executable Information Available" -ForegroundColor DarkGray
                                }

                                # Script file information - show if script file exists
                                if ($scriptFile -and $scriptFileDetails) {
                                    Write-Host ""
                                    Write-Host "--- Exec File ---" -ForegroundColor DarkCyan
                                    Write-Host "Exec File    : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $scriptFile -ForegroundColor Red

                                    if ($scriptFileDetails.Exists) {
                                        if ($scriptFileDetails.Created -ne 'N/A') {
                                            Write-Host "Created      : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $scriptFileDetails.Created) -ForegroundColor DarkGray
                                        }
                                        if ($scriptFileDetails.Modified -ne 'N/A') {
                                            Write-Host "Modified     : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $scriptFileDetails.Modified) -ForegroundColor DarkGray
                                        }
                                        if ($scriptFileDetails.Accessed -ne 'N/A') {
                                            Write-Host "Accessed     : " -NoNewline -ForegroundColor Yellow
                                            Write-Host (Format-DateTime -DateTime $scriptFileDetails.Accessed) -ForegroundColor DarkGray
                                        }
                                        if ($scriptFileDetails.Size -ne 'N/A') {
                                            Write-Host "Size         : " -NoNewline -ForegroundColor Yellow
                                            Write-Host "$($scriptFileDetails.Size) MB" -ForegroundColor DarkGray
                                        }
                                        if ($scriptFileDetails.SHA256 -ne 'N/A') {
                                            Write-Host "Exec SHA256  : " -NoNewline -ForegroundColor Yellow
                                            Write-Host $scriptFileDetails.SHA256 -ForegroundColor Gray
                                        }
                                    }
                                    else {
                                        Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                        Write-Host "Script File Not Found" -ForegroundColor Red
                                    }
                                }

                                # Working directory information - show if working directory exists and is different from other paths
                                if ($workingDir -and $workingDir -ne $resolvedExecutable -and $workingDir -ne $scriptFile -and $workingDirDetails -and $workingDirDetails.Exists) {
                                    Write-Host ""
                                    Write-Host "--- Working Directory ---" -ForegroundColor DarkCyan
                                    Write-Host "Path         : " -NoNewline -ForegroundColor Yellow
                                    Write-Host $workingDirDetails.Path -ForegroundColor Cyan

                                    if ($workingDirDetails.Created -ne 'N/A') {
                                        Write-Host "Created      : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $workingDirDetails.Created) -ForegroundColor DarkGray
                                    }
                                    if ($workingDirDetails.Modified -ne 'N/A') {
                                        Write-Host "Modified     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $workingDirDetails.Modified) -ForegroundColor DarkGray
                                    }
                                    if ($workingDirDetails.Accessed -ne 'N/A') {
                                        Write-Host "Accessed     : " -NoNewline -ForegroundColor Yellow
                                        Write-Host (Format-DateTime -DateTime $workingDirDetails.Accessed) -ForegroundColor DarkGray
                                    }
                                }

                                # Show triggers - always show with status message if none available
                                Write-Host ""
                                Write-Host "--- Triggers ---" -ForegroundColor DarkCyan
                                if ($task.Triggers -and $task.Triggers.Count -gt 0) {
                                    $hasValidTriggers = $false
                                    $triggerOutput = @()

                                    foreach ($trigger in $task.Triggers) {
                                        try {
                                            $triggerType = $trigger.CimClass.CimClassName -replace 'MSFT_TaskTrigger', '' -replace 'Trigger', ''
                                            $triggerLines = @()

                                            if ($triggerType) {
                                                $triggerLines += "Type         : $triggerType"
                                                $hasValidTriggers = $true
                                            }
                                            if ($trigger.StartBoundary) {
                                                $triggerLines += "Start Time   : $($trigger.StartBoundary)"
                                                $hasValidTriggers = $true
                                            }
                                            if ($trigger.Enabled -eq $false) {
                                                $triggerLines += "Status       : Disabled"
                                                $hasValidTriggers = $true
                                            }

                                            if ($triggerLines.Count -gt 0) {
                                                $triggerOutput += $triggerLines
                                            }
                                        }
                                        catch {
                                            # Continue if trigger parsing fails
                                        }
                                    }

                                    # Display triggers or status message
                                    if ($hasValidTriggers) {
                                        foreach ($line in $triggerOutput) {
                                            if ($line -like "Type*") {
                                                Write-Host "Type         : " -NoNewline -ForegroundColor Yellow
                                                Write-Host ($line -replace "Type         : ", "") -ForegroundColor DarkGray
                                            }
                                            elseif ($line -like "Start Time*") {
                                                Write-Host "Start Time   : " -NoNewline -ForegroundColor Yellow
                                                Write-Host ($line -replace "Start Time   : ", "") -ForegroundColor DarkGray
                                            }
                                            elseif ($line -like "Status*") {
                                                Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                                Write-Host ($line -replace "Status       : ", "") -ForegroundColor Red
                                            }
                                        }
                                    }
                                    else {
                                        Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                        Write-Host "Trigger Information Unavailable" -ForegroundColor DarkGray
                                    }
                                }
                                else {
                                    Write-Host "Status       : " -NoNewline -ForegroundColor Yellow
                                    Write-Host "No Triggers Found" -ForegroundColor DarkGray
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Error processing action for task '$($task.TaskName)': $($_.Exception.Message)"
                            continue
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing task '$($task.TaskName)': $($_.Exception.Message)"
                    continue
                }
            }

            # Export to CSV if requested
            if (-not [string]::IsNullOrWhiteSpace($OutputCSV) -and $script:TaskResults.Count -gt 0) {
                try {
                    $csvPath = Get-CSVFileName -OutputPath $OutputCSV
                    if ($csvPath) {
                        # Ensure parent directory exists
                        $parentDir = Split-Path $csvPath -Parent
                        if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path $parentDir -PathType Container)) {
                            New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction Stop | Out-Null
                        }
                        
                        # Prepare CSV data with sanitized values
                        $csvData = $script:TaskResults | ForEach-Object {
                            [PSCustomObject]@{
                                TaskName           = Sanitize-CSVValue $_.TaskName
                                TaskPath           = Sanitize-CSVValue $_.TaskPath
                                State              = Sanitize-CSVValue $_.State
                                Author             = Sanitize-CSVValue $_.Author
                                Description        = Sanitize-CSVValue $_.Description
                                LastRunTime        = if ($_.LastRunTime) { $_.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                                NextRunTime        = if ($_.NextRunTime) { $_.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                                TaskFilePath       = Sanitize-CSVValue $_.TaskFilePath
                                TaskFileExists     = $_.TaskFileExists
                                TaskFileSHA256     = Sanitize-CSVValue $_.TaskFileSHA256
                                TaskFileModified   = if ($_.TaskFileModified -ne 'N/A') { $_.TaskFileModified.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                                ExecutablePath     = Sanitize-CSVValue $_.ExecutablePath
                                ExecutableExists   = $_.ExecutableExists
                                ExecutableSHA256   = Sanitize-CSVValue $_.ExecutableSHA256
                                ExecutableModified = if ($_.ExecutableModified -ne 'N/A') { $_.ExecutableModified.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                                Arguments          = Sanitize-CSVValue $_.Arguments
                                ScriptFilePath     = Sanitize-CSVValue $_.ScriptFilePath
                                ScriptFileExists   = $_.ScriptFileExists
                                ScriptFileSHA256   = Sanitize-CSVValue $_.ScriptFileSHA256
                                WorkingDirectory   = Sanitize-CSVValue $_.WorkingDirectory
                                TriggerTypes       = Sanitize-CSVValue $_.TriggerTypes
                                Hostname           = Sanitize-CSVValue $_.Hostname
                            }
                        }
            
                        # Export to CSV
                        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            
                        if (-not $Quiet) {
                            Write-Host "`nResults exported to CSV: $csvPath" -ForegroundColor Green
                        }
                        Write-Verbose "[INFO]: CSV export successful: $csvPath"
                    }
                }
                catch {
                    Write-Warning "Failed to export CSV: $($_.Exception.Message)"
                    Write-Verbose "[ERROR]: CSV export failed: $($_.Exception.Message)"
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($OutputCSV) -and $script:TaskResults.Count -eq 0) {
                Write-Warning "No results to export to CSV."
            }

            # Summary and return logic
            if (-not $Quiet) {
                Write-Host ""
                Write-Host ""
                Write-Host "----------------------------------------" -ForegroundColor Gray
            }

            Write-Verbose "[INFO]: Enumerated $taskCount tasks with $matchCount actions."
            if ($Search) {
                Write-Verbose "[INFO]: Search filter applied: '$Search'" 
            }
            if (-not $IncludeDisabled) {
                Write-Verbose "[INFO]: Disabled tasks excluded." 
            }
            if (-not [string]::IsNullOrWhiteSpace($OutputCSV)) {
                Write-Verbose "[INFO]: CSV output requested: $OutputCSV"
            }

            # Complete progress
            Write-Progress -Activity "Enumerating Scheduled Tasks" -Status "Complete" -PercentComplete 100 -Completed

            # Return objects only if PassThru is specified
            if ($PassThru) {
                return $script:TaskResults
            }
        }
        catch {
            Write-Host "[ERROR]: Failed to enumerate scheduled tasks: $($_.Exception.Message)" -ForegroundColor Red
            if ($PassThru) {
                return @()
            }
        }
    }
}


function Hunt-Registry {
    <#
.SYNOPSIS
Hunt-Registry searches Windows registry for specified strings and autorun persistence locations.

.DESCRIPTION
Hunt-Registry is a DFIR function that searches the Windows registry for specified strings across keys, values, and data. 
It can also enumerate all autorun registry locations commonly used for persistence. The function supports searching 
specific registry hives, loading unloaded user profiles, and exporting results to CSV format.

.PARAMETER Search
Array of strings to search for in registry keys, value names, and value data. Not required when using -RunKeys.

.PARAMETER Type
Specifies what to search: Key, Value, StringValue, BinaryValue, DWordValue, QWordValue, MultiStringValue, ExpandStringValue, or All.

.PARAMETER Hive
Specifies which registry hive to search: HKLM, HKCU, HKCR, HKU, HKCC, or All.

.PARAMETER RunKeys
Switch to retrieve all autorun registry locations instead of searching for specific strings.

.PARAMETER LoadHives
Switch to load unloaded user registry hives. Requires administrator privileges.

.PARAMETER PassThru
Switch to return results as PowerShell objects instead of just displaying them.

.PARAMETER OutputCSV
Path to export results to CSV. Can be a file path or directory path (will auto-generate filename).

.PARAMETER Quiet
Switch to suppress console output (errors and warnings still shown).

.EXAMPLE
Hunt-Registry -Search @("malware", "backdoor") -Type All
Searches all registry hives for keys, values, or data containing "malware" or "backdoor".

.EXAMPLE
Hunt-Registry -RunKeys -OutputCSV "C:\Reports\"
Retrieves all autorun registry locations and exports to CSV in C:\Reports\ directory.

.EXAMPLE
Hunt-Registry -Search @("powershell.exe") -Hive HKLM -Type StringValue -PassThru -Quiet
Searches HKLM for string values containing "powershell.exe", returns objects silently.

.EXAMPLE
Hunt-Registry -Search @("evil.exe") -LoadHives -PassThru
Searches all hives including unloaded user profiles for "evil.exe".
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Search = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Key', 'Value', 'StringValue', 'BinaryValue', 'DWordValue', 'QWordValue', 'MultiStringValue', 'ExpandStringValue', 'All')]
        [string]$Type = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC', 'All')]
        [string]$Hive = 'All',

        [Parameter(Mandatory = $false)]
        [switch]$RunKeys,

        [Parameter(Mandatory = $false)]
        [switch]$LoadHives,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [string]$OutputCSV,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($null -eq $isAdmin -or -not $isAdmin) {
        Write-Warning "Not running as Administrator, insufficient privileges may cause detection issues..."
    }

    # Store hive parameter in script scope to avoid validation conflicts
    $script:HiveFilter = $Hive

    # Initialize variables
    $hostname = $env:COMPUTERNAME
    $results = @()
    $script:mountedHives = @()

    # Known Run keys from Hunt-Persistence
    $runKeyPaths = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\System'
    )


    function ConvertTo-SafeCSV {
        param($Results)
    
        foreach ($result in $Results) {
            # Sanitize each property to be Excel-safe
            $result.KeyPath = Format-ExcelSafeString $result.KeyPath
            $result.ValueName = Format-ExcelSafeString $result.ValueName
            $result.ValueData = Format-ExcelSafeString $result.ValueData
            $result.SearchTerm = Format-ExcelSafeString $result.SearchTerm
            $result.MatchLocation = Format-ExcelSafeString $result.MatchLocation
            $result.Hostname = Format-ExcelSafeString $result.Hostname
            $result.Hive = Format-ExcelSafeString $result.Hive
            $result.ValueType = Format-ExcelSafeString $result.ValueType
        }
        return $Results
    }

    function Export-ResultsToCSV {
        param(
            [array]$Results,
            [string]$OutputPath
        )

        try {
            # Determine output file path
            if (Test-Path $OutputPath -PathType Container -ErrorAction SilentlyContinue) {
                # It's a directory, generate filename
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $filename = "Hunt-Registry_Results_$timestamp.csv"
                $fullPath = Join-Path $OutputPath $filename
            }
            else {
                # It's a file path
                $directory = Split-Path $OutputPath -Parent
                if (-not [string]::IsNullOrEmpty($directory) -and !(Test-Path $directory -ErrorAction SilentlyContinue)) {
                    New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
                }
                $fullPath = $OutputPath
            }
    
            # Ensure .csv extension
            if (![System.IO.Path]::HasExtension($fullPath) -or [System.IO.Path]::GetExtension($fullPath) -ne '.csv') {
                $fullPath += '.csv'
            }
    
            # Sanitize results for Excel
            $safeResults = ConvertTo-SafeCSV $Results
    
            # Export to CSV with error handling
            $safeResults | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    
            if (-not $Quiet) {
                Write-Host "[CSV] Results exported to: $fullPath" -ForegroundColor Green
            }
    
            return $fullPath
        }
        catch {
            Write-Warning "Failed to export CSV: $($_.Exception.Message)"
            return $null
        }
    }

    function Format-ExcelSafeString {
        param([string]$InputString)
    
        if ([string]::IsNullOrEmpty($InputString)) {
            return ""
        }
    
        # Remove or escape dangerous characters
        $safeString = $InputString -replace '^=', "'=" -replace '^@', "'@" -replace '^\+', "'+" -replace '^-', "'-"
    
        # Remove control characters and non-printable characters
        $safeString = $safeString -replace '[\x00-\x1F\x7F]', ''
    
        # Escape double quotes by doubling them
        $safeString = $safeString -replace '"', '""'
    
        # Truncate if too long for Excel (32,767 character limit per cell)
        if ($safeString.Length -gt 32000) {
            $safeString = $safeString.Substring(0, 32000) + "...[TRUNCATED]"
        }
    
        return $safeString
    }

    function Get-AllRegistryHives {
        [CmdletBinding()]
        param([Switch]$Unloaded)
    
        $hiveList = [Collections.ArrayList]::new()
    
        if ($Unloaded) {
            if (-not $isAdmin) {
                Write-Warning "Administrator privileges required for -LoadHives. Continuing with loaded hives only."
                $Unloaded = $false
            }
        }
    
        # Add main hives based on parent $Hive parameter
        if ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKLM') {
            $hklm = Get-Item Registry::HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
            if ($hklm) { $null = $hiveList.Add($hklm.PSPath) }
        }
    
        if ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKCU') {
            $hkcu = Get-Item Registry::HKEY_CURRENT_USER -ErrorAction SilentlyContinue
            if ($hkcu) { $null = $hiveList.Add($hkcu.PSPath) }
        }
    
        if ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKCR') {
            $hkcr = Get-Item Registry::HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue
            if ($hkcr) { $null = $hiveList.Add($hkcr.PSPath) }
        }
    
        if ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKU') {
            $loadedUserHives = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue
            foreach ($hiveItem in $loadedUserHives) {
                $null = $hiveList.Add($hiveItem.PSPath)
            }
        }
    
        if ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKCC') {
            $hkcc = Get-Item Registry::HKEY_CURRENT_CONFIG -ErrorAction SilentlyContinue
            if ($hkcc) { $null = $hiveList.Add($hkcc.PSPath) }
        }
    
        # Load unloaded user profiles if requested
        if ($Unloaded -and ($script:HiveFilter -eq 'All' -or $script:HiveFilter -eq 'HKU')) {
            if (-not $Quiet) {
                Write-Host "[INFO] Loading unloaded user registry hives..." -ForegroundColor Yellow
            }
        
            try {
                $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                $profiles = Get-ChildItem $profileListPath -ErrorAction Stop
            
                foreach ($profile in $profiles) {
                    $sid = Split-Path $profile.Name -Leaf
                
                    $alreadyLoaded = $loadedUserHives | Where-Object { $_.Name -like "*$sid*" }
                    if ($alreadyLoaded) { continue }
                
                    $profileData = Get-ItemProperty $profile.PSPath -ErrorAction SilentlyContinue
                    if ($null -eq $profileData.ProfileImagePath) { continue }
                
                    $ntUserPath = Join-Path $profileData.ProfileImagePath "NTUSER.DAT"
                
                    if (Test-Path $ntUserPath -ErrorAction SilentlyContinue) {
                        $mountPoint = "TEMP_HUNT_REG_$($sid.Replace('-','_'))"
                    
                        try {
                            $result = & reg.exe load "HKLM\$mountPoint" $ntUserPath 2>$null
                            if ($LASTEXITCODE -eq 0) {
                                $mountedHivePath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\$mountPoint"
                                $null = $hiveList.Add($mountedHivePath)
                                $script:mountedHives += $mountPoint
                                Write-Verbose "Mounted unloaded profile: $sid"
                            }
                        }
                        catch {
                            Write-Verbose "Error mounting profile $sid : $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to enumerate user profiles: $($_.Exception.Message)"
            }
        }
    
        return $hiveList
    }

    function Dismount-TemporaryHives {
        if ($script:mountedHives -and $script:mountedHives.Count -gt 0) {
            if (-not $Quiet) {
                Write-Host "[CLEANUP] Dismounting temporary registry hives..." -ForegroundColor Yellow
            }
            
            foreach ($mountPoint in $script:mountedHives) {
                try {
                    $result = & reg.exe unload "HKLM\$mountPoint" 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Successfully dismounted: $mountPoint"
                    }
                }
                catch {
                    Write-Warning "Error dismounting $mountPoint : $($_.Exception.Message)"
                }
            }
            $script:mountedHives = @()
        }
    }

    function New-RegistryResult {
        param(
            [string]$Hostname,
            [string]$HiveName,
            [string]$KeyPath,
            [string]$ValueName = $null,
            [string]$ValueType = $null,
            [string]$ValueData = $null,
            [string]$SearchTerm,
            [string]$MatchLocation
        )
        
        return [PSCustomObject]@{
            Hostname      = $Hostname
            Hive          = $HiveName
            KeyPath       = $KeyPath
            ValueName     = $ValueName
            ValueType     = $ValueType
            ValueData     = $ValueData
            SearchTerm    = $SearchTerm
            MatchLocation = $MatchLocation
        }
    }

    function Search-RegistryRecursive {
        param(
            [string]$HivePath,
            [string[]]$SearchTerms,
            [string]$SearchType
        )

        $hiveResults = @()

        # Add progress tracking
        $totalKeys = 0
        $processedKeys = 0

        # Extract hive name from PSPath format
        if ($HivePath -like "*Registry::HKEY_LOCAL_MACHINE*") {
            $hiveName = "HKEY_LOCAL_MACHINE"
        }
        elseif ($HivePath -like "*Registry::HKEY_CURRENT_USER*") {
            $hiveName = "HKEY_CURRENT_USER"
        }
        elseif ($HivePath -like "*Registry::HKEY_CLASSES_ROOT*") {
            $hiveName = "HKEY_CLASSES_ROOT"
        }
        elseif ($HivePath -like "*Registry::HKEY_USERS*") {
            $hiveName = "HKEY_USERS"
        }
        elseif ($HivePath -like "*Registry::HKEY_CURRENT_CONFIG*") {
            $hiveName = "HKEY_CURRENT_CONFIG"
        }
        else {
            $hiveName = Split-Path $HivePath -Leaf
        }

        try {
            $keys = Get-ChildItem -Path $HivePath -Recurse -ErrorAction SilentlyContinue
            $totalKeys = $keys.Count
    
            if (-not $Quiet -and $totalKeys -gt 0) {
                Write-Progress -Activity "Searching Registry" -Status "Processing $hiveName" -PercentComplete 0
            }
    
            foreach ($key in $keys) {
                $processedKeys++
        
                if (-not $Quiet -and $totalKeys -gt 0 -and ($processedKeys % 100) -eq 0) {
                    $percentComplete = [math]::Round(($processedKeys / $totalKeys) * 100)
                    Write-Progress -Activity "Searching Registry" -Status "Processing $hiveName ($processedKeys of $totalKeys)" -PercentComplete $percentComplete
                }
            
                try {
                    $keyPath = $key.Name
            
                    # Search in key names if applicable
                    if ($SearchType -eq 'All' -or $SearchType -eq 'Key') {
                        foreach ($searchTerm in $SearchTerms) {
                            if ($keyPath -like "*$searchTerm*") {
                                $hiveResults += New-RegistryResult -Hostname $hostname -HiveName $hiveName -KeyPath $keyPath -SearchTerm $searchTerm -MatchLocation "Key Name"
                            }
                        }
                    }
            
                    # Search in values if applicable
                    if ($SearchType -eq 'All' -or $SearchType -in @('Value', 'StringValue', 'BinaryValue', 'DWordValue', 'QWordValue', 'MultiStringValue', 'ExpandStringValue')) {
                        try {
                            $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            if ($properties) {
                                $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
                        
                                foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $properties)) {
                                    if ($psProperties.Contains($prop.Name)) { continue }
                            
                                    $valueName = $prop.Name
                                    $valueData = $properties.($prop.Name)
                                    $valueType = "Unknown"
                            
                                    # Try to determine value type
                                    try {
                                        $regValue = Get-ItemProperty -Path $key.PSPath -Name $valueName -ErrorAction SilentlyContinue
                                        if ($regValue) {
                                            $valueType = switch ($regValue.($valueName).GetType().Name) {
                                                'String' { 'String' }
                                                'String[]' { 'MultiString' }
                                                'Int32' { 'DWord' }
                                                'Int64' { 'QWord' }
                                                'Byte[]' { 'Binary' }
                                                default { 'String' }
                                            }
                                        }
                                    }
                                    catch { }
                            
                                    # Filter by value type if specified
                                    $typeMatch = $false
                                    switch ($SearchType) {
                                        'All' { $typeMatch = $true }
                                        'Value' { $typeMatch = $true }
                                        'StringValue' { $typeMatch = ($valueType -eq 'String') }
                                        'BinaryValue' { $typeMatch = ($valueType -eq 'Binary') }
                                        'DWordValue' { $typeMatch = ($valueType -eq 'DWord') }
                                        'QWordValue' { $typeMatch = ($valueType -eq 'QWord') }
                                        'MultiStringValue' { $typeMatch = ($valueType -eq 'MultiString') }
                                        'ExpandStringValue' { $typeMatch = ($valueType -eq 'String') }
                                    }
                            
                                    if ($typeMatch) {
                                        # Search in value names
                                        foreach ($searchTerm in $SearchTerms) {
                                            if ($valueName -like "*$searchTerm*") {
                                                $hiveResults += New-RegistryResult -Hostname $hostname -HiveName $hiveName -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $valueData -SearchTerm $searchTerm -MatchLocation "Value Name"
                                            }
                                        }
                                
                                        # Search in value data
                                        if ($valueData) {
                                            $dataString = $valueData.ToString()
                                            foreach ($searchTerm in $SearchTerms) {
                                                if ($dataString -like "*$searchTerm*") {
                                                    $hiveResults += New-RegistryResult -Hostname $hostname -HiveName $hiveName -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $valueData -SearchTerm $searchTerm -MatchLocation "Value Data"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { continue }
            }
        }
        catch { }

        # Move the Write-Progress completion outside the loops - this was the critical bug
        if (-not $Quiet) {
            Write-Progress -Activity "Searching Registry" -Completed
        }

        return $hiveResults
    }

    function Get-RunKeysOnly {
        $runResults = @()
    
        try {
            $systemAndUsersHives = Get-AllRegistryHives -Unloaded:$LoadHives
    
            if (-not $Quiet) {
                Write-Progress -Activity "Retrieving Autorun Keys" -Status "Processing registry hives" -PercentComplete 0
            }
        
            $hiveCount = 0
            $totalHives = $systemAndUsersHives.Count
        
            foreach ($registryHive in $systemAndUsersHives) {
                $hiveCount++
            
                if (-not $Quiet -and $totalHives -gt 0) {
                    $percentComplete = [math]::Round(($hiveCount / $totalHives) * 100)
                    Write-Progress -Activity "Retrieving Autorun Keys" -Status "Processing hive $hiveCount of $totalHives" -PercentComplete $percentComplete
                }
            
                # Extract hive name from PSPath format
                if ($registryHive -like "*Registry::HKEY_LOCAL_MACHINE*") {
                    $hiveName = "HKEY_LOCAL_MACHINE"
                }
                elseif ($registryHive -like "*Registry::HKEY_CURRENT_USER*") {
                    $hiveName = "HKEY_CURRENT_USER"
                }
                elseif ($registryHive -like "*Registry::HKEY_CLASSES_ROOT*") {
                    $hiveName = "HKEY_CLASSES_ROOT"
                }
                elseif ($registryHive -like "*Registry::HKEY_USERS*") {
                    $hiveName = "HKEY_USERS"
                }
                elseif ($registryHive -like "*Registry::HKEY_CURRENT_CONFIG*") {
                    $hiveName = "HKEY_CURRENT_CONFIG"
                }
                else {
                    $hiveName = Split-Path $registryHive -Leaf
                }
    
                foreach ($runPath in $runKeyPaths) {
                    try {
                        $fullPath = "$registryHive\$runPath"
                        $runProps = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue
            
                        if ($null -ne $runProps) {
                            $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
                
                            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps)) {
                                if ($psProperties.Contains($prop.Name)) { continue }
                    
                                $runResults += New-RegistryResult -Hostname $hostname -HiveName $hiveName -KeyPath $runPath -ValueName $prop.Name -ValueType "String" -ValueData $runProps.($prop.Name) -SearchTerm "RunKey" -MatchLocation "Autorun Location"
                            }
                        }
                    }
                    catch { 
                        Write-Verbose "Error accessing run key $runPath in $hiveName : $($_.Exception.Message)"
                        continue 
                    }
                }
            }
        
            if (-not $Quiet) {
                Write-Progress -Activity "Retrieving Autorun Keys" -Completed
            }
        }
        catch {
            Write-Warning "Error retrieving run keys: $($_.Exception.Message)"
            if (-not $Quiet) {
                Write-Progress -Activity "Retrieving Autorun Keys" -Completed
            }
        }

        return $runResults
    }

    function Write-ColoredRegistryResult {
        param($RegistryResult)
        
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Gray     
        Write-Host "Hive             : " -NoNewline -ForegroundColor Yellow
        Write-Host $RegistryResult.Hive -ForegroundColor White
        
        Write-Host "Key Path         : " -NoNewline -ForegroundColor Yellow
        Write-Host $RegistryResult.KeyPath -ForegroundColor Cyan
        
        if ($RegistryResult.ValueName) {
            Write-Host "Value Name       : " -NoNewline -ForegroundColor Yellow
            Write-Host $RegistryResult.ValueName -ForegroundColor DarkYellow
            
            if ($RegistryResult.ValueType) {
                Write-Host "Value Type       : " -NoNewline -ForegroundColor Yellow
                Write-Host $RegistryResult.ValueType -ForegroundColor White
            }
            
            if ($RegistryResult.ValueData) {
                Write-Host "Value Data       : " -NoNewline -ForegroundColor Yellow
                Write-Host $RegistryResult.ValueData -ForegroundColor Red
            }
        }
        
        Write-Host "Search Term      : " -NoNewline -ForegroundColor Yellow
        Write-Host $RegistryResult.SearchTerm -ForegroundColor DarkGray
        
        Write-Host "Match Location   : " -NoNewline -ForegroundColor Yellow
        Write-Host $RegistryResult.MatchLocation -ForegroundColor DarkGray

        Write-Host "Hostname         : " -NoNewline -ForegroundColor Yellow
        Write-Host $RegistryResult.Hostname -ForegroundColor DarkGray
    }

    # Main execution logic
    try {
        Write-Verbose "Starting Hunt-Registry execution..."
        
        # Handle RunKeys mode
        if ($RunKeys) {
            if (-not $Quiet) {
                Write-Host "[INFO] Retrieving all autorun registry locations..." -ForegroundColor Yellow
            }
            
            $results = Get-RunKeysOnly
        }
        else {
            # Validate search parameters
            if ($Search.Count -eq 0) {
                Write-Error "Search parameter is required when not using -RunKeys"
                return
            }
            
            if (-not $Quiet) {
                Write-Host "[INFO] Searching registry for: $($Search -join ', ')" -ForegroundColor Yellow
                Write-Host "[INFO] Search Type: $Type, Hive: $script:HiveFilter" -ForegroundColor Cyan
            }
            
            # Get registry hives
            $systemAndUsersHives = Get-AllRegistryHives -Unloaded:$LoadHives
            
            # Search each hive
            foreach ($registryHive in $systemAndUsersHives) {
                try {
                    if (-not $Quiet) {
                        # Extract hive name for display
                        if ($registryHive -like "*Registry::HKEY_LOCAL_MACHINE*") {
                            $displayHiveName = "HKEY_LOCAL_MACHINE"
                        }
                        elseif ($registryHive -like "*Registry::HKEY_CURRENT_USER*") {
                            $displayHiveName = "HKEY_CURRENT_USER"
                        }
                        elseif ($registryHive -like "*Registry::HKEY_CLASSES_ROOT*") {
                            $displayHiveName = "HKEY_CLASSES_ROOT"
                        }
                        elseif ($registryHive -like "*Registry::HKEY_USERS*") {
                            $displayHiveName = "HKEY_USERS"
                        }
                        elseif ($registryHive -like "*Registry::HKEY_CURRENT_CONFIG*") {
                            $displayHiveName = "HKEY_CURRENT_CONFIG"
                        }
                        else {
                            $displayHiveName = Split-Path $registryHive -Leaf
                        }
                        Write-Host "[SEARCH] Processing hive: $displayHiveName" -ForegroundColor Cyan
                    }
        
                    $hiveResults = Search-RegistryRecursive -HivePath $registryHive -SearchTerms $Search -SearchType $Type
                    if ($hiveResults) {
                        $results += $hiveResults
                    }
                }
                catch {
                    Write-Verbose "Error searching hive $registryHive : $($_.Exception.Message)"
                    continue
                }
            }
        }
        
        # Display results
        if ($results.Count -gt 0) {
            if (-not $Quiet) {
                Write-Host "`n[RESULTS] Found $($results.Count) registry matches" -ForegroundColor Green
                
                foreach ($result in $results) {
                    Write-ColoredRegistryResult $result
                }
            }
            
            # Export to CSV if requested
            if ($OutputCSV) {
                $csvPath = Export-ResultsToCSV -Results $results -OutputPath $OutputCSV
                if ($csvPath -and $PassThru) {
                    # Add CSV path property to results for PassThru
                    foreach ($result in $results) {
                        $result | Add-Member -MemberType NoteProperty -Name 'CSVExportPath' -Value $csvPath -Force
                    }
                }
            }
            
            if ($PassThru) {
                return $results
            }
        }
        else {
            if (-not $Quiet) {
                Write-Host "`n[INFO] No registry matches found" -ForegroundColor Yellow
            }
            
            # Create empty CSV if requested
            if ($OutputCSV) {
                Export-ResultsToCSV -Results @() -OutputPath $OutputCSV | Out-Null
            }
            
            if ($PassThru) {
                return @()
            }
        }
    }
    catch {
        Write-Error "Hunt-Registry failed: $($_.Exception.Message)"
        if ($PassThru) {
            return @()
        }
    }
    finally {
        # Cleanup loaded hives
        if ($LoadHives) {
            Dismount-TemporaryHives
        }
    }
}


function Hunt-Services {
    <#
    .SYNOPSIS
    Hunt-Services enumerates and analyzes Windows services for DFIR investigations.
    
    .DESCRIPTION
    Hunt-Services provides comprehensive analysis of Windows services including:
    - Service metadata (name, display name, status, start type)
    - Executable file analysis with SHA256 hashes and timestamps
    - Service configuration details (account, dependencies)
    - Search filtering across all service properties
    - CSV export with Excel-compatible sanitization
    - Silent operation mode for automation
    
    This function is designed for digital forensics, incident response, threat hunting,
    and security auditing activities where comprehensive service analysis is required.
    
    .PARAMETER Search
    Filter results using wildcard patterns. Searches across service names, paths, descriptions,
    accounts, and all other service properties. Case-insensitive matching.
    
    .PARAMETER Type
    Filter services by start type: Automatic, Manual, Disabled, Boot, System, or All.
    
    .PARAMETER PassThru
    Return PowerShell objects for further processing instead of just displaying results.
    
    .PARAMETER Quiet
    Suppress console output except for errors and warnings.
    
    .PARAMETER OutputCSV
    Export results to CSV format. Accepts either:
    - Full file path: "C:\Analysis\services.csv"
    - Directory path: "C:\Analysis\" (auto-generates filename with timestamp)
    
    .EXAMPLE
    Hunt-Services
    Display all Windows services with full analysis.
    
    .EXAMPLE
    Hunt-Services -Search "*malware*" -Type Automatic
    Search for automatic services containing "malware" in any field.
    
    .EXAMPLE
    Hunt-Services -OutputCSV "C:\DFIR\Analysis\"
    Export all service analysis to auto-generated CSV file.
    
    .EXAMPLE
    $suspiciousServices = Hunt-Services -Search "*persist*" -PassThru -Quiet
    Silently collect services with "persist" in any field, return as objects.
    
    .EXAMPLE
    Hunt-Services -Type Disabled -OutputCSV ".\disabled_services.csv"
    Find all disabled services and export to CSV.
    
    .NOTES
    Requirements: PowerShell 5.0+, Windows
    Privileges: Administrator recommended for complete service enumeration
    Output: Displays forensic analysis or returns PSCustomObjects via -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Search = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Automatic', 'Manual', 'Disabled', 'Boot', 'System', 'All')]
        [string]$Type = 'All',

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false)]
        [string]$OutputCSV = ""
    )

    # Get-FileFromCommandLine function embedded
    function Get-FileFromCommandLine {
        param([String]$CommandLine)

        if ([string]::IsNullOrWhiteSpace($CommandLine)) {
            return $null
        }

        try {
            $expanded = [System.Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
        
            # COMPATTELRUNNER.EXE with -m: parameter
            if ($expanded -match '(.*compattelrunner\.exe)\s+-m:') {
                return $matches[1]
            }
        
            # CMD.EXE executing files
            if ($expanded -match 'cmd\.exe.*?/[dc]\s+"([^"]+\.(cmd|bat|ps1|vbs|js))"') {
                return $matches[1]
            }
            if ($expanded -match 'cmd\.exe.*?/[dc]\s+([^"\s]+\.(cmd|bat|ps1|vbs|js))') {
                return $matches[1]
            }
        
            # POWERSHELL.EXE executing files
            if ($expanded -match 'powershell\.exe.*?-[Ff]ile\s+"?([^"\s]+\.(ps1|bat|cmd|exe|vbs|js))"?') {
                return $matches[1]
            }
            if ($expanded -match 'powershell\.exe.*?"[^"]*([A-Za-z]:\\[^"]*\.(ps1|bat|cmd|exe|vbs|js|dll))[^"]*"') {
                return $matches[1]
            }
        
            # NODE.EXE, PYTHON.EXE, WSCRIPT/CSCRIPT.EXE, MSHTA.EXE
            if ($expanded -match 'node\.exe\s+"?([^"\s]+\.js)"?') {
                return $matches[1]
            }
            if ($expanded -match 'python\.exe\s+"?([^"\s]+\.py)"?') {
                return $matches[1]
            }
            if ($expanded -match '(?:wscript|cscript)\.exe\s+"?([^"\s]+\.(vbs|js|wsf))"?') {
                return $matches[1]
            }
            if ($expanded -match 'mshta\.exe\s+"?([^"\s]+\.hta)"?') {
                return $matches[1]
            }
        
            # REGSVR32.EXE and RUNDLL32.EXE
            if ($expanded -match 'regsvr32\.exe.*?\s+"?([^"\s]+\.dll)"?') {
                return $matches[1]
            }
            if ($expanded -match 'rundll32\.exe\s+([^,\s]+\.dll)') {
                return $matches[1]
            }
        
            # MSIEXEC.EXE and SCHTASKS.EXE
            if ($expanded -match 'msiexec\.exe.*?[/\-]i\s+"?([^"\s]+\.msi)"?') {
                return $matches[1]
            }
            if ($expanded -match 'schtasks\.exe.*?/TR\s+"?([^"\s]+\.(exe|bat|cmd|ps1))"?') {
                return $matches[1]
            }
        
            # Quoted paths
            if ($expanded -match '"([^"]+\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))"') {
                return $matches[1]
            }
        
            # Simple drive paths
            if ($expanded -match '^([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))(\s|$)') {
                return $matches[1].Trim() -replace '[,;]+$', ''
            }
        
            # Drive paths with arguments
            if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))\s+[-/]') {
                return $matches[1].Trim()
            }
        
            # UNC paths
            if ($expanded -match '(\\\\[^\\]+\\[^\s"]+\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr))') {
                return $matches[1].Trim()
            }
        
            # Simple executable names
            if ($expanded -match '^([a-zA-Z][a-zA-Z0-9]*\.(exe|com|scr|dll))(\s|$)') {
                return $matches[1]
            }
        
            # Any executable file in command line
            if ($expanded -match '([A-Za-z]:[^"]*\.(exe|dll|bat|cmd|ps1|vbs|js|msi|com|scr|lnk|cpl|hta|wsf))') {
                return $matches[1] -replace '[,;]+$', ''
            }
        
            return $expanded.Trim()
        }
        catch {
            return $CommandLine.Trim()
        }
    }

    # Get the true service executable (including DLLs for svchost services)
    function Get-ServiceExecutable {
        param([string]$ServiceName, [string]$CommandLine)
        
        try {
            $cmdLineExe = Get-FileFromCommandLine -CommandLine $CommandLine
            
            if ($cmdLineExe -and $cmdLineExe -match 'svchost\.exe$') {
                try {
                    # Method 1: Check Parameters subkey for ServiceDll
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
                    if (Test-Path $regPath -ErrorAction SilentlyContinue) {
                        $serviceDll = (Get-ItemProperty $regPath -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
                        if ($serviceDll) {
                            return [Environment]::ExpandEnvironmentVariables($serviceDll)
                        }
                    }
                    
                    # Method 2: Check main service key for ServiceDll
                    $regPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                    if (Test-Path $regPath2 -ErrorAction SilentlyContinue) {
                        $serviceReg = Get-ItemProperty $regPath2 -ErrorAction SilentlyContinue
                        
                        if ($serviceReg.ServiceDll) {
                            return [Environment]::ExpandEnvironmentVariables($serviceReg.ServiceDll)
                        }
                        
                        # Method 3: Extract DLL path from Description field (for services like AarSvc_2cf489)
                        if ($serviceReg.Description -and $serviceReg.Description -match '@([^,]+\.dll)') {
                            $dllPath = [Environment]::ExpandEnvironmentVariables($matches[1])
                            if (Test-Path $dllPath -ErrorAction SilentlyContinue) {
                                return $dllPath
                            }
                        }
                        
                        # Method 4: Try service name as DLL name (remove suffix after underscore)
                        $baseName = $ServiceName -replace '_.*$', ''
                        $possibleDll = "$env:SystemRoot\system32\$baseName.dll"
                        if (Test-Path $possibleDll -ErrorAction SilentlyContinue) {
                            return $possibleDll
                        }
                        
                        # Method 5: Try full service name as DLL
                        $possibleDll2 = "$env:SystemRoot\system32\$ServiceName.dll"
                        if (Test-Path $possibleDll2 -ErrorAction SilentlyContinue) {
                            return $possibleDll2
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve service DLL for $ServiceName"
                }
                return $cmdLineExe
            }
            
            return $cmdLineExe
        }
        catch {
            return $CommandLine
        }
    }

    # Get SHA256 hash
    function Get-FileSHA256 {
        param([string]$FilePath)
        try {
            if (Test-Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue) {
                $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
                return $hash.Hash.ToLower()
            }
        }
        catch { }
        return $null
    }

    # Test search matches - optimized with early return
    function Test-ServiceMatches {
        param($Service, $ServiceDetails, $Search)
        
        if ($Search.Count -eq 0) { return $true }
        
        $searchFields = @($Service.Name, $Service.DisplayName, $Service.Status, $Service.StartType)
        if ($ServiceDetails) {
            $searchFields += @($ServiceDetails.StartName, $ServiceDetails.Description, $ServiceDetails.PathName)
        }
        
        foreach ($searchString in $Search) {
            foreach ($field in $searchFields) {
                if ($field -and $field -like "*$searchString*") {
                    return $true
                }
            }
        }
        return $false
    }

    # Sanitize CSV values
    function Sanitize-CSVValue {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
        try {
            $sanitized = $Value -replace '[\x00-\x1F\x7F]', ' ' -replace '["\r\n\t]', ' ' -replace '^[\+\-@=]', '_'
            return $sanitized.Trim().Substring(0, [Math]::Min($sanitized.Length, 32000))
        }
        catch { return "" }
    }

    # Get CSV filename
    function Get-CSVFileName {
        param([string]$OutputPath)
        try {
            if ([string]::IsNullOrWhiteSpace($OutputPath)) { return $null }
            
            if (Test-Path $OutputPath -PathType Container -ErrorAction SilentlyContinue) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                return Join-Path $OutputPath "Hunt-Services_Results_$($env:COMPUTERNAME)_$timestamp.csv"
            }
            elseif ($OutputPath -match '\.csv$') {
                $parentDir = Split-Path $OutputPath -Parent
                if ([string]::IsNullOrWhiteSpace($parentDir) -or (Test-Path $parentDir -PathType Container -ErrorAction SilentlyContinue)) {
                    return $OutputPath
                }
                New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction Stop | Out-Null
                return $OutputPath
            }
            return $null
        }
        catch { return $null }
    }

    # Main execution
    try {
        if (-not $Quiet) {
            Write-Host "[+] Enumerating Windows services..." -ForegroundColor Green
        }
        
        $services = Get-Service -ErrorAction Stop
        if ($Type -ne 'All') {
            $services = $services | Where-Object { $_.StartType -eq $Type }
        }

        $results = @()
        $totalServices = $services.Count
        $processedCount = 0
        $matchCount = 0
        
        foreach ($service in $services) {
            $processedCount++
            
            if ($processedCount % 50 -eq 0) {
                Write-Progress -Activity "Processing Services" -Status "$processedCount of $totalServices" -PercentComplete (($processedCount / $totalServices) * 100)
            }
            
            try {
                $serviceDetails = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
                
                if (-not (Test-ServiceMatches -Service $service -ServiceDetails $serviceDetails -Search $Search)) {
                    continue
                }
                
                $matchCount++
                
                # Get true executable path (including service DLLs)
                $truePath = $null
                $sha256 = $null
                $lastModified = $null
                
                if ($serviceDetails -and $serviceDetails.PathName) {
                    $extractedPath = Get-ServiceExecutable -ServiceName $service.Name -CommandLine $serviceDetails.PathName
                    if ($extractedPath -and (Test-Path $extractedPath -ErrorAction SilentlyContinue)) {
                        $truePath = $extractedPath
                        $fileInfo = Get-Item $extractedPath -ErrorAction SilentlyContinue
                        if ($fileInfo) {
                            $sha256 = Get-FileSHA256 -FilePath $extractedPath
                            $lastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                    }
                    elseif ($extractedPath) {
                        $truePath = $extractedPath
                    }
                }
                
                $serviceResult = [PSCustomObject]@{
                    ServiceName    = $service.Name
                    DisplayName    = $service.DisplayName
                    Status         = $service.Status
                    StartType      = $service.StartType
                    Account        = if ($serviceDetails -and $serviceDetails.StartName) { $serviceDetails.StartName } else { $null }
                    Description    = if ($serviceDetails -and $serviceDetails.Description) { $serviceDetails.Description } else { $null }
                    CommandLine    = if ($serviceDetails -and $serviceDetails.PathName) { $serviceDetails.PathName } else { $null }
                    ExecutablePath = $truePath
                    SHA256         = $sha256
                    LastModified   = $lastModified
                    Dependencies   = if ($service.DependentServices -and $service.DependentServices.Count -gt 0) { ($service.DependentServices.Name -join '; ') } else { $null }
                    CanStop        = $service.CanStop
                    Hostname       = $env:COMPUTERNAME
                }
                
                $results += $serviceResult
            }
            catch {
                Write-Verbose "Error processing service '$($service.Name)': $($_.Exception.Message)"
                continue
            }
        }
        
        Write-Progress -Activity "Processing Services" -Completed
        
        # Display results - only show fields with values
        if (-not $Quiet -and $results.Count -gt 0) {
            Write-Host "[+] Displaying $($results.Count) service matches..." -ForegroundColor Cyan
            
            foreach ($result in $results) {
                Write-Host ""
                Write-Host "----------------------------------------" -ForegroundColor Gray
                
                # Always show these core fields
                Write-Host "Service Name     : " -NoNewline -ForegroundColor Yellow
                Write-Host $result.ServiceName -ForegroundColor Cyan
                
                if ($result.DisplayName) {
                    Write-Host "Display Name     : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.DisplayName -ForegroundColor White
                }
                
                Write-Host "Status           : " -NoNewline -ForegroundColor Yellow
                $statusColor = switch ($result.Status) {
                    'Running' { 'Green' }
                    'Stopped' { 'Red' }
                    'Paused' { 'Yellow' }
                    default { 'DarkGray' }
                }
                Write-Host $result.Status -ForegroundColor $statusColor
                
                Write-Host "Start Type       : " -NoNewline -ForegroundColor Yellow
                Write-Host $result.StartType -ForegroundColor White
                
                if ($result.Account) {
                    Write-Host "Account          : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.Account -ForegroundColor White
                }
                
                if ($result.Description) {
                    Write-Host "Description      : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.Description -ForegroundColor DarkGray
                }
                
                if ($result.CommandLine) {
                    Write-Host "Command Line     : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.CommandLine -ForegroundColor Red
                }
                
                if ($result.ExecutablePath) {
                    Write-Host "Executable Path  : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.ExecutablePath -ForegroundColor Green
                }
                
                if ($result.LastModified) {
                    Write-Host "Last Modified    : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.LastModified -ForegroundColor DarkGray
                }
                
                if ($result.SHA256) {
                    Write-Host "SHA256           : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.SHA256 -ForegroundColor Gray
                }
                
                if ($result.Dependencies) {
                    Write-Host "Dependencies     : " -NoNewline -ForegroundColor Yellow
                    Write-Host $result.Dependencies -ForegroundColor DarkYellow
                }
                
                Write-Host "Can Stop         : " -NoNewline -ForegroundColor Yellow
                Write-Host $result.CanStop -ForegroundColor DarkGray
            }
        }
        
        # CSV Export
        if (-not [string]::IsNullOrWhiteSpace($OutputCSV) -and $results.Count -gt 0) {
            try {
                $csvPath = Get-CSVFileName -OutputPath $OutputCSV
                if ($csvPath) {
                    $csvData = $results | ForEach-Object {
                        [PSCustomObject]@{
                            ServiceName    = Sanitize-CSVValue $_.ServiceName
                            DisplayName    = Sanitize-CSVValue $_.DisplayName
                            Status         = Sanitize-CSVValue $_.Status
                            StartType      = Sanitize-CSVValue $_.StartType
                            Account        = if ($_.Account) { Sanitize-CSVValue $_.Account } else { "" }
                            Description    = if ($_.Description) { Sanitize-CSVValue $_.Description } else { "" }
                            CommandLine    = if ($_.CommandLine) { Sanitize-CSVValue $_.CommandLine } else { "" }
                            ExecutablePath = if ($_.ExecutablePath) { Sanitize-CSVValue $_.ExecutablePath } else { "" }
                            SHA256         = if ($_.SHA256) { Sanitize-CSVValue $_.SHA256 } else { "" }
                            LastModified   = if ($_.LastModified) { $_.LastModified } else { "" }
                            Dependencies   = if ($_.Dependencies) { Sanitize-CSVValue $_.Dependencies } else { "" }
                            CanStop        = $_.CanStop
                            Hostname       = Sanitize-CSVValue $_.Hostname
                        }
                    }
                    
                    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    
                    if (-not $Quiet) {
                        Write-Host "[+] Results exported to CSV: $csvPath" -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Warning "Failed to export CSV: $($_.Exception.Message)"
            }
        }
        
        # Summary
        if (-not $Quiet) {
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor Gray
            Write-Host "[+] Processed $processedCount services, found $matchCount matches" -ForegroundColor Green
        }
        
        if ($PassThru) {
            return $results
        }
    }
    catch {
        Write-Error "Hunt-Services failed: $($_.Exception.Message)"
        if ($PassThru) { return @() }
    }
}


function Hunt-VirusTotal {
    <#
    .SYNOPSIS
    Hunt-VirusTotal - DFIR function for VirusTotal file analysis using direct API calls
    
    .DESCRIPTION
    This function provides VirusTotal capabilities for DFIR investigations:
    - Automatically queries hash existence and uploads if not found
    - Monitors upload analysis status until completion
    - Uses direct REST API calls (no module dependencies)
    - Displays results in standardized DFIR format with rich context
    - Supports MD5, SHA1, and SHA256 hashes
    - Handles rate limiting gracefully
    
    Note: Email files (.eml) and archives may be processed by VirusTotal,
    resulting in different file hashes than the original upload.
    
    .PARAMETER FilePath
    Path to file for analysis
    
    .PARAMETER Hash
    File hash (MD5, SHA1, SHA256) to query VirusTotal
    
    .PARAMETER ApiKey
    VirusTotal API key (optional - will prompt if not provided)
    
    .PARAMETER Force
    Force upload even if file already exists in VirusTotal
    
    .PARAMETER More
    Show all available fields from VirusTotal response
    
    .PARAMETER UploadStatus
    Check status of analysis by Analysis ID
    
    .PARAMETER AnalysisId
    Analysis ID to check status for (used with -UploadStatus)
    
    .PARAMETER OutputCSV
    Output results to CSV file
    
    .PARAMETER PassThru
    Return results as PowerShell objects for further processing
    
    .PARAMETER Quiet
    Suppress console output
    
    .PARAMETER ClearSavedKey
    Delete saved API key from session
    
    .EXAMPLE
    Hunt-VirusTotal -FilePath "C:\suspect\malware.exe"
    
    .EXAMPLE
    Hunt-VirusTotal -Hash "e3c925286ccafd07fb61bd6a12a2ee94" -More
    
    .EXAMPLE
    Hunt-VirusTotal -FilePath "C:\suspect\file.exe" -OutputCSV
    
    .EXAMPLE
    Hunt-VirusTotal -Hash "abc123..." -PassThru | Where-Object {$_.Malicious -gt 0}
    
    .EXAMPLE
    Hunt-VirusTotal -FilePath "C:\batch\*.exe" -Quiet -PassThru
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [string]$Hash,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$More,
        
        [Parameter(Mandatory = $false)]
        [switch]$UploadStatus,
        
        [Parameter(Mandatory = $false)]
        [string]$AnalysisId,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputCSV,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        
        [Parameter(Mandatory = $false)]
        [switch]$ClearSavedKey
    )

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin -and -not $Quiet) {
        Write-Warning "Not running as Administrator. Some file access may be limited."
    }

    # Handle ClearSavedKey first
    if ($ClearSavedKey) {
        if ($Global:HuntVTApiKey) {
            Remove-Variable -Name "HuntVTApiKey" -Scope Global -ErrorAction SilentlyContinue
            if (-not $Quiet) { Write-Host "[+] API key cleared from session" -ForegroundColor Green }
        }
        else {
            if (-not $Quiet) { Write-Host "[!] No saved API key found" -ForegroundColor Yellow }
        }
        return
    }



    function Invoke-VTFileQuery {
        param([string]$FileHash, [string]$VTApiKey)
    
        try {
            $uri = "https://www.virustotal.com/api/v3/files/$FileHash"
            $headers = @{
                'x-apikey' = $VTApiKey
                'accept'   = 'application/json'
            }
        
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 30 -ErrorAction Stop
            return $response
        }
        catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                Write-Host "[!] Rate limit exceeded. Waiting 60 seconds..." -ForegroundColor Yellow
                Start-Sleep 60
                return $null
            }
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404) {
                return $null
            }
            throw $_
        }
    }

    function Invoke-VTFileUpload {
        param([string]$FileToUpload, [string]$VTApiKey)
    
        try {
            $fileInfo = Get-Item $FileToUpload -ErrorAction Stop
        
            if ($fileInfo.Length -gt 33554432) {
                throw "File too large for direct upload (>32MB)"
            }
        
            $uri = "https://www.virustotal.com/api/v3/files"
            $headers = @{ 'x-apikey' = $VTApiKey }
        
            $fileBytes = [System.IO.File]::ReadAllBytes($FileToUpload)
            $fileName = Split-Path $FileToUpload -Leaf
            $boundary = [System.Guid]::NewGuid().ToString()
            $LF = "`r`n"
        
            $bodyStart = "--$boundary$LF" + 
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"$LF" +
            "Content-Type: application/octet-stream$LF$LF"
            $bodyEnd = "$LF--$boundary--$LF"
        
            $bodyStartBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStart)
            $bodyEndBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyEnd)
        
            $totalBytes = New-Object byte[] ($bodyStartBytes.Length + $fileBytes.Length + $bodyEndBytes.Length)
            [System.Array]::Copy($bodyStartBytes, 0, $totalBytes, 0, $bodyStartBytes.Length)
            [System.Array]::Copy($fileBytes, 0, $totalBytes, $bodyStartBytes.Length, $fileBytes.Length)
            [System.Array]::Copy($bodyEndBytes, 0, $totalBytes, $bodyStartBytes.Length + $fileBytes.Length, $bodyEndBytes.Length)
        
            $headers['Content-Type'] = "multipart/form-data; boundary=$boundary"
        
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $totalBytes -TimeoutSec 60 -ErrorAction Stop
            return $response
        }
        catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                Write-Host "[!] Rate limit exceeded during upload. Waiting 60 seconds..." -ForegroundColor Yellow
                Start-Sleep 60
                throw "Rate limit exceeded - try again later"
            }
            throw $_
        }
    }

    function Monitor-VTAnalysis {
        param([string]$AnalysisId, [string]$VTApiKey, [switch]$Quiet, [switch]$PassThru, [string]$OutputCSV, [switch]$More)

        $maxWaitTime = 300
        $checkInterval = 15
        $elapsedTime = 0
    
        if (-not $Quiet) { Write-Host "[+] Monitoring analysis status..." -ForegroundColor Green }
        Write-Progress -Activity "VirusTotal Analysis" -Status "Waiting for analysis completion..." -PercentComplete 50

        while ($elapsedTime -lt $maxWaitTime) {
            try {
                $uri = "https://www.virustotal.com/api/v3/analyses/$AnalysisId"
                $headers = @{
                    'x-apikey' = $VTApiKey
                    'accept'   = 'application/json'
                }
            
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 30 -ErrorAction Stop
            
                if ($response.data.attributes.status -eq "completed") {
                    if (-not $Quiet) { Write-Host "[+] Analysis completed!" -ForegroundColor Green }
                
                    if ($response.meta.file_info.sha256) {
                        $fileHash = $response.meta.file_info.sha256
                        if (-not $Quiet) { Write-Host "[+] Final file hash: $fileHash" -ForegroundColor Cyan }
                    
                        $vtReport = Invoke-VTFileQuery -FileHash $fileHash -VTApiKey $VTApiKey
                        if ($vtReport) {
                            Write-Progress -Activity "VirusTotal Analysis" -Status "Processing final results..." -PercentComplete 90
                            $result = Convert-VTResponse -VTReport $vtReport -Hash $fileHash -HashType "SHA256"
    
                            if (-not $Quiet) {
                                Display-VTReport -Result $result -More:$More
                            }
    
                            if ($OutputCSV) {
                                Export-VTResultsToCSV -Results @($result) -OutputPath $OutputCSV
                            }
    
                            Write-Progress -Activity "VirusTotal Analysis" -Completed
                            return $result
                        }
                    }
                    return
                }
                else {
                    if (-not $Quiet) { Write-Host "[+] Status: $($response.data.attributes.status) (${elapsedTime}s elapsed)" -ForegroundColor Yellow }
                    Start-Sleep $checkInterval
                    $elapsedTime += $checkInterval
                }
            }
            catch {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                    if (-not $Quiet) { Write-Host "[!] Rate limit hit during monitoring. Waiting 60 seconds..." -ForegroundColor Yellow }
                    Start-Sleep 60
                    $elapsedTime += 60
                    continue
                }
                if (-not $Quiet) { Write-Host "[!] Error checking status: $($_.Exception.Message)" -ForegroundColor Red }
                break
            }
        }
    
        if ($elapsedTime -ge $maxWaitTime) {
            if (-not $Quiet) { Write-Host "[!] Analysis timeout - check manually: https://www.virustotal.com/gui/analysis/$AnalysisId" -ForegroundColor Yellow }
            Write-Progress -Activity "VirusTotal Analysis" -Completed
        }
    }

    function Convert-VTResponse {
        param($VTReport, $Hash, $HashType, $FilePath = "")

        if (-not $VTReport -or -not $VTReport.data -or -not $VTReport.data.attributes) {
            Write-Error "Invalid VirusTotal response data"
            return $null
        }
    
        $attrs = $VTReport.data.attributes
        $stats = $attrs.last_analysis_stats
    
        $result = [PSCustomObject]@{
            Hash             = $Hash
            HashType         = $HashType
            FilePath         = $FilePath
            Malicious        = $stats.malicious
            Suspicious       = $stats.suspicious
            Undetected       = $stats.undetected
            Harmless         = $stats.harmless
            Total            = ($stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless)
            Filename         = $attrs.meaningful_name
            FileType         = $attrs.type_description
            Size             = $attrs.size
            SizeMB           = if ($attrs.size) { [math]::Round($attrs.size / 1MB, 2) } else { $null }
            FirstSeen        = if ($attrs.first_submission_date) { [DateTimeOffset]::FromUnixTimeSeconds($attrs.first_submission_date) } else { $null }
            LastAnalysis     = if ($attrs.last_analysis_date) { [DateTimeOffset]::FromUnixTimeSeconds($attrs.last_analysis_date) } else { $null }
            Reputation       = $attrs.reputation
            Tags             = if ($attrs.tags) { $attrs.tags -join '; ' } else { $null }
            ThreatNames      = $null
            SandboxVerdicts  = $null
            Signatures       = $null
            SignatureInfo    = $null
            DetectionResults = $null
            ReportURL        = "https://www.virustotal.com/gui/file/$Hash"
            MD5              = $attrs.md5
            SHA1             = $attrs.sha1
            SHA256           = $attrs.sha256
            RawResponse      = $VTReport
        }
    
        # Extract threat names
        if ($attrs.popular_threat_classification -and $attrs.popular_threat_classification.suggested_threat_label) {
            $result.ThreatNames = $attrs.popular_threat_classification.suggested_threat_label
        }
    
        # Extract sandbox verdicts
        if ($attrs.sandbox_verdicts) {
            $sandboxResults = @()
            foreach ($sandbox in $attrs.sandbox_verdicts.PSObject.Properties) {
                $verdict = $sandbox.Value
                $sandboxResults += "$($sandbox.Name): $($verdict.category)"
            }
            $result.SandboxVerdicts = $sandboxResults -join '; '
        }
    
        # Extract signature info
        if ($attrs.signature_info) {
            $sigInfo = $attrs.signature_info
            $sigDetails = @()
            if ($sigInfo.verified) { $sigDetails += "Verified: $($sigInfo.verified)" }
            if ($sigInfo.signers) { $sigDetails += "Signers: $($sigInfo.signers)" }
            $result.SignatureInfo = $sigDetails -join '; '
        }
    
        # Extract detection results for malicious/suspicious
        if ($attrs.last_analysis_results) {
            $detections = $attrs.last_analysis_results.PSObject.Properties | 
            Where-Object { $_.Value.category -in @("malicious", "suspicious") } | 
            ForEach-Object { "$($_.Name): $($_.Value.result)" }
            $result.DetectionResults = $detections -join '; '
        }
    
        return $result
    }

    function Display-VTReport {
        param($Result, [switch]$More)
    
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host "$($Result.HashType) Hash      : " -NoNewline -ForegroundColor Yellow
        Write-Host $Result.Hash -ForegroundColor White
    
        $detectionColor = if ($Result.Malicious -gt 0) { "Red" } elseif ($Result.Suspicious -gt 0) { "Yellow" } else { "Green" }
        Write-Host "Detections       : " -NoNewline -ForegroundColor Yellow
        Write-Host "$($Result.Malicious)/$($Result.Total) malicious, $($Result.Suspicious) suspicious" -ForegroundColor $detectionColor
    
        if ($Result.Filename) {
            Write-Host "Filename         : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.Filename -ForegroundColor White
        }
    
        if ($Result.FileType) {
            Write-Host "File Type        : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.FileType -ForegroundColor White
        }
    
        if ($Result.Size) {
            Write-Host "Size             : " -NoNewline -ForegroundColor Yellow
            Write-Host "$($Result.Size) bytes ($($Result.SizeMB) MB)" -ForegroundColor DarkGray
        }
    
        if ($Result.ThreatNames) {
            Write-Host "Threat Names     : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.ThreatNames -ForegroundColor Red
        }
    
        if ($Result.Tags) {
            Write-Host "Tags             : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.Tags -ForegroundColor Red
        }
    
        if ($Result.SandboxVerdicts) {
            Write-Host "Sandbox Verdicts : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.SandboxVerdicts -ForegroundColor DarkYellow
        }
    
        if ($Result.SignatureInfo) {
            Write-Host "Signature Info   : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.SignatureInfo -ForegroundColor White
        }
    
        if ($Result.Reputation -ne $null) {
            Write-Host "Reputation       : " -NoNewline -ForegroundColor Yellow
            $repColor = if ($Result.Reputation -lt 0) { "Red" } elseif ($Result.Reputation -eq 0) { "Yellow" } else { "Green" }
            $repValue = if ($Result.Reputation -gt 0) { "+$($Result.Reputation)" } else { $Result.Reputation }
            Write-Host $repValue -ForegroundColor $repColor
        }

        if ($Result.FirstSeen) {
            Write-Host "First Seen       : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.FirstSeen.ToString('yyyy-MM-dd HH:mm:ss UTC') -ForegroundColor DarkGray
        }
    
        if ($Result.LastAnalysis) {
            Write-Host "Last Analysis    : " -NoNewline -ForegroundColor Yellow
            Write-Host $Result.LastAnalysis.ToString('yyyy-MM-dd HH:mm:ss UTC') -ForegroundColor DarkGray
        }
    
        Write-Host "Report URL       : " -NoNewline -ForegroundColor Yellow
        Write-Host $Result.ReportURL -ForegroundColor Cyan
    
        if ($Result.DetectionResults -and ($Result.Malicious -gt 0 -or $Result.Suspicious -gt 0)) {
            Write-Host ""
            Write-Host "--- Detection Engines ---" -ForegroundColor Red
            $detections = $Result.DetectionResults -split '; ' 
            foreach ($detection in $detections) {
                if ($detection) {
                    $parts = $detection -split ': ', 2
                    if ($parts.Count -eq 2) {
                        Write-Host "$($parts[0])".PadRight(20) -NoNewline -ForegroundColor Yellow
                        Write-Host ": " -NoNewline -ForegroundColor Yellow
                        Write-Host $parts[1] -ForegroundColor Red
                    }
                }
            }
        }
    
        if ($More) {
            Write-Host ""
            Write-Host "--- RAW DATA ---" -ForegroundColor Magenta
            $attrs = $Result.RawResponse.data.attributes
            $processedFields = @('meaningful_name', 'type_description', 'size', 'md5', 'sha1', 'sha256', 
                'first_submission_date', 'last_analysis_date', 'last_analysis_stats', 
                'last_analysis_results', 'reputation', 'tags', 'popular_threat_classification',
                'sandbox_verdicts', 'signature_info')
        
            foreach ($property in $attrs.PSObject.Properties) {
                if ($property.Name -notin $processedFields -and $null -ne $property.Value) {
                    $value = if ($property.Value -is [array]) { 
                        $property.Value -join '; ' 
                    }
                    elseif ($property.Value -is [object] -and $property.Value.GetType().Name -eq 'PSCustomObject') {
                        $property.Value | ConvertTo-Json -Compress
                    }
                    else { 
                        $property.Value.ToString() 
                    }
                
                    if ($value.Length -gt 10000) { $value = $value.Substring(0, 10000) + "..." }
                
                    Write-Host "$($property.Name)".PadRight(20) -NoNewline -ForegroundColor DarkCyan
                    Write-Host ": " -NoNewline -ForegroundColor Yellow
                    Write-Host $value -ForegroundColor Gray
                }
            }
        }
    
        Write-Host "----------------------------------------`n" -ForegroundColor Gray
    }

    function Export-VTResultsToCSV {
        param($Results, [string]$OutputPath)

        if (-not $Results -or $Results.Count -eq 0) {
            Write-Warning "No results to export to CSV"
            return
        }
    
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $csvPath = "VT_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        }
        elseif ((Test-Path $OutputPath -PathType Container) -or ($OutputPath -match '[\\/]$')) {
            $csvPath = Join-Path $OutputPath "VT_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            if (-not (Test-Path (Split-Path $csvPath -Parent))) {
                New-Item -ItemType Directory -Path (Split-Path $csvPath -Parent) -Force | Out-Null
            }
        }
        else {
            $csvPath = $OutputPath
            $parentPath = Split-Path $csvPath -Parent
            if ($parentPath -and -not (Test-Path $parentPath)) {
                New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
            }
        }
    
        # Sanitize data for Excel
        try {
            $sanitizedResults = $Results | ForEach-Object {
                $obj = $_.PSObject.Copy()
                foreach ($prop in $obj.PSObject.Properties) {
                    if ($null -ne $prop.Value) {
                        $value = $prop.Value.ToString()
                        # Escape leading equals sign to prevent formula execution
                        if ($value.StartsWith("=")) {
                            $value = "'" + $value
                        }
                        # Truncate if too long (Excel limit is 32,767 characters per cell)
                        if ($value.Length -gt 32000) {
                            $value = $value.Substring(0, 32000) + "..."
                        }
                        $prop.Value = $value
                    }
                }
                $obj
            }
        }
        catch {
            Write-Error "Failed to sanitize data for CSV export: $($_.Exception.Message)"
            return
        }
    
        $csvData = $sanitizedResults | Select-Object Hash, HashType, FilePath, Malicious, Suspicious, Undetected, 
        Harmless, Total, Filename, FileType, Size, SizeMB, FirstSeen, 
        LastAnalysis, Reputation, Tags, ThreatNames, SandboxVerdicts, 
        SignatureInfo, DetectionResults, ReportURL, MD5, SHA1, SHA256
    
        try {
            $csvData | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
            Write-Host "[+] Results exported to: $csvPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV: $($_.Exception.Message)"
        }
    }


    # Handle UploadStatus
    if ($UploadStatus) {
        if (-not $AnalysisId) {
            Write-Error "AnalysisId parameter required with -UploadStatus"
            return
        }
        
        if (-not $ApiKey -and $Global:HuntVTApiKey) {
            $ApiKey = $Global:HuntVTApiKey
        }
        if (-not $ApiKey) {
            Write-Error "API key required for status check"
            return
        }
        
        return Monitor-VTAnalysis -AnalysisId $AnalysisId -VTApiKey $ApiKey -Quiet:$Quiet -PassThru:$PassThru -OutputCSV:$OutputCSV -More:$More
    }

    # Input validation
    if (-not $FilePath -and -not $Hash) {
        Write-Error "Either -FilePath or -Hash parameter is required"
        return
    }

    if ($FilePath -and (Test-Path $FilePath -PathType Container)) {
        Write-Error "FilePath cannot be a directory. Please specify a file path."
        return
    }
    
    if ($FilePath -and -not (Test-Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue)) {
        Write-Error "File not found: $FilePath"
        return
    }
    
    # Test connectivity
    try {
        $null = Test-Connection -ComputerName "www.virustotal.com" -Count 1 -Quiet -ErrorAction Stop
    }
    catch {
        Write-Error "Cannot reach VirusTotal. Check internet connection."
        return
    }
    
    # Handle API key
    if (-not $ApiKey -and $Global:HuntVTApiKey) {
        $ApiKey = $Global:HuntVTApiKey
    }
    
    if (-not $ApiKey) {
        if (-not $Quiet) {
            Write-Host "`n[!] VirusTotal API key required" -ForegroundColor Yellow
            Write-Host "Get free API key: https://www.virustotal.com/gui/join-us" -ForegroundColor Cyan
        }
        $promptResult = Read-Host "`nEnter your VirusTotal API key"
        
        if ([string]::IsNullOrWhiteSpace($promptResult)) {
            if (-not $Quiet) { Write-Host "[!] No API key provided - exiting" -ForegroundColor Red }
            return
        }
        
        $ApiKey = $promptResult.Trim()
        $Global:HuntVTApiKey = $ApiKey
        if (-not $Quiet) { Write-Host "[+] API key saved for session" -ForegroundColor Green }
    }
    
    # Calculate hash if needed and validate hash format
    if ($FilePath -and -not $Hash) {
        try {
            $hashResult = Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction Stop
            $Hash = $hashResult.Hash
        }
        catch {
            Write-Error "Failed to calculate hash: $($_.Exception.Message)"
            return
        }
    }
    
    # Validate and identify hash type
    if ($null -ne $Hash) {
        $Hash = $Hash -replace '[^a-fA-F0-9]', ''
        $hashType = switch ($Hash.Length) {
            32 { "MD5" }
            40 { "SHA1" }
            64 { "SHA256" }
            default { 
                Write-Error "Invalid hash format. Supported: MD5 (32), SHA1 (40), SHA256 (64) characters"
                return
            }
        }
    }
    
    # Main execution logic
    try {
        if (-not $Quiet) { Write-Host "[+] Querying VirusTotal for: $Hash" -ForegroundColor Green }
        Write-Progress -Activity "VirusTotal Analysis" -Status "Querying hash database..." -PercentComplete 10
        $vtReport = Invoke-VTFileQuery -FileHash $Hash -VTApiKey $ApiKey
        
        if ($vtReport -and $vtReport.data -and -not $Force) {
            Write-Progress -Activity "VirusTotal Analysis" -Status "Processing results..." -PercentComplete 80
            # File exists, process and display report
            $result = Convert-VTResponse -VTReport $vtReport -Hash $Hash -HashType $hashType -FilePath $FilePath
    
            if (-not $Quiet) {
                Display-VTReport -Result $result -More:$More
            }
    
            if ($OutputCSV) {
                Export-VTResultsToCSV -Results @($result) -OutputPath $OutputCSV
            }
    
            Write-Progress -Activity "VirusTotal Analysis" -Completed
    
            if ($PassThru) {
                return $result
            }
            return
        }
        else {
            # File doesn't exist or Force specified
            if ($FilePath) {
                if ($vtReport -and $Force) {
                    if (-not $Quiet) { Write-Host "[!] File exists but forcing upload..." -ForegroundColor Yellow }
                }
                else {
                    if (-not $Quiet) { Write-Host "[!] Hash not found in VirusTotal" -ForegroundColor Yellow }
                }
                
                Write-Progress -Activity "VirusTotal Analysis" -Status "Uploading file..." -PercentComplete 30
                if (-not $Quiet) { Write-Host "[+] Uploading file for analysis..." -ForegroundColor Green }
                $uploadResult = Invoke-VTFileUpload -FileToUpload $FilePath -VTApiKey $ApiKey

                if ($uploadResult -and $uploadResult.data) {
                    if (-not $Quiet) {
                        Write-Host "[+] Upload successful, monitoring analysis..." -ForegroundColor Green
                        Write-Host "[+] Analysis URL: https://www.virustotal.com/gui/analysis/$($uploadResult.data.id)" -ForegroundColor Cyan
                    }
    
                    $result = Monitor-VTAnalysis -AnalysisId $uploadResult.data.id -VTApiKey $ApiKey -Quiet:$Quiet -PassThru:$true -OutputCSV:$OutputCSV -More:$More
                    Write-Progress -Activity "VirusTotal Analysis" -Completed
    
                    if ($PassThru) {
                        return $result
                    }
                    return
                }
                else {
                    if (-not $Quiet) { Write-Host "[!] Upload failed" -ForegroundColor Red }
                    Write-Progress -Activity "VirusTotal Analysis" -Completed
                }
            }
            else {
                if (-not $Quiet) { Write-Host "[!] Hash not found and no file path provided for upload" -ForegroundColor Yellow }
                Write-Progress -Activity "VirusTotal Analysis" -Completed
            }
        }
    }
    catch {
        Write-Progress -Activity "VirusTotal Analysis" -Completed
        Write-Error "Error: $($_.Exception.Message)"
    }
}