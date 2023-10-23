###
# This is a script to update the local Windows defender firewall with data from an External Blocklist (EBL)
# This version of the script is sutible for a stand alone installation, there is an other version more suited for managing domain joined computers via GPO
# All IP-adresses in the list will be put in to one or multiple Firewall rules in the Defender firewall to block Outgoing traffic
# One primary use-case is to block traffic to known bad IP-adresses hosting C2-servers, of course such a list is not static and we need to reguly update.
#
# The format of the EBLs needs to be one IP-address(or CIDR) per row. Everything after a comment (#) will be ignored per row 
#
#
# Yes, it is a some what hastie work.. but seams to do the job fine. There is certinly room for much improvement
#
#####
# Features:
# - Can be installed/uninstalled as a scheduled job, running as LocalService (will add LocalService user to group Network Config Operators to run with least priv)
#   - This requires running the script with administrator priviliges to set-up
# - Update/Remove inserts/deletes rules based on downloaded list (user running needs permissions like 'Network Config Operators')
# - Can handle multiple lists defined via URL
#   - Each list must have a unique _file-name_ or we will mess things up
#
# TODO: 
# - Quarantine option, block(and unblock) "all" outgoing traffic - cli option to be kicked by automation
# - Use a encrypted blocklist so it can be publicly published (use key-pair for encrypt/decrypt)
# - (Optionaly use a config file) - design decision not to have one for easier deployment, you will have to edit variables in top of file for now
#####

######################

#This you will want to change for your deployment
$Urls = @("https://c2ebl.example.net/c2ips.txt","C:\tmp\myc2ips.txt")
$Organization = "ACME" #Used in scheduler, Program Files and Registry

#There is probably no need to change this, but feel free
$ScriptName = "Defender-EBL-Updater"
$EventLogSource = $ScriptName
$BlockListName = "EBL-BlockList"
$InstallPath = "C:\Program Files\$Organization\$ScriptName"
$MaxEntriesPerRule = 400



########################

# Function to write logs to the Windows Application Event Log
function Write-Log {
    Param([string]$Message, [string]$Level="Information")
    $EventId = 1
    [System.Diagnostics.EventLog]::WriteEntry($EventLogSource, $Message, $Level, $EventId)
    Write-Host $Message
}

function Test-Role {  
    [OutputType([bool])]
    param([string]$Role=$AdminGroupName)
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent()
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::"BUILTIN\\"+$Role)
    }
}


# Function to delete all rules inserted by the script
function Remove-Rules {
    [CmdletBinding(DefaultParameterSetName='ByListName')]
    param(
        [Parameter(Mandatory=$false, ParameterSetName='ByListName')]
        [string]$ListFileName="",
         
        [Parameter(Mandatory=$true, ParameterSetName='NotInList')]
        [array]$lists    
    )
          
    switch ($PSCmdlet.ParameterSetName) {
        #Remove the rules matchning the listname(or all rules if no listname specified)
        'ByListName' {
            Write-Log "Deleting firewall rules for '$BlockListName-$ListFileName*'..." -Level "Information"
            Get-NetFirewallRule -DisplayName "$BlockListName-$ListFileName*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule | Out-Null
            Write-Log "Deleted firewall rules with display name starting with '$BlockListName-$ListFileName*'." -Level "Information"
        }
        #Remove rules NOT matching specified lists
        'NotInList' {
            $KeepBlockLists = $lists | ForEach-Object{"$BlockListName-$_-*"}
            #Check if not each rules Displayname matches a name in our keep-list we should remove it
            Get-NetFirewallRule -DisplayName "$BlockListName-*" -ErrorAction SilentlyContinue | Where-Object {$item=$_.DisplayName; -not ($KeepBlockLists |Where-Object {$item -like $_}) } | Remove-NetFirewallRule | Out-Null
            Write-Log "Deleted firewall rules not matching keep-list '$KeepBlockLists'." -Level "Information"
        }
    }

}

# Function to remove the scheduled task and delete the rules
function Remove-ScheduledTaskAndRules {
    $TaskName = $BlockListName
    
    #If we should run the task as LocalServie we need to add the user to "Network Configuration Operators", now clean that up
    Remove-LocalGroupMember -Group $NetworkGroupName -Member "NT AUTHORITY\LocalService" -ErrorAction SilentlyContinue
   
    $taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like $TaskName }
    if ($taskExists) {
    
        try {
            $null = Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
        }
        catch {
            Write-Log "Failed to unregister scheduled task with name '$TaskName', probably no such task registrered." -Level "Error"
        }
    }
    Write-Log "Scheduled task '$TaskName' removed." -Level "Information"
    Remove-Rules
}

# Function to install the script as a scheduled task
function Install-ScheduledTask {
    #$TaskName = "Block-IPAddresses"
    #$TaskPath = "\Microsoft\Windows\PowerShell\ScheduledJobs\"
    $TaskName = $BlockListName
    $TaskPath = "\$Organization\"
    $FileName = Split-Path $PSCommandPath -Leaf
    $FullInstallPath = $InstallPath + "\" + $FileName
    #Create destination directory under Program Files, when running scheduled as system we do not want the file editable by users or we would have created a nice LPE
    try {
        $null = New-Item -ItemType Directory -Force -Path $InstallPath -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to create install directory." -Level "Error"
    }
    
    try {
        $null = Copy-Item -Path $PSCommandPath -Destination $InstallPath -Force
    }
    catch {
        Write-Log "Failed to copy file to install directory." -Level "Error"
    }

    $taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like $TaskName }
    if ($taskExists) {
        try {
            $null = Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
        }
        catch {
            Write-Log "Failed to unresiter scheduled task with name '$TaskName', probably no such task registrered." -Level "Error"
        }
    }

    #If we should run the task as LocalServie we need to add the user to "Network Configuration Operators"
    Add-LocalGroupMember -Group $NetworkGroupName -Member "NT AUTHORITY\LocalService" -ErrorAction SilentlyContinue
                
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$FullInstallPath`" -Update"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5) -RepetitionInterval (New-TimeSpan -Hours 1)

    $TaskParams = @{
        TaskName  = $TaskName
        Action    = $Action
        Trigger   = $Trigger
        Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LocalService" -LogonType ServiceAccount -RunLevel Highest
        Settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    }

    try {
        $null = Register-ScheduledTask -TaskPath $TaskPath @TaskParams
    }
    catch {
        Write-Log "Failed to install scheduled task" -Level "Error"
        Exit
    }
    Write-Log "Script installed as a scheduled task: $TaskPath$TaskName" -Level "Information"
}

# Function to download list and update rules
function Update-Rules {

    $lists = @()
    foreach ($Url in $Urls){
        #Strip file name without extension form url
        $ListFileName = ($Url.Substring($Url.LastIndexOf("/") + 1)).Split(".")[0]
        #Strip if it was a filesystem reference
        $ListFileName = ($ListFileName.Substring($ListFileName.LastIndexOf("\") + 1))
        $lists += ($ListFileName)
        # Download the file
        try {
            Write-Log "Downloading file from $Url..." -Level "Information"
            $TempFile = [System.IO.Path]::GetTempFileName()
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile($Url, $TempFile)
            Write-Log "File downloaded successfully." -Level "Information"
        }
        catch {
            Write-Log "Failed to download the IP address list from: $Url" -Level "Error"
            Exit
        }
    
        # Read the file and extract IP addresses
        $IPAddresses = Get-Content $TempFile | ForEach-Object {
            $IPAddress = $_ -replace '#.*$'  # Remove comments from the line
            $IPAddress.Trim()
        } | Where-Object { ($_.Trim().Length -ne 0) -and ($_ -match '^[0-9a-f]{1,4}[\.\:]') }
    
        $TotalEntries = $IPAddresses.Count
    
        # Confirm that the InputFile had at least one IP address or IP range to block
        if ($TotalEntries -eq 0) {
            Write-tLog "The InputFile contained no IP addresses to block. Quitting..." -Level "Warning"
            Exit
        }
        Remove-Rules -ListFileName $ListFileName
            
        # Create array of IP address ranges with a maximum number of ranges per rule
        $RangesByRule = @()
    
        for ($i = 0; $i -lt $TotalEntries; $i += $MaxEntriesPerRule) {
            $rangeSubset = $IPAddresses[$i..($null -ne ($i + $MaxEntriesPerRule - 1))]
            $RangesByRule += , $rangeSubset
        }
        $TotalRules = $RangesByRule.Count
        Write-Log "Fetched $TotalEntries IP-addresses to go in to $TotalRules rules" -Level "Information"
    
        $ProfileType = 'Any'
        $InterfaceType = 'Any'
        $nowDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $RuleDescription = "Automatic rule inserted by script $PSCommandPath at $nowDate"
    
        # Create firewall blocking rules for each subset of IP address ranges
        for ($i = 0; $i -lt $RangesByRule.Count; $i++) {
            $iCount = ($i + 1).ToString().PadLeft(3, "0")
            $TextRanges = $RangesByRule[$i]
        
            #Write-Output "$TextRanges"
            New-NetFirewallRule -DisplayName "$BlockListName-$ListFileName-#$iCount" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $TextRanges -Description $RuleDescription -Profile $ProfileType -InterfaceType $InterfaceType | Out-Null
        }
    
        Write-Log "Firewall blocking rules with name $BlockListName-$ListFileName-#x creation complete." -Level "Information"
         
    }
    Remove-Rules -lists $lists
}

#############################

#This is SID of built in local admin group(Administrators), get name to be language agnostic
$AdminGroupSid = 'S-1-5-32-544'
$AdminGroup = New-Object System.Security.Principal.SecurityIdentifier($AdminGroupSid)
$AdminGroupName = $AdminGroup.Translate([System.Security.Principal.NTAccount]).Value -replace '.+\\'

#This is SID of built in local network group(Network Configuration Operators), get name to be language agnostic
$NetworkGroupSid = 'S-1-5-32-556'
$NetworkGroup = New-Object System.Security.Principal.SecurityIdentifier($NetworkGroupSid)
$NetworkGroupName = $NetworkGroup.Translate([System.Security.Principal.NTAccount]).Value -replace '.+\\'


# Register the event log source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($EventLogSource, $eventLogName)
}

# Determine the action based on the command-line arguments
if ($args -contains "-Update") {
    if( -Not(Test-Role($NetworkGroupName)) -And -Not(Test-Role($AdminGroupName)) ) {
        Write-Log "This option must be executed with Network Operator privileges" -Level "Error"
        exit 1;
    }

    # Update action
    Write-Log "Updating IP blocking rules..." -Level "Information"
    Update-Rules
}
elseif ($args -contains "-Remove") {
    if( -Not(Test-Role($NetworkGroupName)) -And -Not(Test-Role($AdminGroupName)) ) {
        Write-Log "This option must be executed with Network Operator privileges" -Level "Error"
        exit 1;
    }

    # Delete action
    Remove-Rules
}
elseif ($args -contains "-Install") {
    if(-not (Test-Role($AdminGroupName))) {
        Write-Log "This option must be executed with Administrator privileges" -Level "Error"
        exit 1;
    }

    # Install action
    Write-Log "Installing script as a scheduled task..." -Level "Information"
    #TODO Break out install files and run it
    Install-ScheduledTask
}
elseif ($args -contains "-Uninstall") {
    if(-not (Test-Role($AdminGroupName))) {
        Write-Log "This option must be executed with Administrator privileges" -Level "Error"
        exit 1;
    }

    # Uninstall/Remove action
    Write-Log "Uninstalling scheduled task and firewall rules..." -Level "Information"
    Remove-ScheduledTaskAndRules
    #TODO delete files from Program Files
}
else {
    Write-Log "Invalid argument. Available arguments: -Update, -Remove, -Install, -Uninstall." -Level "Error"
}
