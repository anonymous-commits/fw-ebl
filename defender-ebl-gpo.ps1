
###
# This is a script to update domain joined clients Windows defender firewall with data from an External Blocklist (EBL) via GPO
# There is an other version of the script intended for managing stand alone installations
# All IP-adresses in the list will be put in to one or multiple Firewall rules in the Defender firewall to block Outgoing traffic
# One primary use-case is to block traffic to known bad IP-adresses hosting C2-servers, of course such a list is not static and we need to reguly update.
#
# The format of the EBLs needs to be one IP-address(or CIDR) per row. Everything after a comment (#) will be ignored per row 
#
#
# Yes, it is a some what hastie work.. but seams to do the job fine. There is certinly room for much improvement
# Apparently you could use the Net-GPO metods for stand-alone machine as well and work with local GPOs...
# There seems to be something wierd with ps for win 2022 missing -gposession option in Remove-NetFirewallRule (use policystore instead?)
#
# This script will currently need some Windows management modules that comes with RSAT packages
# I thought about makeing it platform agnostic, but it isn't right now.. but you can alwas run it remote.
# I'm more likely to also write a ansible playbook (not running this powershell-script) then to make this script more platform agnostic.
#
#
#####
# Features:
# - Update/Remove inserts/deletes rules based on downloaded list - updates a GPO defining the block rules (to merge with other rules)
#   - You will have to take care of managing you GPO scope and precedence correctly 
#   - Of course you need to run the script with a user allowed to make updates to the GPO
#   - GPO's per default refreshes every 90 minutes, with random offset of 0-30 min (Meaning it could take up to 2h for updates to apply)
#     - So, it wouldn't make sense to run this more frequent than every 2h top
# - Can handle multiple lists defined via URL
#   - Each list must have a unique _file-name_ or we will mess things up
# - Logs to Windows Application Eventlog
#
# TODO: 
# - Use a encrypted blocklist so it can be publicly published (use key-pair for encrypt/decrypt)
# - (Optionaly use a config file) - design decision not to have one for easier deployment, you will have to edit variables in top of file for now
# - Windows Server 2022(ps7?) does not fully support GPOSession parameters as it seems, fix a suitible workaround
#####

######################

#This you will want to change for your deployment
$Urls = @("https://c2ebl.example.net/c2ips.txt","C:\tmp\myc2ips.txt")
$DomainName = "ad.example.net"
#Na, we don't want to create or link the GPO in this script... you will have to do that yourself, we just update the GPO that should be pre-created
#$TargetOU = "OU=clients,DC=ad,DC=example,DC=net"

#There is probably no need to change this, but feel free
$ScriptName = "Defender-EBL-Updater"
$EventLogSource = $ScriptName
$GpoName =  $ScriptName
$BlockListName = "EBL-BlockList"
$MaxEntriesPerRule = 400
$PolicyStoreName = "$DomainName\$GpoName"


########################



# Function to write logs to the Windows Application Event Log
function Write-Log {
    Param([string]$Message, [string]$Level="Information")
    $EventId = 1
    #EventLog is a pure windows thing
    [System.Diagnostics.EventLog]::WriteEntry($EventLogSource, $Message, $Level, $EventId)
    Write-Host $Message
}



# Function to delete all rules inserted by the script
function Remove-Rules {
    #Removeing all rules matchning our prefix "$BlockListName-*"
    Write-Log "Deleting firewall rules for '$BlockListName-$ListFileName*'..." -Level "Information"
    Remove-NetFirewallRule -DisplayName "$BlockListName-*" -GPOSession $GpoSessionName | Out-Null
    Write-Log "Deleted firewall rules with display name starting with '$BlockListName-$ListFileName*'." -Level "Information"
}


# Function to download list and update rules
function Update-Rules {

    #Since we work in a session we should be ok to delete all rule now, we will not write the session if anything fail
    Remove-Rules 

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
            Write-Log "The InputFile contained no IP addresses to block. Quitting..." -Level "Warning"
            Exit
        }
                                        
            
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
            New-NetFirewallRule -DisplayName "$BlockListName-$ListFileName-#$iCount" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $TextRanges -Description $RuleDescription -Profile $ProfileType -InterfaceType $InterfaceType -GPOSession $GpoSessionName | Out-Null
        }
    
        Write-Log "Firewall blocking rules with name $BlockListName-$ListFileName-#x creation complete." -Level "Information"
         
    }
    
}

# Register the event log source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($EventLogSource, $eventLogName)
}

#Get the domains PDC
#This seems to need Module: ActiveDirectory from RSAT package
$pdc = Get-ADDomainController -Discover -Service PrimaryDC -DomainName $DomainName

#The GPO stuff needs Module: GroupPolicy  from RSAT package
#Create the GPO if it does not exist
#Per default we use the current users credentials, but we can use other credentials and remoting options with -CimSession (wsman(ps-remoting), dcom)
New-GPO -Name $GpoName -Server $($pdc.Hostname) -Comment "Script created GPO for dynamically updated firewall external block list" -ErrorAction SilentlyContinue
#If we want to link that could be done with
#New-Gplink -Name $GpoName -target $TargetOU -Order 1 -LinkEnabled Yes -Server $($pdc.Hostname)

#First check that we can open the GPO
try {
    #Per default we use the current users credentials, but we can use other credentials and remoting options with -CimSession (wsman(ps-remoting), dcom)
    $GpoSessionName = Open-NetGPO –PolicyStore $PolicyStoreName -DomainController $pdc.Hostname
} 
catch {
    Write-Log "Could not open GPO $PolicyStoreName for editing. Quitting.." -Level "Warning"
    Exit
}

# Determine the action based on the command-line arguments
if ($args -contains "-Update") {
    # Update action
    Write-Log "Updating IP blocking rules in GPO $GPOName..." -Level "Information"
    Update-Rules
}
elseif ($args -contains "-Remove") {
     # Delete action
    Remove-Rules
}
else {
    Write-Log "Invalid argument. Available arguments: -Update, -Remove." -Level "Error"
 }

try {
    Save-NetGPO –GPOSession $GpoSessionName
} 
catch {
    Write-Log "Could not save session to GPO $PolicyStoreName. Quitting.." -Level "Warning"
    Exit
}

