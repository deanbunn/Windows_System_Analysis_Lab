## PowerShell for Windows System Analysis Lab

Ten sessions offered for learning to use PowerShell to analyze Windows system configuration.

**All lab exercises and descriptions are listed in the README**. 

The lesson script files are designed to only be used as a downloadable reference. 

At the beginning of each script is a "exit" command to prevent an accidental run


## Lesson 1

### 1.1 Transcripts 

<details>
<summary>1.1 Exercises</summary>


Start a Transcript File
```powershell
Start-Transcript
#Default Location C:\Users\userID\Documents\PowerShell_transcript.NNNNNN.NNNNNNNNNNN.txt
```
Start Transcript with Custom Name
```powershell
Start-Transcript "MyTranscript.txt"
```
Or for the File to be Placed in the Specific Directory
```powershell
Start-Transcript C:\Script_Runs\MyTranscript.txt
```
To Stop the Transcript from Recording Commands and Output
```powershell
Stop-Transcript
```
</details>

### 1.2 PowerShell Version

<details>
<summary>1.2 Exercises</summary>


View PowerShell Version
```powershell
$PSVersionTable
```
</details>

### 1.3 Cmdlets and Modules


<details>
<summary>1.3 Exercises</summary>

Cmdlet Format -eq action-noun
```powershell
Get-Command -Noun service
```
Get All Commands by a Certain Action
```powershell
Get-Command -Verb start
```
Get All Currently Loaded Cmdlets
```powershell
Get-Command -CommandType Cmdlet
```
Update Help Before Using It
```powershell
Update-Help
```
Basic Help Information for Cmdlet
```powershell
Get-Help Get-Process
```
Online Help for a Cmdlet
```powershell
Get-Help Get-Process -Online
```
Help with Examples
```powershell
Get-Help Get-Process -examples
```
Help Full Listing
```powershell
Get-Help Get-Process -Full
```
Help About a Certain Subject
```powershell
Get-Help about_operators
```
Help About
```powershell
Get-Help about_*
```
Get All PowerShell Modules Available on System
```powershell
Get-Module -ListAvailable
```
Import Module in Current PowerShell Session
```powershell
Import-Module DnsClient
```
Get All Commands in a Module (Should Only Be Used After Importing)
```powershell
Get-Command -Module DnsClient
```
Find .NET Object Used in Cmdlet
```powershell
Get-Process | Get-Member
```
List All Alias
```powershell
Get-Alias
```
Look for Specific Alias
```powershell
Get-Alias -Definition Stop-Process
```
Create Alias
```powershell
New-Alias -Name "Gunrock" Get-ChildItem
```

</details>

### 1.4 Pipeline


<details>
<summary>1.4 Exercises</summary>

Command to Find If CmdLet Allows for Piping (Check Accept Pipeline Property Under Parameters) 
```powershell
Get-Help Get-Process -full | more 
```
Using Out-File to Get Resource Info on the Pipeline
```powershell
Get-Help About_pipeline | Out-File about_pipeline.txt
```
Get All Process and Then Sort by Display Name
```powershell
Get-Process | Sort-Object ProcessName -descending
```
Stop All Notepad Process and Log Process Collection Before Stopping
```powershell
Get-Process notepad | Tee-Object -file Notepad_Processes.txt | Stop-Process
```
Get All Services That Are Running Then Only Show the Display Name
```powershell
Get-Service | Where-Object { $_.Status -eq "Running" } | ForEach-Object { $_.DisplayName }
```
Quick Way to Report on File Types in a Folder
```powershell
Get-ChildItem | Group-Object -property extension
```

</details>

## Lesson 2

### 2.1 Script Execution Policy

<details>
<summary>2.1 Exercises</summary>

Get Current Policy
```powershell
Get-ExecutionPolicy
```
Set the Script Execution Policy for Current User 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

</details>

### 2.2 Outputs


<details>
<summary>2.2 Exercises</summary>

To Get All the Format Object Commands
```powershell
Get-Command -verb format
```
Get All Processes in a GUI Gridview
```powershell
Get-Process | Out-GridView
```
Output Sent to a File
```powershell
Get-Service | Out-File Services.txt
```
Quick Array Sent to a File
```powershell
@("Server1","Server2","Server3","Server4") | Out-File servers.txt
```
Service List Sent to Your Default Printer
```powershell
Get-Service | Out-Printer 
```
Running Service List With Only a Few Columns Exported to CSV
```powershell
Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name,DisplayName,Status,CanStop | Sort-Object DisplayName | Export-Csv running_services.csv -NoTypeInformation
```

</details>

### 2.3 Inputs

<details>
<summary>2.3 Exercises</summary>

Prompt User for Info
```powershell
$requiredData = Read-Host -prompt "Enter Required Data"
```
Create String Array From a Text File 
```powershell
$servers = Get-Content servers.txt
```
Import Data a CSV File and Use a Specific Column From It
```powershell
Import-Csv running_services.csv | Foreach-Object { $_.DisplayName }
```

</details>

### 2.4 Errors

<details>
<summary>2.4 Exercises</summary>

The Setting for Error Handling is Stored in the $ErrorActionPreference variable
Error Handling Options:
- Continue = Output Error Message; Continue to Run Next Command (Default)
- SilentlyContinue = Suppress Error Message; Continue to Run the next command
- Stop = Halt the Execution
- Inquire = Prompt User for Action to Perform

```powershell
$ErrorActionPreference = "Continue";
```
Errors that Occur During a PowerShell Session are Stored in $error
```powershell
$error
```
Empty Error Messages from $error
```powershell
$error.clear();
```
Some Cmdlets Support an ErrorAction Statement (only for parameter data)
These Won't Display an Error
```powershell
Remove-Item nothinghere -ErrorAction "SilentlyContinue";
Stop-Process -ID 8888888 -ErrorAction "SilentlyContinue";
#This Will Due to -ID Must Be an Int
Stop-Process -ID NothingHere -ErrorAction "SilentlyContinue";
```

</details>

## Lesson 3

### 3.1 Environment Variables

<details>
<summary>3.1 Exercises</summary>


View Environment Variables
```powershell
Get-ChildItem Env:
```
View Path Environment Variable
```powershell
$Env:path -split ";"
```

</details>

### 3.2 File System

<details>
<summary>3.2 Exercises</summary>


Navigate with Set-Location (alias cd)
```powershell
Set-Location c:\users\$env:username\Desktop
```
List Items in Current Directory
```powershell
Get-ChildItem
```
List Only the Text File
```powershell
Get-ChildItem -Filter *.txt
```
Get List of All "Item" Cmdlets
```powershell
Get-Command -noun item | Select-Object Name | Sort-Object Name | Out-File Item_Commands.txt
```
Get the Path of Current Operating Directory
```powershell
(Get-Location).Path
```
Check to See If a Directory or File Exists
```powershell
Test-Path -Path c:\goldenstate\warriors.txt
```
Get List of All "Content" Cmdlets
```powershell
Get-Command -Noun Content
```
Search for All Text Files on System Drive
```powershell
Get-Childitem -Path c:\ -Filter *.txt -Recurse;
```
Create a Folder
```powershell
New-Item My_Scripts -ItemType Directory
```
Create a Text File 
```powershell
New-Item .\My_Scripts\first_script.ps1 -ItemType File;
```
Add Content to a File
```powershell
Add-Content -Path .\My_Scripts\first_script.ps1 -Value "Get-Service";
```
Move or Rename a File
```powershell
Move-Item .\My_Scripts\first_script.ps1 .\My_Scripts\second_script.ps1;
```
Get Rights on Current Directory
```powershell
Get-Acl -Path . | Format-List
```
Get Access on Current Directory
```powershell
(Get-Acl -Path .).Access
```
Get the Owner of a Directory or File
```powershell
(Get-Acl -Path c:\Intel\Logs).Owner 
```
List the NTFS Permissions of a File or Folder
```powershell
(Get-Acl -Path $env:programfiles).Access
```
Show Permissions in Friendly Format on Current Directory
```powershell
(Get-Acl -Path .).Access | Select-Object -ExpandProperty IdentityReference FileSystemRights | Format-Table Value,FileSystemRights
```
View File Hash
```powershell
Get-FileHash .\Scary_Executable_I_Just_Downloaded.exe
```

</details>

### 3.3 PSDrive and Registry


<details>
<summary>3.3 Exercises</summary>


PS Drives
```powershell
Get-PSDrive
```
List PSDrive for Registry
```powershell
Get-PSDrive -PSProvider Registry
```
Change to HKEY\_LOCAL\_MACHINE
```powershell
Set-Location HKLM:
```
View Windows Current Version Information
```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion'
```
View RDP Port Number (Requires Admin Console)
```powershell
(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").PortNumber
```
System Environment
```powershell
Set-Location env:
```

</details>

### 3.4 Searching File Contents

<details>
<summary>3.4 Exercises</summary>


Create File to Search
```powershell
Get-Process | Out-File processes.txt
```
Search a File for a Specific Term
```powershell
Select-String "svchost" .\processes.txt
```
Search for String in File and Show One Line Before and Three Lines After
```powershell
Select-String "explorer" .\processes.txt -Context 1,3
```
Search Multiple Files
```powershell
Select-String "explorer" .\process* 
```

</details>

## Lesson 4

### 4.1 System Information

<details>
<summary>4.1 Exercises</summary>


Get BIOS Information
```powershell
Get-WmiObject -Class Win32_BIOS -Computer localhost
```
Get Basic System Info
```powershell
Get-WmiObject -Class Win32_ComputerSystem -Computer localhost
```
Get Operating System Info
```powershell
Get-WmiObject -Class Win32_OperatingSystem -Computer localhost
```
Get Consolidated Object of System and Operating System Properties
```powershell
Get-ComputerInfo
```

</details>

### 4.2 Disk Information

<details>
<summary>4.2 Exercises</summary>


Get Disk Information
```powershell
Get-Disk | Format-List
```
Show Physical Disk Information
```powershell
Get-PhysicalDisk
```
Get Disk Information (Model and Size)
```powershell
Get-WmiObject -Class Win32_DiskDrive | ForEach-Object { Write-Output ($_.Model.ToString() + " Size:" + ($_.Size/1GB) + "GB") }
```
Get Logical Disk Info
```powershell
Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType='3'" -Computer localhost
```
Show Disk Partitions
```powershell
Get-Partition
```
Get Disk Volume Information
```powershell
Get-Volume | Format-Table
```
Get Fixed Volumes
```powershell
Get-Volume | Where-Object DriveType -eq "Fixed"
```
Get Volume Info (Windows 7)
```powershell
Get-WmiObject -Class Win32_Volume -Filter "DriveType='3'" | Select-Object Name
```
Get Share Info
```powershell
Get-SmbShare | Format-List
```
Get Share Info (Version 2)
```powershell
Get-WmiObject -Class Win32_Share -Computer localhost
```

</details>

### 4.3 Processor and Memory

<details>
<summary>4.3 Exercises</summary>


Get Processor Information
```powershell
Get-WmiObject -Class Win32_Processor | Select-Object Name,Description,NumberOfCores | Sort-Object Name
```
Get Number of Memory Slots
```powershell
(Get-WmiObject -Class Win32_PhysicalMemoryArray).MemoryDevices
```
Retrieve Memory Slot Allocations
```powershell
Get-WMIObject -Class Win32_PhysicalMemory | ForEach-Object { Write-Output ($_.DeviceLocator.ToString() + " " + ($_.Capacity/1GB) + "GB") };
```

</details>

### 4.4 Printer Information

<details>
<summary>4.4 Exercises</summary>


Show Printers
```powershell
Get-Printer
```
Show Local Printers
```powershell
Get-Printer | Where-Object { $_.Type -eq "Local" } | Format-Table -AutoSize
```
Show Printer Ports
```powershell
Get-PrinterPort
```

</details>

## Lesson 5

### 5.1 Local Users and Groups

<details>
<summary>5.1 Exercises</summary>


Show Local Users
```powershell
Get-LocalUser
```
Show Local Groups
```powershell
Get-LocalGroup
```
Show Local Group Membership
```powershell
Get-LocalGroupMember -Group Administrators
```
Show Local Group Membership using Pipe
```powershell
Get-LocalGroup -Name 'Remote Desktop Users' | Get-LocalGroupMember
```
Show Local Profiles and Their SIDs
```powershell
Get-WmiObject win32_userprofile | Select-Object LocalPath,SID
```

</details>

### 5.2 Processes and Services

<details>
<summary>5.2 Exercises</summary>


Get Process By Partial Name
```powershell
Get-Process -Name Chrom*
```
View Processes by Highest CPU Usage
```powershell
Get-Process | Sort-Object CPU -Descending | more
```
View Processes by Highest Memory Usage
```powershell
Get-Process | Sort-Object WorkingSet -Descending | more
```
Show File Information for One of the Zoom Processes
```powershell
Get-Process -ProcessName 'Zoom' -FileVersionInfo | Format-List
```
Get Path to Process's Executable
```powershell
Get-Process -FileVersionInfo -ErrorAction "SilentlyContinue" | Select-Object OriginalFilename,FileVersionRaw,FileName | Sort-Object OriginalFilename
#Or
Get-WmiObject -Class Win32_Process -Computer localhost | Select-Object Name,Path | Sort-Object Name
```
Get Owner of the Process
```powershell
Get-WmiObject -Class Win32_Process -Computer localhost | Select-Object Name, @{Name="Owner"; Expression={$_.GetOwner().User}} | Sort-Object Name
```
Get Service By Partial Name
```powershell
Get-Service -Name Spoo*
```
Get Running Services
```powershell
Get-Service | Where { $_.Status -eq "Running" } | Select-Object Name,DisplayName,Status,CanStop | Sort-Object DisplayName
```
Get All Services and the Account which they are running under
```powershell
Get-WmiObject -Class Win32_Service -Computer localhost | Select-Object Name,State,StartName | Sort-Object -Property @{Expression="StartName";Descending=$false},@{Expression="Name";Descending=$false}
```

</details>

### 5.3 Event Logs

<details>
<summary>5.3 Exercises</summary>


Get All Event Log Names
```powershell
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue;
```
Get the Latest 100 Items in the System Log
```powershell
Get-WinEvent -LogName 'System' -MaxEvents 100;
```
Log Entry Types:
- 0 = LogAlways
- 1 = Critical
- 2 = Error
- 3 = Warning
- 4 = Informational
- 5 = Verbose

Keywords:
- AuditFailure = 4503599627370496
- AuditSuccess = 9007199254740992

Get the Lastest 5 Errors in the System Log
```powershell
Get-WinEvent -FilterHashtable @{ LogName='System'; Level=2; } -MaxEvents 5;
```
Get Application Log Entries Between Specific Times
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=(Get-Date).AddDays(-5); EndTime=(Get-Date).AddDays(-1); };
```
Get Failed Logins Over the Last 24 Hours (Requires Elevated Session)
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=(Get-Date).AddDays(-1); Id='4625'; } | Format-List | more;
```
Get Successful Logins Over the Last 24 Hours (Requires Elevated Session)
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=(Get-Date).AddDays(-1); Id='4624'; };
```
Get All Audit Failures in the Past Week
```powershell
Get-WinEvent -FilterHashtable @{ LogName=@('Security'); Keywords=@(4503599627370496); StartTime=(Get-Date).AddDays(-7); } | Format-List | more
```
Get Provider Names for Application, System, and Security Logs (Requires Elevated Session)
```powershell
Get-WinEvent -ListLog @('Application','System','Security') | Select-Object LogName, @{Name="Providers"; Expression={$_.ProviderNames | Sort-Object }} | Foreach-Object { Write-Output("`r`n---- " + $_.LogName + " ----`r`n"); $_.Providers }; 
```
Get Group Policy Related Entries in System Log in the Last 24 Hours
```powershell
Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-GroupPolicy'; StartTime=(Get-Date).AddDays(-1); } | Format-List | more;
```
Get All Sophos and Security Center Events in the Last 72 Hours (Requires Elevated Session)
```powershell
Get-WinEvent -FilterHashtable @{ LogName=@('Application','System','Security'); ProviderName=@('HitmanPro.Alert','SAVOnAccess','SAVOnAccessControl','SAVOnAccessFilter','SecurityCenter'); StartTime=(Get-Date).AddDays(-3); } -ErrorAction SilentlyContinue | Format-List | more
```
Get All Critial or Error Entries from Application, System, and Security Logs in Last 24 Hours (Requires Elevated Session)
```powershell
Get-WinEvent -FilterHashtable @{ LogName=@('Application','System','Security'); Level=@(1,2); StartTime=(Get-Date).AddDays(-1); };
```


</details>

### 5.4 Scheduled Tasks

<details>
<summary>5.4 Exercises</summary>


Show Scheduled Tasks
```powershell
Get-ScheduledTask | Format-List
```
Get Scheduled Task By Name
```powershell
Get-ScheduledTask -TaskName Adobe*
```
Show Schedule Informatio for Task
```powershell
Get-ScheduledTask -TaskName Adobe* | ScheduledTaskInfo
```
Show Execute Actions for All Scheduled Tasks
```powershell
Get-ScheduledTask | Sort-Object -Property TaskName | Foreach-Object { Write-Output("`n" + $_.TaskName + ":"); Foreach ($ta in $_.Actions){$ta.execute}}
```

</details>

## Lesson 6

### 6.1 Remote Desktop Protocol (RDP)

<details>
<summary>6.1 Exercises</summary>

View RDP Configuration (If not set via GPO). Check out fDenyTSConnections key. 0 = enabled, 1 = disabled
```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
```
Check Status of RDP Service
```powershell
Get-Service -Name TermService | Format-List
```
Display information about users logged on to the system. Run with /? for Help
```powershell
quser
```
Display information about Remote Desktop Services sessions. Run with /? for Help
```powershell
qwinsta
```

</details>

### 6.2 Windows Updates

<details>
<summary>6.2 Exercises</summary>

Show Windows Update Log
```powershell
Get-WindowsUpdateLog #Export File Goes to Desktop
```
View Last 50 Entries in Windows Update Log
```powershell
Get-Content ([Environment]::GetFolderPath("Desktop") + "\WindowsUpdate.log") | Select-Object -Last 50
```
Get All Updates Installed in the Last 7 Days
```powershell
Get-HotFix | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-7) }
```
Get the First 10 Items in the Windows Update Log (Windows 7 and Older)
```powershell
Get-Content $env:windir\windowsupdate.log | Select-Object -first 10
```
Display the Lines of the Windows Update Log that Have "Added Update" in Them (Windows 7 and Older)
```powershell
Get-Content $env:windir\windowsupdate.log | Select-String "Added update"
```

</details>

### 6.3 Installed Software

<details>
<summary>6.3 Exercises</summary>


Get List of Installed 64 bit Software
```powershell
Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion
```
Get List of Installed 32 bit Software
```powershell
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion
```
Installed Software Script Code
```powershell
#Create An Array for Storing Installed Applications for Reporting
$arrInstldApps = @();

#Pull 32-bit Installed Applications on System and put them into Report Array
$arrInstldApps = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion;

#Pull 64-bit Installed Applications on System and Add them to Report Array
$arrInstldApps += Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion;

#Display Installed Applications
$arrInstldApps;
```

</details>

## Lesson 7

### 7.1 Network Settings and Connections

<details>
<summary>7.1 Exercises</summary>


Show Network Adapters
```powershell
Get-NetAdapter
```
Get Basic Network Settings
```powershell
Get-NetIPConfiguration
```
Get IP Address Information
```powershell
Get-NetIPAddress
```
Get TCP Connections
```powershell
Get-NetTCPConnection
```
Show Established TCP Connections By Local Port 
```powershell
Get-NetTCPConnection -State Established | Sort-Object LocalPort
```
Show Network Neighbors
```powershell
Get-NetNeighbor
```
Get DNS Information (NSLookup)
```powershell
Resolve-DnsName ucdavis.edu
```
Get Route Information
```powershell
Get-NetRoute
```
Ping Remote System Only Once
```powershell
Test-Connection -TargetName ucdavis.edu -Count 1
```
Traceroute to Remote System
```powershell
Test-Connection -TargetName ucdavis.edu -Traceroute
```
Test If Specific Port Is Open (Computer Name can be hostname or IP Address)
```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 4000
```
Test Network Connection By Port Common Name (Only Options HTTP, RDP, SMB, WINRM)
```powershell
Test-NetConnection -ComputerName localhost -CommonTCPPort RDP
```
Test Network Connection (Ping and TraceRoute)
```powershell
Test-NetConnection universityofcalifornia.edu -TraceRoute
```
Test Network Connection with Detailed Information
```powershell
Test-NetConnection -ComputerName universityofcalifornia.edu -DiagnoseRouting -InformationLevel Detailed
```
Get MAC Addresses of All Network Adapters
```powershell
Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null } | Select-Object Name,MACAddress | Sort-Object Name
```
Get All Assigned IPs
```powershell
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null} | Select-Object Description,IPAddress
```

</details>

### 7.2 Firewall Configuration

<details>
<summary>7.2 Exercises</summary>


Show Firewall Status
```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled
```
Get Firewall Rules Under Domain Profile
```powershell
Get-NetFirewallProfile -Name Domain | Get-NetFirewallRule | More
```
Get Firewall Rules that Allow Inbound Traffic
```powershell
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow
```

</details>

### 7.3 Windows Remote Management

<details>
<summary>7.3 Exercises</summary>

Check Status of WinRM Service
```powershell
Get-Service -Name WinRM
#Or
Test-WSMan
```
View WinRM Config (Requires Elevated Session)
```powershell
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config
```
Display WinRM Listener Information (Requires Elevated Session)
```powershell
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config/Listener -Enumerate
```

</details>

## Lesson 8

### 8.1 Windows Defender

<details>
<summary>8.1 Exercises</summary>

View Current Defender Status
```powershell
Get-MpComputerStatus
```
```powershell
# How Would You Only Display the QuickScanStartTime, QuickScanEndTime, and QuickScanOverDue Properties?
```
View Active and Past Malware Threats that Windows Defender Detected
```powershell
Get-MpThreatDetection
```
View Preferences for the Windows Defender Scans and Updates
```powershell
Get-MpPreference
```
View All Defender Related Commands
```powershell
Get-Command | Where-Object -Property Source -eq -Value "Defender"
```
```powershell
# Which Command Would Start a Quick Scan On the Local System? 
```



</details>

### 8.2 Transport Layer Security (TLS)

<details>
<summary>8.2 Exercises</summary>

Show List of Enabled TLS Cipher Suites
```powershell
Get-TlsCipherSuite
```
Show Only the AES Ciphers
```powershell
Get-TlsCipherSuite -Name "AES"
```
```powershell
# How Would You Just List the Names of the Ciphers?
```
```powershell
# What Happens When You Run
```
```powershell
Get-TlsCipherSuite | Select-Object Name;
```
```powershell
# Let's Look at What the Get-TlsCipherSuite Command Returns. What is the TypeName Value
```
```powershell
Get-TlsCipherSuite | Get-Member
```
```powershell
# What Happens When You Run
```
```powershell
Get-TlsCipherSuite | Foreach-Object { $_.Name  }
```
```powershell
# Check Out the Help on Disabling a Cipher. Are You Able to Pipe In Get-TlsCipherSuite Object Result?
```
```powershell
Get-Help Disable-TlsCipherSuite -Full
```
```powershell
# Would The Below Code Disable the DES Cipher? 
```
```powershell
Foreach($tcs in (Get-TlsCipherSuite -Name "DES")){ Disable-TlsCipherSuite -Name $tcs.Name }
```

</details>

### 8.3 BitLocker

<details>
<summary>8.3 Exercises</summary>

View BitLocker Volume (Requires Elevated Session)
```powershell
Get-BitLockerVolume
```
```powershell
# The BitLockerVolume Class Has More than 10 Properties. How Would You View All Of Them? 
```
```powershell
# How Would You Only Display the "VolumeStatus" Property?
```
```powershell
# Which Command Could You Run to Find The Other "BitLocker" Related Commands?
```


</details>

## Lesson 9

### 9.1 Creating Custom Objects

<details>
<summary>9.1 Exercises</summary>

```powershell
#Initializing Array to Hold Custom Objects
$arrReporting = @();

#Load Up 25 Custom Objects
foreach($n in 1..25)
{
    #Creating a Custom Object 
    $cstObject = New-Object PSObject -Property (@{name=""; weight=0; handed="";});

    #Load Dynamic Value
    $cstObject.name = "User" + $n;
    $cstObject.weight = 100 + $n;

    if($n % 5 -eq 0)
    { 
        $cstObject.handed = "left";
    }
    else 
    {
        $cstObject.handed = "right";
    }

    #Adding Custom Object to Array 
    $arrReporting += $cstObject;
}

#View Reporting Array
$arrReporting;

```

</details>

### 9.2 Plug and Play (PnP) Devices

<details>
<summary>9.2 Exercises</summary>

Show PnP Devices
```powershell
Get-PnpDevice
```
Show PnP USB Devices
```powershell
Get-PnpDevice -Class USB
```
```powershell
<# 
Some PnP Device Classes
AudioEndpoint
Bluetooth
Camera
Image
Media
Monitor
Mouse
Net
PrintQueue
Processor
SecurityDevices
SmartCard
SoftwareDevice
USB
#>
```
```powershell
# How Would You Display the Currently Present USB Devices?
```
```powershell
# Which Command Could You Run to Display the Other PnP Device Related Commands?
```
Show PnP AudioEndpoint and Camera Device Properties
```powershell
Get-PnpDevice -Class AudioEndpoint,Camera | Get-PnpDeviceProperty | Format-Table -AutoSize
```
Show Current PnP AudioEndpoint and Camera Device Friendly Name and Install Date Properties
```powershell
Get-PnpDevice -Class AudioEndpoint,Camera -PresentOnly | Get-PnpDeviceProperty | Sort-Object InstanceId,KeyName | Where-Object -Property KeyName -in -Value "DEVPKEY_Device_FriendlyName", "DEVPKEY_Device_InstallDate" | Format-Table -AutoSize
```
```powershell
<# 

Write a Script That Uses Custom Objects to Report the Friendly Names and Install Dates Of All Image and Media Devices Currently Present. 

Only One Custom Object Per InstanceId

Hint - The Group-Object Command is Your Friend

Export Custom Object Listing to CSV File (See Lesson 2)

#>
```


</details>

## Lesson 10

### 10.1 File Permissions and Processes Script

<details>
<summary>10.1 Exercises</summary>

Write a Script to Report the File Permissions and Active Process Counts of all Program Files Folders and the Windows Directory 
```powershell

#ProgramFiles                   C:\Program Files
#ProgramFiles(x86)              C:\Program Files (x86)
#windir                         C:\WINDOWS

#Array to Hold Current Processes
$arrCurrntProcesses = @();

#Load Array of Strings of Currently Running Process's Executable 
$arrCurrntProcesses = Get-Process -FileVersionInfo -ErrorAction "SilentlyContinue" | Select-Object FileName | Foreach-Object { $_.FileName.ToString().ToLower(); };

#Reporting Array for Locations to Check
$arrReportLTC = @();

#Reporting Array for Locations to Check Permissions
$arrReportLTCPerms = @();

#Array of Locations to Check
$arrLocsToCheck = @(${env:programfiles(x86)},${env:programfiles},${env:windir});

#Loop Through the Locations to Check
foreach($LocToCheck in $arrLocsToCheck)
{
    #Pull Directories Under the Locations to Check
    foreach($ltcFldr in (Get-ChildItem -Path $LocToCheck -Directory -Depth 0))
    {
        #Create Custom Location to Check Folder Object
        $cstLTCFlder = New-Object PSObject -Property (@{ Location=""; Running_Process_Count=0;});
        $cstLTCFlder.Location = $ltcFldr.FullName;

        #Var of LTC Folder to Lower with Extra "\"
        [string]$ltcFldrLoc = $ltcFldr.FullName.ToString().ToLower() + "\";

        foreach($crntPrcs in $arrCurrntProcesses)
        {
            if($crntPrcs.ToString().StartsWith($ltcFldrLoc) -eq $true)
            {
                #####################################
                # What Would We Want To Do Here?
                #####################################
            }

        }

        #Add Custom Object to Reporting Array
        $arrReportLTC += $cstLTCFlder;
        
        #Pull File System ACLs for Folder
        foreach($fsACL in (Get-Acl -Path $ltcFldr.FullName).Access)
        {
            #Create Custom Shared Folder ACL Object
            $cstFsACL = new-object PSObject -Property (@{ Location=""; IdentityReference=""; FileSystemRights=""; AccessControlType=""; IsInherited=""; });
            
            ############################################################
            # Load the Custom Object with File System ACL Information
            #
            #
            #
            #
            #
            #
            ############################################################

            #Add Custom Object to Reporting Array
            $arrReportLTCPerms += $cstFsACL;
        }

    }#End of Get-ChildItem Foreach

}#End of $arrLocsToCheck Foreach

#Var for System Name
[string]$sysName= (hostname).ToString().ToUpper();

#Var for Report Date
[string]$rptDate = (Get-Date).ToString("yyyy-MM-dd");

#Var for LTC Process Counts Report Name
[string]$rptNameProcessCount = ".\LTC_Process_Counts_on_" + $sysName + "_" + $rptDate + ".csv";

#Var for LTC ACL Report Name
[string]$rptNameACLs = ".\LTC_ACLs_on_" + $sysName + "_" + $rptDate + ".csv";

#Export LTC Process Count Report to CSV
$arrReportLTC| Sort-Object -Property Location | Select-Object -Property Location,Running_Process_Count | Export-Csv -Path $rptNameProcessCount -NoTypeInformation;

#########################################################
# Export LTC ACLs Report to CSV
#
# 
#
#########################################################



```


</details>