## Beginning PowerShell for Windows System Analysis Lab

Seven quick sessions to learn the basics of PowerShell while analysing the configuration of a Windows system.

**All lab code and descriptions are listed in README**. 

The lesson script files are designed to only be used as a downloadable reference. 

At the beginning of each script is a "exit" command to prevent an accidental run


## Lesson 1

<details>
<summary>Transcripts</summary>


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

<details>
<summary>PowerShell Version</summary>


View PowerShell Version
```powershell
$PSVersionTable
```
</details>

<details>
<summary>Cmdlets and Modules</summary>

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

<details>
<summary>Pipeline</summary>

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
Get-Service | Where { $_.Status -eq "Running" } | ForEach-Object { $_.DisplayName }
```
Quick Way to Report on File Types in a Folder
```powershell
Get-ChildItem | Group-Object -property extension
```

</details>

## Lesson 2

<details>
<summary>Script Execution Policy</summary>

Get Current Policy
```powershell
Get-ExecutionPolicy
```
Set the Script Execution Policy for Current User 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

</details>

<details>
<summary>Outputs</summary>

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
Get-Service | Where { $_.Status -eq "Running" } | Select-Object Name,DisplayName,Status,CanStop | Sort-Object DisplayName | Export-Csv running_services.csv -NoTypeInformation
```

</details>

<details>
<summary>Inputs</summary>

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
Import-Csv running_services.csv | Foreach { $_.DisplayName }
```

</details>

<details>
<summary>Errors</summary>

The Setting for Error Handling is Stored in the $ErrorActionPreference variable
Error Handling Options:
1. Continue = Output Error Message; Continue to Run Next Command (Default)
2. SilentlyContinue = Suppress Error Message; Continue to Run the next command
3. Stop = Halt the Execution
4. Inquire = Prompt User for Action to Perform

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

<details>
<summary>Environment Variables</summary>


View Environment Variables
```powershell
Get-ChildItem Env:
```
View Path Environment Variable
```powershell
$Env:path -split ";"
```

</details>


<details>
<summary>File System</summary>


Navigate with Set-Location (alias cd)
```powershell
cd c:\users\$env:username\Desktop
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
Get-Command -noun item | Select-Object Name | Sort-Object Name
```
Get the Path of Current Operating Directory
```powershell
(get-location).path
```
Check to See If a Directory or File Exists
```powershell
Test-Path -Path c:\goldenstate\warriors.txt
```
Get List of All "Content" Cmdlets
```powershell
Get-Command -Noun content
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
Get-Acl -Path . | fl
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
(Get-Acl -Path .).Access | Select-Object -ExpandProperty IdentityReference FileSystemRights | FT Value,FileSystemRights
```
View File Hash
```powershell
Get-FileHash .\Scary_Executable_I_Just_Downloaded.exe
```

</details>

<details>
<summary>PSDrive and Registry</summary>


PS Drives
```powershell
Get-PSDrive
```
List PSDrive for Registry
```powershell
Get-PSDrive -PSProvider Registry
```
Change to HKEY_LOCAL_MACHINE
```powershell
cd HKLM:
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
cd env:
```

</details>

<details>
<summary>Searching File Contents</summary>


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

<details>
<summary>System Information</summary>


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

</details>

<details>
<summary>Disk Information</summary>


Get Disk Information
```powershell
Get-Disk | FL
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
Get-Volume | FT
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
Get-SmbShare | FL
```
Get Share Info (Version 2)
```powershell
Get-WmiObject -Class Win32_Share -Computer localhost
```

</details>

<details>
<summary>Processor and Memory</summary>


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

<details>
<summary>Printer Information</summary>


Show Printers
```powershell
Get-Printer
```
Show Printer Ports
```powershell
Get-PrinterPort
```

</details>

## Lession 5

<details>
<summary>Local Users and Groups</summary>


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
Show Local Profiles and Their SIDs
```powershell
Get-WmiObject win32_userprofile | Select LocalPath,SID
```

</details>

<details>
<summary>Processes and Services</summary>


Get Process By Partial Name
```powershell
Get-Process -Name FireFo*
```
Get Path to Process's Executable
```powershell
Get-Process -FileVersionInfo | Select-Object OriginalFilename,FileName | Sort-Object OriginalFilename
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

<details>
<summary>Event Logs</summary>


Get All Event Log Names on a System
```powershell
Get-EventLog -List
```
Get the Latest 100 Items in the System Log
```powershell
Get-EventLog -LogName System -Newest 100 | Select-Object Message
```
Get the Lastest 5 Errors in the System Log
```powershell
Get-EventLog -LogName System -EntryType Error -Newest 5
#EntryTypes Information, Warning, Error, FailureAudit, SuccessAudit
```
Get Application Log Entries Between Specific Times
```powershell
Get-EventLog -LogName Application -Before (get-date).AddDays(-1) -After (get-date).AddDays(-3)
```
Get Failed Logins Over the Last 24 Hours
```powershell
Get-EventLog -LogName Security -After (get-date).AddDays(-1) | Where-Object { $_.instanceID -eq 4625 }
```
Get Successful Logins Over the Last 24 Hours
```powershell
Get-EventLog -LogName Security -InstanceId 4624 -After (get-date).AddDays(-1)
```

</details>

<details>
<summary>Scheduled Tasks</summary>


Show Scheduled Tasks
```powershell
Get-ScheduledTask | FL
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

## Lession 6

<details>
<summary>Remote Desktop Protocol (RDP)</summary>

View RDP Configuration (If not set via GPO). Check out fDenyTSConnections key. 0 = enabled, 1 = disabled
```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
```
Check Status of RDP Service
```powershell
Get-Service -Name TermService | fl
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

<details>
<summary>Windows Updates</summary>

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

<details>
<summary>Installed Software</summary>


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

## Lession 7

<details>
<summary>Network Settings and Connections</summary>


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
Test Network Connection (Ping and TraceRoute)
```powershell
Test-NetConnection ucdavis.edu -TraceRoute
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

<details>
<summary>Firewall Configuration</summary>


Show Firewall Status
```powershell
Get-NetFirewallProfile | Select Name,Enabled
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

<details>
<summary>Windows Remote Management</summary>

Check Status of WinRM Service
```powershell
Get-Service -Name WinRM
#Or
Test-WSMan
```
View WinRM Config
```powershell
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config
```
Display WinRM Listener Information
```powershell
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config/Listener -Enumerate
```


</details>

