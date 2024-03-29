<#
    Script: Lesson_06.ps1
    Last Modified: 2021-06-06
#>

#Stopping an Accidental Run
exit

########################################
# Remote Desktop Protocol (RDP)
########################################

#View RDP Configuration (If not set via GPO). Check out fDenyTSConnections key. 0 = enabled, 1 = disabled
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

#Check Status of RDP Services
Get-Service -Name TermService | Format-List

#Display information about users logged on to the system. Run with /? for Help
quser

#Display information about Remote Desktop Services sessions. Run with /? for Help
qwinsta


########################################
# Windows Updates
########################################

#Show Windows Update Log
Get-WindowsUpdateLog #Export File Goes to Desktop

#View Last 50 Entries in Windows Update Log
Get-Content ([Environment]::GetFolderPath("Desktop") + "\WindowsUpdate.log") | Select-Object -Last 50

#Get All Updates Installed in the Last 7 Days
Get-HotFix | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-7) }

#Get the First 10 Items in the Windows Update Log (Windows 7 and Older)
Get-Content $env:windir\windowsupdate.log | Select-Object -first 10

#Display the Lines of the Windows Update Log that Have "Added Update" in Them (Windows 7 and Older)
Get-Content $env:windir\windowsupdate.log | Select-String "Added update"


########################################
# Installed Software
########################################

#Get List of Installed 64 bit Software
Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion

#Get List of Installed 32 bit Software
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion

#######################################
# Installed Software Script Code
#######################################

#Create An Array for Storing Installed Applications for Reporting
$arrInstldApps = @();

#Pull 32-bit Installed Applications on System and put them into Report Array
$arrInstldApps = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion;

#Pull 64-bit Installed Applications on System and Add them to Report Array
$arrInstldApps += Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName,DisplayVersion;

#Display Installed Applications
$arrInstldApps;

