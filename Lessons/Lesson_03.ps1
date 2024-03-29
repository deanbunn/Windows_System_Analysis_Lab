<#
    Script: Lesson_03.ps1
    Last Modified: 2023-06-08
#>

#Stopping an Accidental Run
exit

########################################
# Environment Variables
########################################

#View Environment
Get-ChildItem Env:

#View Path Environment Variable
$Env:path -split ";"

########################################
# File System
########################################

#Navigate with Set-Location (alias cd)
Set-Location c:\users\$env:username\desktop

#List Items in Current Directory
Get-ChildItem 

#List Only the Text File
Get-ChildItem -Filter *.txt

#Get List of All "Item" Cmdlets
Get-Command -noun item | Select-Object Name | Sort-Object Name | Out-File Item_Commands.txt

<#
Clear-Item                                                                                                             
Copy-Item                                                                                                              
Get-Item                                                                                                               
Invoke-Item                                                                                                            
Move-Item                                                                                                              
New-Item                                                                                                               
Remove-Item                                                                                                            
Rename-Item                                                                                                            
Set-Item 
#>

#Get the Path of Current Operating Directory
(Get-Location).Path

#Check to See If a Directory or File Exists
Test-Path -Path c:\goldenstate\warriors.txt

#Get List of All "Content" Cmdlets
Get-Command -Noun Content

<#
Add-Content
Clear-Content
Get-Content
Set-Content
#>

#Search for All Text Files on System Drive
Get-Childitem -Path c:\ -Filter *.txt -Recurse;

#Create a Folder
New-Item My_Scripts -ItemType Directory
 
#Create a Text File 
New-Item .\My_Scripts\first_script.ps1 -ItemType File;

#Add Content to a File
Add-Content -Path .\My_Scripts\first_script.ps1 -Value "Get-Service";

#Move or Rename a File
Move-Item .\My_Scripts\first_script.ps1 .\My_Scripts\second_script.ps1;

#Get Rights on Current Directory
Get-Acl -Path . | Format-List

#Get Access on Current Directory
(Get-Acl -Path .).Access

#Get the Owner of a Directory or File
(Get-Acl -Path c:\Intel\Logs).Owner 

#List the NTFS Permissions of a File or Folder
(Get-Acl -Path $env:programfiles).Access

#Show Permissions in Friendly Format on Current Directory
(Get-Acl -Path .).Access | Select-Object -ExpandProperty IdentityReference FileSystemRights | Format-Table Value,FileSystemRights

#View File Hash
Get-FileHash .\Scary_Executable_I_Just_Downloaded.exe 

########################################
# PSDrive
########################################

#PS Drives
Get-PSDrive

#List PSDrive for Registry
Get-PSDrive -PSProvider Registry

#Change to HKEY_LOCAL_MACHINE
Set-Location HKLM:

#View Windows Current Version Information
Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion'

#View RDP Port Number (Requires Admin Console)
(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").PortNumber

#System Environment 
Set-Location env:

########################################
# Searching File Contents
########################################

#Create File to Search
Get-Process | Out-File processes.txt

#Search a File for a Specific Term
Select-String "svchost" .\processes.txt 

#Search for String in File and Show One Line Before and Three Lines After
Select-String "explorer" .\processes.txt -Context 1,3

#Search Multiple Files
Select-String "explorer" .\process* 

