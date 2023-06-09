<#
    Script: Lesson_01.ps1
    Last Modified: 2023-06-08
#>

#Stopping an Accidental Run
exit


########################################
# Transcripts
########################################

#Start a Transcript File
#Default Location C:\Users\userID\Documents\PowerShell_transcript.NNNNNN.NNNNNNNNNNN.txt
Start-Transcript
#Start Transcript with Custom Name
Start-Transcript "MyTranscript.txt"
#Or for the File to be Placed in the Specific Directory
Start-Transcript C:\Script_Runs\MyTranscript.txt

#To Stop the Transcript from Recording Commands and Output
Stop-Transcript

#########################################
#Version of PowerShell Running on System
#########################################
$PSVersionTable

#########################################
# Cmdlets and Modules
#########################################

#Cmdlet Format -eq action-noun
Get-Command -Noun service 

#Get All Commands by a Certain Action
Get-Command -Verb start

#Get All Currently Loaded Cmdlets
Get-Command -CommandType Cmdlet

#Update Help Before Using It
Update-Help

#Basic Help Information for Cmdlet
Get-Help Get-Process

#Online Help for a Cmdlet
Get-Help Get-Process -Online

#Help with Examples
Get-Help Get-Process -examples

#Help Full Listing
Get-Help Get-Process -Full

#Help About a Certain Subject
Get-Help about_operators

#Help About
Get-Help about_*

#Get All PowerShell Modules Available on System
Get-Module -ListAvailable

#Import Module in Current PowerShell Session
Import-Module DnsClient 

#Get All Commands in a Module (Should Only Be Used After Importing)
Get-Command -Module DnsClient 

#Get All PowerShell Modules Available on System
Get-Module -ListAvailable

#Find .NET Object Used in Cmdlet
Get-Process | Get-Member

#List All Alias
Get-Alias

#Look for Specific Alias
Get-Alias -Definition Stop-Process

#Create Alias
New-Alias -Name "Gunrock" Get-ChildItem

#########################################
# Pipeline
#########################################

#Command to Find If CmdLet Allows for Piping (Check Accept Pipeline Property Under Parameters) 
Get-Help Get-Process -full | more 

#Using Out-File to Get Resource Info on the Pipeline
Get-Help About_pipeline | Out-File about_pipeline.txt

#Get All Process and Then Sort by Display Name
Get-Process | Sort-Object ProcessName -descending

#Stop All Notepad Process and Log Process Collection Before Stopping
Get-Process notepad | Tee-Object -file Notepad_Processes.txt | Stop-Process

#Get All Services That Are Running Then Only Show the Display Name
Get-Service | Where-Object { $_.Status -eq "Running" } | ForEach-Object { $_.DisplayName }

#Quick Way to Report on File Types in a Folder
Get-ChildItem | Group-Object -property extension



