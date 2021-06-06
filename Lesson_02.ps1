<#
    Script: Lesson_02.ps1
    Last Modified: 2021-06-06
#>

#Stopping an Accidental Run
exit

########################################
# Script Execution Policy
########################################

#Get Current Policy 
Get-ExecutionPolicy

#Set the Script Execution Policy for Current User 
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

########################################
# Outputs
########################################

#To Get All the Format Object Commands
Get-Command -verb format

#Get All Processes in a GUI Gridview
Get-Process | Out-GridView

#Output Sent to a File
Get-Service | Out-File Services.txt

#Quick Array Sent to a File
@("Server1","Server2","Server3","Server4") | Out-File servers.txt

#Service List Sent to Your Default Printer
Get-Service | Out-Printer 

#Running Service List With Only a Few Columns Exported to CSV
Get-Service | Where { $_.Status -eq "Running" } | Select-Object Name,DisplayName,Status,CanStop | Sort-Object DisplayName | Export-Csv running_services.csv -NoTypeInformation

########################################
# Inputs
########################################

#Prompt User for Info
$requiredData = Read-Host -prompt "Enter Required Data"

#Create String Array From a Text File 
$servers = Get-Content servers.txt

#Import Data a CSV File and Use a Specific Column From It
Import-Csv running_services.csv | Foreach { $_.DisplayName }


########################################
# Errors
########################################

<#
The Setting for Error Handling is Stored in the $ErrorActionPreference variable
Error Handling Options:
1) Continue = Output Error Message; Continue to Run Next Command (Default)
2) SilentlyContinue = Suppress Error Message; Continue to Run the next command
3) Stop = Halt the Execution
4) Inquire = Prompt User for Action to Perform
#>

$ErrorActionPreference = "Continue";

#Errors that Occur During a PowerShell Session are Stored in $error
$error

#Empty Error Messages from $error
$error.clear();

#Some Cmdlets Support an ErrorAction Statement (only for parameter data)
#These Won't Display an Error
Remove-Item nothinghere -ErrorAction "SilentlyContinue";
Stop-Process -ID 8888888 -ErrorAction "SilentlyContinue";
#This Will Due to -ID Must Be an Int
Stop-Process -ID NothingHere -ErrorAction "SilentlyContinue";



