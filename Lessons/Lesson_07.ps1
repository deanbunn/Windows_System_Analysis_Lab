<#
    Script: Lesson_07.ps1
    Last Modified: 2023-06-15
#>

#Stopping an Accidental Run
exit

########################################
# Network Settings and Connections
########################################

#Show Network Adapters
Get-NetAdapter

#Get Basic Network Settings
Get-NetIPConfiguration

#Get IP Address Information
Get-NetIPAddress

#Get TCP Connections
Get-NetTCPConnection

#Show Established TCP Connections By Local Port 
Get-NetTCPConnection -State Established | Sort-Object LocalPort

#Show Network Neighbors
Get-NetNeighbor

#Get DNS Information (NSLookup)
Resolve-DnsName ucdavis.edu

#Get Route Information
Get-NetRoute

#Ping Remote System Only Once
Test-Connection -TargetName ucdavis.edu -Count 1

#Traceroute to Remote System
Test-Connection -TargetName ucdavis.edu -Traceroute

#Test If Specific Port Is Open (Computer Name can be hostname or IP Address)
Test-NetConnection -ComputerName 127.0.0.1 -Port 4000

#Test Network Connection By Port Common Name (Only Options HTTP, RDP, SMB, WINRM)
Test-NetConnection -ComputerName localhost -CommonTCPPort RDP

#Test Network Connection (Ping and TraceRoute)
Test-NetConnection -ComputerName universityofcalifornia.edu -TraceRoute

#Test Network Connection with Detailed Information
Test-NetConnection -ComputerName universityofcalifornia.edu -DiagnoseRouting -InformationLevel Detailed

#Get MAC Addresses of All Network Adapters
Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null } | Select-Object Name,MACAddress | Sort-Object Name

#Get All Assigned IPs 
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null} | Select-Object Description,IPAddress


###########################################
# Firewall Configuration
###########################################

#Show Firewall Status
Get-NetFirewallProfile | Select-Object Name,Enabled

#Get Firewall Rules Under Domain Profile
Get-NetFirewallProfile -Name Domain | Get-NetFirewallRule | More

#Get Firewall Rules that Allow Inbound Traffic
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow


############################################
# Windows Remote Management
############################################

#Check Status of WinRM Service
Get-Service -Name WinRM
#Or 
Test-WSMan 

#View WinRM Config (Requires Elevated Session)
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config

#Display Listener Information (Requires Elevated Session)
Get-WSManInstance -ComputerName Localhost -ResourceURI winrm/config/Listener -Enumerate