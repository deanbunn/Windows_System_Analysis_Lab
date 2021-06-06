<#
    Script: Lesson_07.ps1
    Last Modified: 2021-06-06
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

#Test Network Connection (Ping and TraceRoute)
Test-NetConnection ucdavis.edu -TraceRoute

#Get MAC Addresses of All Network Adapters
Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null } | Select-Object Name,MACAddress | Sort-Object Name

#Get All Assigned IPs 
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null} | Select-Object Description,IPAddress


###########################################
# Firewall Configuration
###########################################

#Show Firewall Status
Get-NetFirewallProfile | Select Name,Enabled

#Get Firewall Rules Under Domain Profile
Get-NetFirewallProfile -Name Domain | Get-NetFirewallRule | More

#Get Firewall Rules that Allow Inbound Traffic
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow