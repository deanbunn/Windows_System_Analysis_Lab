<#
    Script: Lesson_08.ps1
    Last Modified: 2023-06-08
#>

#Stopping an Accidental Run
exit

########################################
# Transport Layer Security (TLS) 
########################################

#Show List of Enabled TLS Cipher Suites
Get-TlsCipherSuite

#Show Only the AES Ciphers
Get-TlsCipherSuite -Name "AES"

#How Would You List Just the Names of the Ciphers? 
#What Happens When You Run
Get-TlsCipherSuite | Select-Object Name;

#Let's Look at What the Get-TlsCipherSuite Command Returns. What is the TypeName Value
Get-TlsCipherSuite | Get-Member

#What Happens When You Run
Get-TlsCipherSuite | Foreach-Object { $_.Name  }