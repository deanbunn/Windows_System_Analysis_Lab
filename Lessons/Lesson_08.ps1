<#
    Script: Lesson_08.ps1
    Last Modified: 2023-06-09
#>

#Stopping an Accidental Run
exit


########################################
# Windows Defender
########################################

#View Current Defender Status
Get-MpComputerStatus

#How Would You Only Display the QuickScanStartTime, QuickScanEndTime, and QuickScanOverDue Properties?


#View Active and Past Malware Threats that Windows Defender Detected
Get-MpThreatDetection

#View Preferences for the Windows Defender Scans and Updates
Get-MpPreference

#View All Defender Related Commands
Get-Command | Where-Object -Property Source -eq -Value "Defender"

#Which Command Would Start a Quick Scan On the Local System? 


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

#Check Out the Help on Disabling a Cipher. Are You Able to Pipe In Get-TlsCipherSuite Object Result? 
Get-Help Disable-TlsCipherSuite -Full

#Would The Below Code Disable the DES Cipher? 
Foreach($tcs in (Get-TlsCipherSuite -Name "DES")){ Disable-TlsCipherSuite -Name $tcs.Name }


########################################
# BitLocker
########################################

#View BitLocker Volume (Requires Elevated Session)
Get-BitLockerVolume

#The BitLockerVolume Class Has More than 10 Properties. How Would You View All Of Them? 


#How Would You Only Display the "VolumeStatus" Property 


#Which Command Could You Run to Find The Other "BitLocker" Related Commands







