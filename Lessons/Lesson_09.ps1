<#
    Script: Lesson_09.ps1
    Last Modified: 2023-06-09
#>

#Stopping an Accidental Run
exit

########################################
# Creating Custom Objects
########################################

#Creating a Custom Object 
$cstObject = New-Object PSObject -Property (@{name=""; size=""; weight=0;});

#Assigning Values to Custom Object
$cstObject.name = "Raymond Scriptor";
$cstObject.size = "XL";
$cstObject.weight = "180";

#Initializing Array to Hold Custom Objects
$arrReporting = @();

#Adding Custom Object to Array 
$arrReporting += $cstObject;


########################################
# Plug and Play (PnP) Devices
########################################

#Show PnP Devices
Get-PnpDevice

#Show PnP USB Devices
Get-PnpDevice -Class USB

<# Some PnP Device Classes
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


#How Would You Display the Currently Present USB Devices?


#Which Command Could You Run to Display the Other PnP Device Related Commands?


#Show PnP Camera Devices and Device Properties
Get-PnpDevice -Class Camera | Get-PnpDeviceProperty | Format-Table -AutoSize


#Write a Script to Create Custom Object for 