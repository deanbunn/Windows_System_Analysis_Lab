<#
    Script: Lesson_09.ps1
    Last Modified: 2023-06-16
#>

#Stopping an Accidental Run
exit

########################################
# Creating Custom Objects
########################################

#Initializing Array to Hold Custom Objects
$arrReporting = @();

#Load Up 25 Custom Objects
foreach($n in 1..25)
{
    #Creating a Custom Object 
    $cstObject = New-Object PSObject -Property (@{name=""; weight=0; handed="";});

    #Load Dynamic Value
    $cstObject.name = "User" + $n;
    $cstObject.weight = 100 + $n;

    if($n % 5 -eq 0)
    { 
        $cstObject.handed = "left"
    }
    else 
    {
        $cstObject.handed = "right"
    }

    #Adding Custom Object to Array 
    $arrReporting += $cstObject;
}

#View Reporting Array
$arrReporting;

########################################
# Ping IP Range
########################################

# Write a One-Liner to Ping a Class C Network and Report the Status of Each Ping.

# Extra Points for Pinging Each IP Only Once and Incorporating the "Quiet" Switch


########################################
# Plug and Play (PnP) Devices
########################################

#Show PnP Devices
Get-PnpDevice

#Show PnP USB Devices
Get-PnpDevice -Class USB

<# 
Some PnP Device Classes
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


#Show PnP AudioEndpoint and Camera Device Properties
Get-PnpDevice -Class AudioEndpoint,Camera | Get-PnpDeviceProperty | Format-Table -AutoSize

#Show Current PnP AudioEndpoint and Camera Device Friendly Name and Install Date Properties
Get-PnpDevice -Class AudioEndpoint,Camera -PresentOnly | Get-PnpDeviceProperty | Sort-Object InstanceId,KeyName | Where-Object -Property KeyName -in -Value "DEVPKEY_Device_FriendlyName", "DEVPKEY_Device_InstallDate" | Format-Table -AutoSize


#Write a Script That Uses Custom Objects to Report the Friendly Names and Install Dates Of All Image and Media Devices Currently Present. 
#Only One Custom Object Per InstanceId
#Hint - The Group-Object Command is Your Friend
#Export Custom Object Listing to CSV File (See Lesson 2)