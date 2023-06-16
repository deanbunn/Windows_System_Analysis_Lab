#Stopping an Accidental Run
exit

$arrReporting = @();

$pnpDevices = Get-PnpDevice -Class AudioEndpoint,Camera -PresentOnly | Get-PnpDeviceProperty | Sort-Object InstanceId,KeyName | Where-Object -Property KeyName -in -Value "DEVPKEY_Device_FriendlyName", "DEVPKEY_Device_InstallDate" | Group-Object -Property InstanceId;

foreach($pnpDvc in $pnpDevices)
{
    #Custom Reporting Object
    $cstDevObj = New-Object PSObject -Property (@{id=""; name=""; install_date="";});

    #Set ID
    $cstDevObj.id = $pnpDvc.Name;

    foreach($dvGM in $pnpDvc.Group)
    {
        #Pull Friendly Name
        if($dvGM.KeyName -eq "DEVPKEY_Device_FriendlyName") 
        {
            $cstDevObj.name = $dvGM.Data;
        }

        #Pull Install Date
        if($dvGM.KeyName -eq "DEVPKEY_Device_InstallDate") 
        {
            $cstDevObj.install_date = $dvGM.Data;
        }

    }

    $arrReporting += $cstDevObj;
}

$arrReporting; 

#================================

1..254 | Foreach-Object { $pingStatus = Test-Connection "192.168.0.$_" -Count 1 -Quiet; "192.168.0.$_ $pingStatus" }
