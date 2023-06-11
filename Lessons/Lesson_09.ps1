<#
    Script: Lesson_09.ps1
    Last Modified: 2023-06-09
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


