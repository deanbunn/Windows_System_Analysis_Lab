<#
    Script: Lesson_10.ps1
    Last Modified: 2023-06-12
#>

#Stopping an Accidental Run
#exit

#Write a Script to Report the File Permissions of all Program Files Folders ()


#ProgramFiles                   C:\Program Files
#ProgramFiles(x86)              C:\Program Files (x86)
#windir                         C:\WINDOWS


#Array of Locations to Check
$arrLocsToCheck = @(${env:programfiles(x86)},${env:programfiles},${env:windir});

#Loop Through the Locations to Check
foreach($LocToCheck in $arrLocsToCheck)
{
    #Pull Directories Under the Locations to Check
    foreach($ltcFldr in (Get-ChildItem -Path $LocToCheck -Directory -Depth 0))
    {
       
        foreach($fsACL in (Get-Acl -Path $ltcFldr.FullName).Access)
        {
            if($fsACL.IsInherited -eq $false)
            {
                $fsACL.IdentityReference;
                #$fsACL.FileSystemRights;
                #$fsACL.AccessControlType;
                #$fsACL.IsInherited;
            }
           
        }

    }

}