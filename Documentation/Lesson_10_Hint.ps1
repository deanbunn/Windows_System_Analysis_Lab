#Stopping an Accidental Run
exit

<#
    Script: DWS_File_Server_Reports.ps1
#>

#Var for Server Name
[string]$srvName = (hostname).ToString().ToUpper();

#Var for Report Date
[string]$rptDate = (Get-Date).ToString("yyyy-MM-dd");

#Reporting Array for SMB Shares
$raSMB = @();

#Reporting Array for SMB Share Access
$raSMBAccess = @();

#Reporting Array for Share Folder ACLs
$raShareFldACLs = @();


#Pull SMB Share Information
foreach($fsSMB in (Get-SmbShare))
{
    
    #Create Custom SMB Share Object
    $cstSMB = new-object PSObject -Property (@{ Name=""; Description=""; Path=""; });

    #Pull Report Values
    $cstSMB.Name = $fsSMB.Name;
    $cstSMB.Path = $fsSMB.Path;

    #Add SMB Share Information to Reporting Array
    $raSMB += $cstSMB;

    #Pull SMB Access Permissions
    foreach($fsSMBAccess in (Get-SmbShareAccess -Name $fsSMB.Name))
    {

        #Create Custom SMB Share Access Object
        $cstSMBAccess = new-object PSObject -Property (@{ ShareName=""; SharePath=""; AccountName=""; AccessControlType=""; AccessRight=""; });

        #Pull Report Values
        $cstSMBAccess.ShareName = $fsSMBAccess.Name;
        $cstSMBAccess.SharePath = $fsSMB.Path;
        $cstSMBAccess.AccountName = $fsSMBAccess.AccountName;
        $cstSMBAccess.AccessControlType = $fsSMBAccess.AccessControlType;
        $cstSMBAccess.AccessRight = $fsSMBAccess.AccessRight;

        #Add SMB Share Access information to Reporting Array
        $raSMBAccess += $cstSMBAccess;

    }#End of Get-SmbShareAccess Foreach


    #Pull Share Folder ACLs
    if([string]::IsNullOrEmpty($fsSMB.Path) -eq $false)
    {
    
        foreach($fsACL in ((Get-Acl -Path $fsSMB.Path).Access))
        {
       
            #Create Custom Shared Folder ACL Object
            $cstFsACL = new-object PSObject -Property (@{ ShareName=""; SharePath=""; IdentityReference=""; FileSystemRights=""; AccessControlType=""; IsInherited=""; });

            #Pull Report Values
            $cstFsACL.ShareName = $fsSMB.Name;
            $cstFsACL.SharePath = $fsSMB.Path;
            $cstFsACL.IdentityReference = $fsACL.IdentityReference;
            $cstFsACL.FileSystemRights = $fsACL.FileSystemRights;
            $cstFsACL.AccessControlType = $fsACL.AccessControlType;
            $cstFsACL.IsInherited = $fsACL.IsInherited;

            #Add Custome Shared Folder ACL to Reporting Array
            $raShareFldACLs += $cstFsACL;

        }#End of Get-Acl on Shared Folder

    }#End of Null\Empty Checks on Path

}

#Var for SMB Report Name
[string]$rptNameSMB = ".\DWS_Report_FileServer_SMBs_on_" + $srvName + "_" + $rptDate + ".csv";

#Var for SMB Access Report Name
[string]$rptNameSMBAccess = ".\DWS_Report_FileServer_SMBAccess_on_" + $srvName + "_" + $rptDate + ".csv";

#Var for Shared Folder ACL Report Name
[string]$rptNameSFACLs = ".\DWS_Report_FileServer_SharedFolderACLs_on_" + $srvName + "_" + $rptDate + ".csv";

#Export SMB Report to CSV
$raSMB | Sort-Object -Property Path | Select-Object -Property Name,Path,Description | Export-Csv -Path $rptNameSMB -NoTypeInformation;

#Export SMB Access Report to CSV
$raSMBAccess | Sort-Object -Property SharePath | Select-Object -Property ShareName,AccountName,AccessControlType,AccessRight,SharePath | Export-Csv -Path $rptNameSMBAccess -NoTypeInformation;

#Export Shared Folder ACLs Report to CSV
$raShareFldACLs | Sort-Object -Property SharePath | Select-Object -Property ShareName,IdentityReference,FileSystemRights,AccessControlType,IsInherited,SharePath | Export-Csv -Path $rptNameSFACLs -NoTypeInformation;

