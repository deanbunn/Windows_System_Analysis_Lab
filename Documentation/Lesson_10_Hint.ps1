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

#==================================

<#
    Script: COE_Instruction_Share_Report.ps1
#>

#Var for Instruction Directories Folder Location
[string]$ISDFldrLoc = "E:\Instruction\StudentProfile";

#Var for Pending Deletion Folder Location
[string]$PendingDeletionFlrLoc = "E:\Instruction\PendingDeletion";

#StudentProfile 
#StudentDocs

#Var for Report Date
[string]$rptDate = (Get-Date).ToString("yyyy-MM-dd"); 

#Var for Instruction Report Name
[string]$rptNameInstruction = ".\Report_Instruction_Dirs_on_" + $rptDate + ".csv";

#DateTime for a Month Ago
$dtOldProfile = (Get-Date).AddMonths(-24);

#DateTime for a Month Ahead
$dtMonthAhead = (Get-Date).AddMonths(1);

#Reporting Array
$arrReporting = @();

#Var for Progress Indicator
$prgresIndctr = 0;

#Pull All the Directories Under the Instruction Share
$ISDirctories = Get-ChildItem -Path $ISDFldrLoc -Directory;

#Loop Through Child Directories
foreach($isdCF in $ISDirctories)
{

    #Increment Progress Indicator
    $prgresIndctr++;

    Write-Output ("Serving Number " + $prgresIndctr.ToString());

    #Custom Object for Home Directory Profile Reporting
    $cstFldrInfo = New-Object PSObject -Property(@{ DirName="";
                                                    ProfileLoc="";
                                                    ProfileHDDate="";
                                                    ProfileLWDate="";
                                                    ProfileOld=$true;
                                                    });

    #Set Name of Directory
    $cstFldrInfo.DirName = $isdCF.Name;
        
    #Set Full Profile Location
    $cstFldrInfo.ProfileLoc = $isdCF.FullName;

    #Set Home Directory Last Write Time
    $cstFldrInfo.ProfileHDDate = $isdCF.LastWriteTime.ToString();

    #DateTime for Oldest Profile Folder
    [datetime]$dtOPF = $isdCF.LastWriteTime;

    #Clear Error Log Before Attempting
    $error.Clear();

    #Pull Profile Folders
    $gcProfileFldrs = Get-ChildItem -Path $isdCF.FullName -Recurse; #-Directory
             
    #Check for Profile Folders Before Comparing
    if($gcProfileFldrs -ne $null -and $gcProfileFldrs.Length -gt 1)
    {

        foreach($gcPFldr in $gcProfileFldrs)
        {

            if($gcPFldr.LastWriteTime -gt $dtOPF -and $gcPFldr.LastWriteTime -lt $dtMonthAhead)
            {
                $dtOPF = $gcPFldr.LastWriteTime;
            }

        }#End of $gcProfileFldrs Foreach

    }#End of Null\Empty Checks on Profile Folders

    $cstFldrInfo.ProfileLWDate = $dtOPF.ToString();

    #Check for Old or Errored Profiles
    if($dtOldProfile -lt $dtOPF -or $error.Count -gt 0)
    {
        $cstFldrInfo.ProfileOld = $false;
    }

    #Add to Reporting Array
    $arrReporting += $cstFldrInfo;

}#End $ISDirectories 


<#
foreach($rptInfo in $arrReporting)
{

    #Check for Old Profiles to Move
    if($rptInfo.ProfileOld -eq $true -and [string]::IsNullOrEmpty($rptInfo.ProfileLoc) -eq $false)
    {
        #Move Command
        Move-Item -Path $rptInfo.ProfileLoc -Destination $PendingDeletionFlrLoc

        #Write-Output $rptInfo.ProfileLoc;
    }

}
#>

#Export Reporting Array to CSV
$arrReporting | Sort-Object -Property DirName | Select-Object -Property DirName,ProfileOld,ProfileHDDate,ProfileLWDate,ProfileLoc | Export-Csv -Path $rptNameInstruction -NoTypeInformation;

==================================

#Array to Hold Current Processes
$arrCurrntProcesses = @();

#Load Array of Strings of Currently Running Process's Executable 
$arrCurrntProcesses = Get-Process -FileVersionInfo -ErrorAction "SilentlyContinue" | Select-Object FileName | Foreach-Object { $_.FileName.ToString().ToLower(); };

#Reporting Array for Locations to Check
$arrReportLTC = @();

#Reporting Array for Locations to Check Permissions
$arrReportLTCPerms = @();

#Array of Locations to Check
$arrLocsToCheck = @(${env:programfiles(x86)},${env:programfiles},${env:windir});

#Loop Through the Locations to Check
foreach($LocToCheck in $arrLocsToCheck)
{
    #Pull Directories Under the Locations to Check
    foreach($ltcFldr in (Get-ChildItem -Path $LocToCheck -Directory -Depth 0))
    {
        #Create Custom Location to Check Folder Object
        $cstLTCFlder = New-Object PSObject -Property (@{ Location=""; Running_Process_Count=0;});
        $cstLTCFlder.Location = $ltcFldr.FullName;

        #Var of LTC Folder to Lower with Extra "\"
        [string]$ltcFldrLoc = $ltcFldr.FullName.ToString().ToLower() + "\";

        foreach($crntPrcs in $arrCurrntProcesses)
        {
            if($crntPrcs.ToString().StartsWith($ltcFldrLoc) -eq $true)
            {
                $cstLTCFlder.Running_Process_Count++;
            }

        }

        #Add Custom Object to Reporting Array
        $arrReportLTC += $cstLTCFlder;
        
        #Pull File System ACLs for Folder
        foreach($fsACL in (Get-Acl -Path $ltcFldr.FullName).Access)
        {
            #Create Custom Shared Folder ACL Object
            $cstFsACL = new-object PSObject -Property (@{ Location=""; IdentityReference=""; FileSystemRights=""; AccessControlType=""; IsInherited=""; });
            $cstFsACL.Location = $ltcFldr.FullName;
            $cstFsACL.IdentityReference = $fsACL.IdentityReference;
            $cstFsACL.FileSystemRights = $fsACL.FileSystemRights;
            $cstFsACL.AccessControlType = $fsACL.AccessControlType;
            $cstFsACL.IsInherited = $fsACL.IsInherited;
            
            #Add Custom Object to Reporting Array
            $arrReportLTCPerms += $cstFsACL;
        }

    }#End of Get-ChildItem Foreach

}#End of $arrLocsToCheck Foreach

#Var for System Name
[string]$sysName= (hostname).ToString().ToUpper();

#Var for Report Date
[string]$rptDate = (Get-Date).ToString("yyyy-MM-dd");

#Var for LTC Process Counts Report Name
[string]$rptNameProcessCount = ".\LTC_Process_Counts_on_" + $sysName + "_" + $rptDate + ".csv";

#Var for LTC ACL Report Name
[string]$rptNameACLs = ".\LTC_ACLs_on_" + $sysName + "_" + $rptDate + ".csv";

#Export LTC Process Count Report to CSV
$arrReportLTC| Sort-Object -Property Location | Select-Object -Property Location,Running_Process_Count | Export-Csv -Path $rptNameProcessCount -NoTypeInformation;

#Export LTC ACLs Report to CSV
$arrReportLTCPerms | Sort-Object -Property Location | Select-Object -Property Location,IdentityReference,FileSystemRights,AccessControlType,IsInherited | Export-Csv -Path $rptNameACLs -NoTypeInformation;


