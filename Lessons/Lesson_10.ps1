<#
    Script: Lesson_10.ps1
    Last Modified: 2023-06-10
#>

#Stopping an Accidental Run
exit

#Write a Script to Report the File Permissions of a Program File Location


#ProgramFiles                   C:\Program Files
#ProgramFiles(x86)              C:\Program Files (x86)
#windir                         C:\WINDOWS
#Get-Process -FileVersionInfo -ErrorAction "SilentlyContinue" | Select-Object OriginalFilename,FileVersionRaw,FileName | Sort-Object OriginalFilename

#Get All processes currently running and check the "FileName" property for any paths that fall into the $env:programfiles or $env:programfiles(x86) or $env:windir directories. 

Get-Process -FileVersionInfo -ErrorAction "SilentlyContinue" | Format-List

foreach($d in $dean){ write-output $d.OriginalFileName; write-output $d.FileName;   }