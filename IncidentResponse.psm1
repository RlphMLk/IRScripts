$LogFolder = "E:\IncidentResponse\Logs\"      #Folder where log files will be created, must be end with a \

#Display log entry and save it to a log file
function Log($Type,$Message,$Computer) {
    $d = Get-Date
    $d = [string]$d
    $l = $d + "`t" + $env:USERNAME + "`t" + $env:COMPUTERNAME + "`t" + $Type + "`t" + $computer + "`t" + $Message
    if ($type -eq "ERR") {
        write-host -ForegroundColor Yellow $l
    } else {
        Write-Host $l
    }
    $logfile = $LogFolder + $Computer + ".log"
    $l | out-file -FilePath $logfile -Append
}

#Check if a specified file exists on a computer
function FileExists($Computer,$filename) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename
    
    if (Test-path $filename) {
        Log "INFO" ("File found:" + $filename) $computer
    } else {
        Log "ERR" ("File not found:" + $filename) $Computer
    }
}

#List ACL on a specified file on a computer
function FileACL($Computer,$filename) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {    
        $Access = (Get-Acl $filename).Access
        $access | % {
            $l = $filename + "`t" + [string]$_.IdentityReference + "`t" + [string]$_.FileSystemRights + "`t" + [string]$_.AccessControlType + "`t" + [string]$_.IsInherite
            Log "INFO" $l $Computer
        }
    
    } else {
        Log "ERR" ("File not found:" + $filename) $Computer
    }
}

#Check if a specified value exist in a file located on a computer
function FileCheckValue($Computer,$Filename,$Pattern) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {    
        $Res = select-string -path $filename -Pattern $Pattern -CaseSensitive:$false
        if ($Res) {
            Log "INFO" ("Found value in file:" + $Pattern + " in " + $filename) $Computer
        } else {
            Log "ERR" "Could not find value in file" $Computer
        }
    } else {
        Log "ERR" ("File not found:" + $filename) $Computer
    }
}

#Check the file version on a computer
function FileVersion($Computer,$filename) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {    
        $ver = (Get-item $filename).VersionInfo
        $detail = $filename + "`t" + ($ver).FileVersion + "`t" + ($ver).FileDescription + "`t" + ($ver).Product + "`t" + ($ver).ProductVersion
        Log "INFO" $detail $Computer
    } else {
        Log "ERR" "File not found" $Computer
    }
}

#Check if a faile has a valid signature
function FileSignature($Computer,$filename) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {    
        #.\signtool.exe verify /ap $filename 
        .\signtool.exe verify $filename 
        if ($LASTEXITCODE -eq 0) {
            Log "INFO" ("Signature validated:" + $filename) $Computer
        } else {
            Log "ERR" ("Invalid or missing signature:" + $filename) $Computer            
        }
    } else {
        Log "ERR" ("File not found:" + $filename) $Computer
    }
}

#check for files that have been created, accessed or written since a number of hours
function FileLast($Computer,$Path,$Hours,[switch]$Create,[switch]$Access,[switch]$Write) {
    $path = $path.replace(":\","$\")
    $path = "\\" + $computer + "\" + $path

    $Now = Get-Date
    $time = $now.AddHours(-$hours)

    if (Test-path $path) {    
        if ($Create) {
            $items = get-childitem -Path $path -Recurse | ? {$_.CreationTime -ge $time}
        }
        elseif ($Access) {
            $items = get-childitem -Path $path -Recurse | ? {$_.LastAccessTime -ge $time}
        }
        elseif ($Write) {
            $items = get-childitem -Path $path -Recurse | ? {$_.LastWriteTime -ge $time}
        }

        if ($items) {
            $items | % {
                $l = $_.fullname + "`t" + [string]$_.CreationTime + "`t" + [string]$_.LastAccessTime + "`t" + [string]$_.LastWriteTime
                Log "INFO" $l $Computer
            }
        }
    } else {
        Log "ERR" "Folder not found" $Computer
    }
}

#Rename a file
function FileRename($Computer,$OldName,$NewName) {
    $OldName = $OldName.replace(":\","$\")
    $OldName = "\\" + $Computer + "\" + $OldName

    if (Test-path $OldName) {
        write-host "Renaming:" $OldName "to" $NewName
        try {
            rename-item $OldName $NewName
            Log "INFO" ("Successfully ranemed: " + $OldName + " to " + $NewName) $Computer
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }
    } else {
        Log "ERR" ("File not found:" + $OldName) $Computer
    }
}

#function copy folder
function FolderCopy($Computer,$CopySource,$CopyTarget) {
    $CopyTarget = $CopyTarget.Replace(":\","$\")
    $CopyTarget = "\\" + $Computer + "\" + $CopyTarget

    if (Test-path $CopyTarget -eq $false) {
        new-item -path $CopyTarget -ItemType directory -ErrorAction SilentlyContinue
    }

    if (Test-path $CopyTarget) {
        try {
            copy-item -Path $CopySource -Destination $CopyTarget
            Log "INFO" ("Folder copied to:" + $CopyTarget) $computer
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }

    } else {
        Log "ERR" ("Could not create folder:" + $CopyTarget) $Computer
    }
}

#Remove a file or folder
function FileRemove($Computer,$filename) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {
        write-host "Deleting:" $filename
        try {
            remove-item $filename -Confirm:$false -Recurse
            Log "INFO" ("Successfully removed:" + $filename) $Computer
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }
    } else {
        Log "ERR" "File not found" $Computer
    }
}

#Replace a text in a file
function fileUpdate($computer,$filename,$pattern,$replace) {
    $filename = $filename.replace(":\","$\")
    $filename = "\\" + $computer + "\" + $filename

    if (Test-path $filename) {    
        try {
            (get-Content $filename) -Replace $pattern,$replace | Set-Content $filename
            Log "INFO" ("Replace value with " + $replace) $Computer
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }
    
    } else {
        Log "ERR" ("File not found:" + $filename) $Computer
    }
}

#Start/Stop a service or change its startup mode
function Service($Computer,$servicename,[switch]$stop,[switch]$start,[switch]$Disabled,[switch]$Manual,[switch]$Auto,[switch]$status) {
    $filter = "name='" + $servicename + "'"
    $service = Get-WmiObject -Class win32_service -ComputerName $computer -Filter $filter -ErrorAction SilentlyContinue
    if ($service) {
    
        if ($stop) {
                try {
                    $service.StopService()
                    Log "INFO" ("Service stopped:" + $servicename) $Computer
                } catch {
                    Log "ERR" $_.Exception.Message $Computer
                }
            }
        if ($Start) {
                try {
                    $service.StartService()
                    Log "INFO" ("service started:" + $servicename) $Computer
                } catch {
                    Log "ERR" $_.Exception.Message $Computer
                }
            }
        if ($Disabled) {
                try {
                    $service.ChangeStartMode("disabled")
                    Log "INFO" ("Service set to disabled:" + $servicename) $Computer
                } catch {
                    Log "ERR" $_.Exception.Message $Computer
                }
            }
        if ($Manual) {
                try {
                    $service.ChangeStartMode("manual")
                    Log "INFO" ("Service set to Manual:" + $servicename) $computer
                } catch {
                    Log "ERR" $_.Exception.Message $Computer
                }
            }
        if ($Auto) {
                try {
                    $service.ChangeStartMode("automatic")
                    Log "INFO" ("Service set to Automatic:" + $servicename) $computer
                } catch {
                    Log "ERR" $_.Exception.Message $Computer
                }
            }
        if ($status) {
            $l = $Service.name + "`t" + $service.status + "`t" + $service.StartMode + "`t" + $service.StartName
            Log "INFO" $l $Computer
        }
            
    } else {
        Log "ERR" ("Service was not found:" + $servicename) $Computer
    }

}

<#
    The script only acts on HKLM and HKLM must not be specified

    get Registry key
    .\Registry.ps1 -Computer PC1 -KeyPath SOFTWARE\TEST -KeyValue MYVALUE1  -Get
    Modify existing key
    .\Registry.ps1 -Computer PC1 -KeyPath SOFTWARE\TEST -KeyValue MYVALUE1  -Type REG_DWORD -Value 4 -Set
    Create a new registry key
    .\Registry.ps1 -Computer PC1 -KeyPath SOFTWARE\TEST -KeyValue MYVALUE2  -Type REG_DWORD -Value 1 -Set

    Delete a registry key
    .\Registry.ps1 -Computer pc1 -KeyPath software\test\subkey -Delete
    Delete a registry key value
    .\Registry.ps1 -Computer pc1 -KeyPath software\test -KeyValue myvalue1 -Delete

    -Set can be used to create a new entry or even modify an entry type
#>
function REGistry($computer,$KeyPath,$KeyValue,$Value,$Type,[switch]$Get,[switch]$Set,[switch]$Delete,[switch]$Create) {

    If ($type) {
        $type = $type.ToUpper()
        switch ($type) {
            "REG_DWORD" {
                $RegType = [Microsoft.Win32.RegistryValueKind]::DWORD
            }
            "REG_SZ" {
                $RegType = [Microsoft.Win32.RegistryValueKind]::String
            }
            "REG_BINARY" {
                $RegType = [Microsoft.Win32.RegistryValueKind]::Binary 
            }
        }
    }

    try {        
        $key = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer)        
        $SubKey = $Key.OpenSubKey($KeyPath,$true)
    } catch {
        Log "ERR" $_.Exception.Message $Computer
    }

    if ($SubKey) {
        if ($Get) {
            try {
                $value = $SubKey.GetValue($KeyValue)
                Log "INFO" $value $Computer
            } catch {            
                Log "ERR" $_.Exception.Message $Computer
            }
        }

        if ($Set) {
            try {
                $SubKey.SetValue($KeyValue,$Value,$RegType)
                Log "INFO" ("Set " + $KeyValue + "=" + $value + " " + $RegType) $Computer
            } catch {
                Log "ERR" $_.Exception.Message $Computer
            }
        }

        if ($Create) {
            try {
                $SubKey.CreateSubKey($KeyValue)
                Log "INFO" ("Create " + $KeyPath) $Computer
            } catch {
                Log "ERR" $_.Exception.Message $Computer
            }
        }

        if ($Delete) {
            try {                
                if ($KeyPath -and $KeyValue) {
                    $Subkey.DeleteValue($KeyValue)
                    Log "INFO" ("Deleted " + $KeyValue) $Computer
                } elseif ($KeyPath) {
                    $key.DeleteSubKeyTree($Keypath)
                    Log "INFO" ("Deleted " + $KeyPath) $Computer
                }
            } catch {
                Log "ERR" $_.Exception.Message $Computer
            }
        }
    } else {
        Log "ERR" ("Could not open subkey:" + $Keypath) $Computer
    }

}

#Check if a process is running or start/stop a process
function fProc($computer,$process,[switch]$Stop,[switch]$Start) {
    #$filter = "name='" + $Process + "'"
    $filter = "name LIKE '%" + $Process + "%'"

    if (!$Start) {
        try {
            $Proc = Get-wmiobject -ComputerName $Computer -Class win32_process -filter $filter  -ErrorAction Stop             
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }
    }
 
    if ($Proc) {
        if ($Stop) {
            try {
                $Proc.Terminate()
                Log "INFO" ($Proc.name + " process stoped") $Computer
            } catch {
                Log "ERR" ($proc.name + "could not be stopped " + $_.Exception.Message) $Computer
            }
        } else {
            Log "INFO" $Process $Computer
        }    
    } elseif ($Start) {
        try {
            Invoke-WmiMethod -ComputerName $Computer -Class win32_process -Name Create -ArgumentList $Process    
            Log "INFO" "Started process" $Computer
        } catch {
            Log "ERR" "Could not start process" $Computer
        }
    } else {
        Log "ERR" "Process not found" $Computer
    }
}

#Stop or Restart a computer
function ComputerStop($Computer,[switch]$Stop,[switch]$Restart) {
    try {
        if ($Stop) {
            Stop-Computer -ComputerName $Computer -Force -ErrorAction Stop
            Log "INFO" "Successfully Stopped" $Computer
        } elseif ($Restart) {
            Restart-Computer -ComputerName $Computer -Force -ErrorAction Stop
            Log "INFO" "Successfully restarted" $Computer
        } else {
            Log "ERR" "No valid parameter" $Computer
        }    
    } catch {
        Log "ERR" $_.Exception.Message $Computer
    }
}

#Edit HOSTS file
function EditHOSTS($Computer,$Hostname,$HostIP,[switch]$add,[switch]$Remove) {
    $filename = "\\" + $computer + "\c$\Windows\System32\drivers\etc\hosts"

    if (Test-path $filename) {    
        try {                    
            if ($Add) {
                $hosts = Get-Content $filename
                $hosts += "`r`n" + $HostIP + "`t" + $hostname + "`t#Added by Incident Response script"
                $hosts | Set-Content $filename

                Log "INFO" ("Adding entry in HOSTS file " + $hostip + "`t" + $hostname) $Computer
            } elseif ($Remove) {
                $newfile = select-string -path $filename -Pattern $hostname -NotMatch | Select-Object -ExpandProperty line                
                $newfile | Set-Content $filename

                Log "INFO" ("Removing entry in HOSTS file " + $hostip + "`t" + $hostname) $Computer
            }
        } catch {
            Log "ERR" $_.Exception.Message $Computer
        }
    
    } else {
        Log "ERR" "File not found"$filename $Computer
    }
}

#Get currently logged on user
function LogonUser($Computer) {
    $Except = @("SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON")
    $SAM = @()

    try {
        $users = Get-WmiObject win32_loggedonuser -ComputerName $Computer | Select-Object dependent,antecedent
    } catch {
        Log "ERR" $_.Exception.Message $Computer
    }

    if ($users) {    
        foreach ($user in $users) {
            $s = $user.antecedent
            $s
            $s0 = $s.split(",")[0]
            $s1 = $s.split(",")[1]
            $s0 = $s0.Split("=")[1]
            $s0 = $s0.replace("""","")
            $s0
            $s1 = $s1.split("=")[1]
            $s1 = $s1.replace("""","")
            $s1
            if ($Except -notcontains $s1) {          
                #Log "INFO" ($s0 + "\" + $s1) $Computer
                $SAM += ($s0 + "\" + $s1)
            }
        }
    }

    If ($SAM) {
        $SAM = $SAM | Select-Object | Group-Object | Select-Object name
        $SAM | % {
            Log "INFO" $_.Name $Computer
        }
    }
}

#List profiles folder with last access dates
function Profiles($Computer) {
    $Path = "\\" + $Computer + "\c$\users"
    
    $folders = Get-ChildItem -Path $path -Directory -ea SilentlyContinue    
    
    if ($folders) {
        foreach ($folder in $folders) {
            $d = $folder.LastAccessTime
            $LastAccess =  '{0:dd\/MM\/yyyy}' -f $d             
            $l = $folder.name + "`t" + $LastAccess                    
            Log "INFO" $l $Computer
        }
    } else {
        Log "ERR" "Could not get folders users" $Computer
    }
}

#List, Enable / Disable a local user
function LocalUser($Computer, $User, [switch]$Enable, [switch]$Disable) {
    try {
        $ADSIComputer = [ADSI]("WinNT://$Computer,computer") 
        $ADSIUser = $ADSIComputer.psbase.children.find($User,  'User')     
    } catch {
        Log "ERR" $_.Exception.Message $Computer
    }

    if ($ADSIUser) {
        if ($Enable) {
            try {
                $ADSIUser.invokeSet("userFlags", ($ADSIUser.userFlags[0] -BXOR 2))
                $ADSIUser.commitChanges()
                Log "INFO" "User has been enabled" $Computer
            } catch {
                Log "ERR" "Could not enable user" $Computer
            }

        } elseif ($Disable) {
            try {
                $ADSIUser.invokeSet("userFlags", ($ADSIUser.userFlags[0] -BOR 2))
                $ADSIUser.commitChanges()
                Log "INFO" "User has been disabled" $Computer
            } catch {
                Log "ERR" "Could not disable user" $Computer
            }
        
        } else {        
            $enabled = !($ADSIUser.UserFlags[0] -band 2)
            Log "INFO" $enabled $Computer
        }
    } else {
        Log "ERR" "User not found" $Computer
    }
}

#Check or add/remove a member to the local Administrators group
function LocalAdmin($Computer,$Member,[switch]$AddUser,[switch]$RemoveUser,[switch]$AddGroup,[switch]$RemoveGroup) {
    try {
        $ADSIComputer = [ADSI]("WinNT://$Computer,computer") 
        $Admins = $ADSIComputer.psbase.children.find('Administrators', 'Group') 
    } catch {
        Log "ERR" "Could not get Administrators group" $Computer
    }

    if ($Member) {
        $Member = $Member.replace("\","/")
    }

    if ($AddUser -or $RemoveUser) {
        try {
            $User = [ADSI]"WinNT://$Member,user"
        } catch {
            Log "ERR" "Could not find user to add/remove:"$Member
        }
    }

    if ($AddGroup -or $RemoveGroup) {
        try {
            $User = [ADSI]"WinNT://$Member,group"
        } catch {
            Log "ERR" "Could not find Group to add/remove:"$Member
        }
    }

    if ($AddUser -or $AddGroup) {                
        if ($User) {
            try {
                $Admins.Add($User.Path)
                Log "INFO" ("Added to local Administrators`t" + $member) $computer
            } catch {
                Log "ERR" $_.Exception.Message $Computer
            }
        }
    } elseif ($RemoveUser -or $RemoveGroup) {
        if ($User) {
            try {
                $Admins.Remove($User.Path)
                Log "INFO" ("Removed from local Administrators`t" + $member) $computer
            } catch {
                Log "ERR" $_.Exception.Message $Computer
            }
        }                
    } else {
        if ($Admins) {
            $Admins.psbase.invoke("members") | % {
                $mbr = $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
                log "INFO" ("Member of Administrators`t" + $mbr) $Computer
            }
        }
    }
}

Export-ModuleMember Log
Export-ModuleMember FileExists
Export-ModuleMember FileACL
Export-ModuleMember FileCheckValue
Export-ModuleMember FileVersion
Export-ModuleMember FileSignature
Export-ModuleMember FileLast
Export-ModuleMember FileRename
Export-ModuleMember FileRemove
Export-ModuleMember fileUpdate
Export-ModuleMember Service
Export-ModuleMember Registry
Export-ModuleMember fProc
Export-ModuleMember ComputerStop
Export-ModuleMember EditHOSTS
Export-ModuleMember LogonUser
Export-ModuleMember Profiles
Export-ModuleMember LocalUser
Export-ModuleMember LocalAdmin
Export-ModuleMember FolderCopy