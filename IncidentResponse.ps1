
cls
$folder = "E:\IncidentResponse\" #Folder where menu files and main log file is stored, must end with \
$LogFolder = "E:\IncidentResponse\Logs\"      #Folder where log files will be created, must be end with a \

$Computer = $CSVFile = $null

if ( (test-path -Path $LogFolder -ErrorAction SilentlyContinue) -ne $true) {
    new-item $LogFolder -ItemType Directory
}
Get-Childitem ($Logfolder + "*.log") | remove-item -Confirm:$false -ErrorAction SilentlyContinue

$help1 = Get-Content -Path '.\list_computers.txt'
$help1

write-host -ForegroundColor cyan "Target Selection"
write-host "1. Specify a computer name"
write-host "2. Log a CSV file (One column file with header named Computer"
$choice = Read-Host "Enter a value for the target selection"

switch($choice) {
    1 {
        write-host
        $Computers = Read-Host "Type Computer name or IP"
    }
    2 {
        $CSVFile = Read-host "Enter CSV file full name"
        if (test-path $CSVFile) {            
            $Computers = Get-Content -Path $CSVFile
        } else {
            write-host -ForegroundColor Yellow "could not load file"$CSVFile
        }
    }
}

if ($Computers) {
    $Menu0 = Get-Content -Path '.\Menu0.txt'
    write-host
    write-host -ForegroundColor cyan "Script type selection"
    $Menu0
    $choice = Read-Host "Enter a value for the script type selection" 

    switch ($choice) {
        1 {
            Write-Host
            Write-Host -ForegroundColor cyan "File script selection"
            $Menu1 = Get-Content -path '.\Menu1.txt'
            $Menu1
            $choice1 = Read-Host "Enter a value for the file script seleection"

            switch ($choice1) {
                1 {
                    write-host
                    $filename = read-host "Enter file full name"
                    foreach ($Computer in $Computers) {
                        Start-Job  -Name $Computer -ScriptBlock {
                            param(
                                $computer,$filename
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileExists $Computer $filename
                           
                        } -ArgumentList $computer,$filename
                    }
                }

                2 {
                    write-host
                    $filename = read-host "Enter file full name"
                    foreach ($computer in $computers) {
                        Start-Job -Name $computer -ScriptBlock {
                            param(
                                $computer,$filename
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileACL $Computer $filename

                        } -ArgumentList $computer,$filename                        
                    }
                }
                
                3 {
                    write-host
                    $filename = read-host "Enter file full name"
                    $Pattern = Read-Host "Enter value to look for in a file"
                    foreach ($computer in $computers) {
                        Start-job -Name $computer -ScriptBlock {
                            param(
                                $Computer,$Filename,$Pattern
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileCheckValue $Computer $Filename $Pattern
                        } -ArgumentList $Computer,$Filename,$Pattern
                    }
                }

                4 {
                    write-host
                    $filename = read-host "Enter file full name"
                    foreach ($computer in $computers) {
                        Start-Job -Name $computer -ScriptBlock {
                            param(
                                $computer,$filename
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileVersion $Computer $filename

                        } -ArgumentList $computer,$filename
                    }
                }

                5 {
                    write-host
                    $filename = read-host "Enter file full name"
                    foreach ($Computer in $Computers) {
                        start-job -Name $computer -ScriptBlock {
                            param(
                                $computer,$filename
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileSignature $Computer $filename
                        } -ArgumentList $computer,$filename
                    }  
                }

                6 {
                    write-host
                    $Path = Read-Host "Enter a folder path"
                    $Hours = Read-Host "Enter the number of hours for the last action"
                    foreach ($Computer in $Computers) {
                        Start-Job -Name $Computer -ScriptBlock {
                            param(
                                $Computer, $Path,$Hours
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileLast $Computer $Path $Hours -Create
                        } -ArgumentList $Computer,$Path,$Hours
                    }
                }

                7 {
                    write-host
                    $Path = Read-Host "Enter a folder path"                    
                    $Hours = Read-Host "Enter the number of hours for the last action"
                    foreach ($Computer in $Computers) {
                        Start-Job -Name $Computer -ScriptBlock {
                            param(
                                $Computer, $Path,$Hours
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileLast $computer $path $hours -Access
                        } -ArgumentList $Computer,$Path,$Hours
                    }
                }

                8 {
                    write-host
                    $Path = Read-Host "Enter a folder path"                    
                    $Hours = Read-Host "Enter the number of hours for the last action"
                    foreach ($Computer in $Computers) {
                        Start-Job -Name $Computer -ScriptBlock {
                            param(
                                $Computer, $Path,$Hours
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileLast $computer $path $hours -Write
                        } -ArgumentList $Computer,$Path,$Hours
                    }
                }

                9 {
                    Write-Host
                    $file1 = Read-Host "Enter the file to rename full name"
                    $file2 = Read-host "Enter the new file name"
                    foreach ($Computer in $Computers) {
                        Start-Job -Name $Computer -ScriptBlock {
                            param(
                                $computer,$file1,$file2
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileRename $computer $file1 $file2
                        } -ArgumentList $computer,$file1,$file2
                    }
                }

                10 {
                    write-host
                    $filename = Read-Host "Enter the path to delete (file or folder)"
                    foreach ($computer in $Computers) {
                        Start-Job -Name $computer -ScriptBlock {
                            param(
                                $computer,$filename
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FileRemove $computer $filename
                        } -ArgumentList $computer,$filename
                    }
                }

                11 {
                    write-host
                    $filename = Read-host "Enter a file full name"
                    $Pattern = Read-Host "Enter the text to replace"
                    $Replace = Read-host "Enter the new text value"
                    foreach ($Computer in $Computers) {
                        Start-Job -Name $Computer -ScriptBlock {
                            param(
                                $computer,$filename,$pattern,$replace
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            fileUpdate $computer $filename $pattern $replace
                        } -ArgumentList $computer,$filename,$pattern,$replace
                    }
                }

                12 {
                    write-host
                    $CopySource = Read-Host "Enter local folder to copy i.e. c:\temp\ToCopyToAllPC"
                    $CopyTarget = Read-Host "Enter destination folder i.e. c:\temp\myData"
                    foreach ($Computer in $Computers) {
                        start-job -Name $Computer -ScriptBlock {
                            param(
                                $Computer,$CopySource,$CopyTarget
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            FolderCopy $Computer $CopySource $CopyTarget
                        } -ArgumentList $Computer,$CopySource,$CopyTarget
                    }
                }
            }
        }    
        
        2 {
            Write-Host
            Write-Host -ForegroundColor cyan "Service script selection"
            $Menu2 = Get-Content -path '.\Menu2.txt'
            $Menu2
            $choice2 = Read-Host "Enter a value for the service script seleection"

            switch ($choice2) {
                1 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to check"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -Status
                        } -ArgumentList $computer,$service
                    }
                }

                2 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to stop"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -stop
                        } -ArgumentList $computer,$service
                    }
                }

                3 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to start"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -Start
                        } -ArgumentList $computer,$service
                    }
                }

                4 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to disable"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -Disabled
                        } -ArgumentList $computer,$service
                    }
                }
                    
                5 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to set to manual"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -Manual
                        } -ArgumentList $computer,$service
                    }
                }

                6 {
                    Write-Host
                    $Service = Read-Host "Enter the service name to set to automatic"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$service
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Service $computer $service -Auto
                        } -ArgumentList $computer,$service
                    }
                }
            }
        }

        3 {
            Write-Host
            Write-Host -ForegroundColor cyan "Registry script selection"
            $Menu3 = Get-Content -path '.\Menu3.txt'
            $Menu3
            $choice3 = Read-Host "Enter a value for the registry script seleection"

            switch ($choice3) {
                1 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $KeyValue = Read-Host "Enter the key value i.e. MyValue"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$KeyPath, $KeyValue
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Registry -Computer $computer -KeyPath $KeyPath -KeyValue $KeyValue -Get
                        } -ArgumentList $computer,$KeyPath,$KeyValue
                    }
                }

                2 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $KeyValue = Read-Host "Enter the key value i.e. MyValue"                                        
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$KeyPath,$KeyValue
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1                            
                            Registry -Computer $computer -KeyPath $KeyPath -KeyValue $KeyValue -Create
                        } -ArgumentList $computer,$KeyPath,$KeyValue
                    }
                }

                3 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $KeyValue = Read-Host "Enter the key value i.e. MyValue"
                    $RegType = Read-Host "Enter the registry type REG_DWORD, REG_SZ or REG_BINARY"
                    $Value = Read-Host "Enter registry value"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(                                
                                $computer,$KeyPath,$KeyValue,$RegType,$Value
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Registry -Computer $computer -KeyPath $KeyPath -KeyValue $KeyValue -Type $RegType -Value $Value -Set
                        } -ArgumentList $computer,$KeyPath,$KeyValue,$RegType,$Value
                    }
                }

                4 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $Confirm = Read-Host "Do you want to delete the Key and its subcontent (y/n)"
                    $confirm = $Confirm.ToUpper()
                    if ($Confirm -eq 'Y') {
                        foreach ($computer in $computers) {
                            start-job -ScriptBlock {
                                param(
                                    $computer,$KeyPath
                                )
                                Import-Module E:\IncidentResponse\IncidentResponse.psm1
                                Registry $computer $KeyPath -Delete
                            } -ArgumentList $computer,$KeyPath
                        }
                    }
                }

                5 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $KeyValue = Read-Host "Enter the key value i.e. MyValue"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$KeyPath,$KeyValue
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Registry $computer $KeyPath $KeyValue -Delete
                        } -ArgumentList $computer,$KeyPath,$KeyValue
                    }
                }

                6 {
                    write-host
                    $KeyPath = Read-Host "Enter the Key Path without HKLM: i.e. SOFTWARE\MyKey"
                    $NewKey = Read-Host "Enter the new key name i.e. MyKey"
                    foreach($Computer in $Computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $Computer,$Keypath,$NewKey
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Registry $Computer $KeyPath -
                        } -ArgumentList $Computer,$Keypath,$NewKey
                    }
                }
            }    
        }

        4 {
            write-host
            Write-Host -ForegroundColor cyan "Process script selection"
            $Menu4 = Get-Content -path '.\Menu4.txt'
            $Menu4
            $choice4 = Read-Host "Enter a value for the Process script seleection"

            switch ($choice4) {
                1 {
                    write-host
                    $Process = read-host "Enter the process name to check"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$process
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            fProc $computer $Process
                        } -ArgumentList $computer,$process
                    }
                }

                2 {
                    write-host
                    $Process = read-host "Enter the process name to stop"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$process
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            fProc $computer $Process -Stop
                        } -ArgumentList $computer,$process
                    }
                }

                3 {
                    write-host
                    $Process = read-host "Enter the process name to start"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$process
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            fProc $computer $Process -Start
                        } -ArgumentList $computer,$process
                    }
                }
            }
        }

        5 {
            write-host
            Write-Host -ForegroundColor cyan "Computer script selection"
            $Menu5 = Get-Content -path '.\Menu5.txt'
            $Menu5
            $choice5 = Read-Host "Enter a value for the Computer script seleection"

            switch ($choice5) {
                1 {
                    write-host
                    $Confirm = Read-Host "Do you want to restart all computers Y/N"
                    $Confirm = $Confirm.ToUpper()
                    if ($Confirm -eq 'Y') {
                        foreach ($computer in $computers) {
                            Start-Job -ScriptBlock {
                                param(
                                    $Computer                                    
                                )
                                Import-Module E:\IncidentResponse\IncidentResponse.psm1
                                ComputerStop $Computer -Restart
                            } -ArgumentList $computer
                        }
                    }
                }

                2 {
                    write-host
                    $Confirm = Read-Host "Do you want to stop all computers Y/N"
                    $Confirm = $Confirm.ToUpper()
                    if ($Confirm -eq 'Y') {
                        foreach ($computer in $computers) {
                            Start-Job -ScriptBlock {
                                param(
                                    $Computer                                    
                                )
                                Import-Module E:\IncidentResponse\IncidentResponse.psm1
                                ComputerStop $Computer -Stop
                            } -ArgumentList $computer
                        }
                    }
                }

                3 {
                    write-host
                    foreach ($Computer in $Computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $Computer
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LogonUser $Computer
                        } -ArgumentList $Computer
                    }
                }

                4 {
                    write-host
                    foreach ($Computer in $Computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $Computer
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            Profiles $Computer
                        } -ArgumentList $Computer
                    }
                }
            }
        }

        6 {
            write-host
            Write-Host -ForegroundColor cyan "Network script selection"
            $Menu6 = Get-Content -path '.\Menu6.txt'
            $Menu6
            $choice6 = Read-Host "Enter a value for the Network script seleection"

            switch ($choice6) {
                1 {
                    write-host
                    $HostName = Read-Host "Enter host name to add"
                    $HostIP = Read-host "Enter IP address for the host to add"
                    foreach($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$HostName,$HostIP
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            EditHOSTS $computer $hostname $HostIP -Add
                        } -ArgumentList $computer,$HostName,$HostIP
                    }
                }

                2 {
                    Write-Host
                    $hostname = Read-Host "Enter host name entry to remove"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$hostname
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            EditHOSTS $Computer $Hostname -Remove
                        } -ArgumentList $computer,$hostname
                    }
                }
            }
        }

        7 {
            write-host
            Write-Host -ForegroundColor cyan "Local user script selection"
            $Menu7 = Get-Content -path '.\Menu7.txt'
            $Menu7
            $choice7 = Read-Host "Enter a value for the Local user script seleection"

            switch ($choice7) {
                1 {
                    write-host
                    $User = Read-Host "Enter user name to check"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalUser $Computer $User
                        } -ArgumentList $computer,$User
                    }
                }

                2 {
                    Write-Host
                    $User = Read-Host "Enter user name to enable"
                                        foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalUser $Computer $User -Enable
                        } -ArgumentList $computer,$User
                    }
                }

                3 {
                    Write-Host
                    $user = read-host "Enter user name to diable"
                    foreach ($computer in $computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalUser $Computer $User -Disable
                        } -ArgumentList $computer,$User
                    }
                }

                4 {
                    write-host
                    foreach ($Computer in $Computers) {
                        Start-Job -ScriptBlock {
                            param(
                                $Computer
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalAdmin $Computer
                        } -ArgumentList $Computer
                    }
                }

                5 {
                    write-host
                    $User = Read-Host "Enter a user name to add to the local Administrators group"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalAdmin $Computer $User -AddUser
                        } -ArgumentList $computer,$user
                    }
                }

                6 {
                    write-host
                    $User = Read-Host "Enter a group name to add to the local Administrators group"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalAdmin $Computer $User -AddGroup
                        } -ArgumentList $computer,$user
                    }
                }

                7 {
                    write-host
                    $User = Read-Host "Enter a user name to remove from the local Administrators group"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalAdmin $Computer $User -RemoveUser
                        } -ArgumentList $computer,$user
                    }
                }

                8 {
                    write-host
                    $User = Read-Host "Enter a group name to remove from the local Administrators group"
                    foreach ($computer in $computers) {
                        start-job -ScriptBlock {
                            param(
                                $computer,$user
                            )
                            Import-Module E:\IncidentResponse\IncidentResponse.psm1
                            LocalAdmin $Computer $User -RemoveGroup
                        } -ArgumentList $computer,$user
                    }
                }
            }
        }
    }

    write-host
    write-host "Waiting for jobs, you can check the log file"
    get-job | wait-job
        
    move-item ($Folder + "IncidentResponse.log") $LogFolder
    new-item -ItemType file ($folder + "IncidentResponse.log")
    Get-Content ($LogFolder + "*.log") | Add-Content ($folder + "IncidentResponse.log")

    write-host
    write-host "To view the output of a job type: Receive-Job job_number -keep"
    $rep = Read-Host "Do you want to delete all jobs Y/N ?"
    $rep = $rep.ToLower()
    if ($rep -eq 'Y') {
        get-job | remove-job
    } else {
        get-job
    }
}

