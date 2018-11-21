$PrimaryReplicaIndi = @()
$PrimaryFQDN = [System.Net.Dns]::GetHostByName(($NODE)) | Select-Object Hostname
$primfqdn = $PrimaryFQDN.Hostname
$primEndpoint = "TCP://"+$primfqdn+":5022"
$PrimaryReplica = $PrimaryReplicaName
$SecondaryReplica = $SecondaryReplicaNames
$DB_Names = $DatabaseList
$AGName = $AvailabilityGroupName
if(($PrimarySQLConnObj.AvailabilityGroups.Name -contains $AGName)){
    Write-Output "AG discovered"
    $agobj = $PrimarySQLConnObj.AvailabilityGroups[$AGName]
    $Databases = @()
    $SecondaryReplicas = $secondaryReplica.Split(",")

    #Backup the Database
    foreach($DB_NAME in $DB_Names){
        $BKPDIR = $PrimarySQLConnObj.BackupDirectory
        if($PrimarySQLConnObj.Databases.Name.Contains($DB_NAME)){
            $db = $PrimarySQLConnObj.Databases | Where-Object {$_.Name -eq $DB_Name}
            $RecoveryModel = $db.RecoveryModel
            if($RecoveryModel -eq "Full"){
                if(!(Test-Path -Path "$BKPDIR\BackupShare")){
                    New-Item -ItemType DIRECTORY -PATH $BKPDIR -Name "BackupShare"
                }            
                $ALWAYSONBACKUPLOC = "$BKPDIR\BackupShare"
                PUSH-LOCATION
                SET-LOCATION "SQLSERVER:\SQL\$NODE\$INS"
                Backup-SqlDatabase  "$DB_NAME" "$ALWAYSONBACKUPLOC\$DB_NAME.bak" -CompressionOption On 
                Backup-SqlDatabase  "$DB_NAME" "$ALWAYSONBACKUPLOC\$DB_NAME.trn" -BackupAction Log
                Pop-Location
                Write-Output "Backup of the database $DB_NAME successful"
            } else {
                Throw "Requested Database is in Simple Recovery model"
            }
        } else {
            Throw "Requested Database isn't present in the instance"
        }
    }

    #Share the Directory
    $Replicas = $SecondaryReplicas
    if($PrimaryReplica -like "*\*"){
        $srvHostInst = $PrimaryReplica.Split("\")
        $srvHost = $srvHostInst[0]
        $srvInst = $srvHostInst[1]
        $Instance = "MSSQL$"+$srvInst
        $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
    } else {
        $srvHost = $PrimaryReplica
        $Instance = "MSSQLSERVER"
        $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
    }

    $directory = $ALWAYSONBACKUPLOC
    $ShareName = "AGBackupShare"
    $account = $ServiceAcct

    if(!(Get-SMBShare -Name $ShareName -ea 0)){
        New-SmbShare -Name $ShareName -Path $directory -FullAccess $account -ErrorAction silentlyContinue -ErrorVariable ShrErr | Out-Null
    } Else {
        Grant-SmbShareAccess -Name $ShareName -AccountName $account -AccessRight Full -Force | Out-Null
    }
    If($ShrErr.count -ne 0){
        $SHRError = $ShrErr[0].Exception.Message
        Throw "Error Creating Share due to an exception: $SHRError"
    }

    $BackupShare = "\\$srvHost\AGBackupShare"


    #Add database to AG
    foreach($db in $DB_Names){
        Add-SqlAvailabilityDatabase -InputObject $agobj -Database "$db" -ErrorAction Stop
    }

    foreach($replica in $SecondaryReplicas){
        $secondarySQLConnObj = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $replica
        if($replica -like "*\*"){
            $SecondaryInsName = $replica.Split("\")
            $secondaryReplicaNode = $SecondaryInsName[0]
            $secondaryReplicaIns = $SecondaryInsName[1]
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        } else {
            $secondaryReplicaNode = $replica
            $secondaryReplicaIns = "DEFAULT"
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        }

        #Restore the Secondary Databases
        foreach($db in $DB_Names){
            $Instance = $Replica
            $DBName = $db
            $BackupLocation = $BackupShare

            IF($Instance -like "*\*"){
                $SQLINSTANCESEC = $Instance.Split("\")
                $SECNODE = $SQLINSTANCESEC[0]
                $SECINS = $SQLINSTANCESEC[1]
            } ELSE {
                $SECNODE = $Instance
                $SECINS = "DEFAULT"
            }

            Push-Location
            SET-LOCATION "SQLSERVER:\SQL\$SECNODE\$SECINS"
            Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.bak" -NoRecovery -ErrorVariable restorerr
            if($restorerr.count -gt 0){
                Throw "Restore failed due to error: $restorerr"
            }
            Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.trn" -RestoreAction "Log" -NoRecovery -ErrorVariable logrestorerr
            if($logrestorerr.count -gt 0){
                Throw "Log Restore failed due to error: $logrestorerr"
            }
            Pop-Location
            Write-Output "Database $dbname is restored successfully on secondary replica $Instance"
        }
        
        $SecondaryAGobject = $secondarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}

        foreach($db in $DB_Names){
            $datab = $secondarySQLConnObj.Databases | Where-Object {$_.Name -eq $db}
            if($datab.Status -eq "Restoring"){
                $Databases += $db
                Add-SqlAvailabilityDatabase -InputObject $SecondaryAGobject -Database "$db"
            } else {
                Write-Output "Database $db isn't initilised. Please restore the database and join the database to Availability Group"
            }
        }
    }
} Else {
    $PrimaryReplicaIndi = New-SqlAvailabilityReplica -Name $PrimaryReplica -EndpointUrl $primEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" -AsTemplate -Version ($PrimarySQLConnObj.Version)
    New-SqlAvailabilityGroup -InputObject $PrimaryReplica -Name $AGName -AvailabilityReplica $PrimaryReplicaIndi -Database $DB_Names -ErrorAction Stop

    #Backup the Database
    foreach($DB_NAME in $DB_Names){
        $BKPDIR = $PrimarySQLConnObj.BackupDirectory
        if($PrimarySQLConnObj.Databases.Name.Contains($DB_NAME)){
            $db = $PrimarySQLConnObj.Databases | Where-Object {$_.Name -eq $DB_Name}
            $RecoveryModel = $db.RecoveryModel
            if($RecoveryModel -eq "Full"){
                if(!(Test-Path -Path "$BKPDIR\BackupShare")){
                    New-Item -ItemType DIRECTORY -PATH $BKPDIR -Name "BackupShare"
                }            
                $ALWAYSONBACKUPLOC = "$BKPDIR\BackupShare"
                PUSH-LOCATION
                SET-LOCATION "SQLSERVER:\SQL\$NODE\$INS"
                Backup-SqlDatabase  "$DB_NAME" "$ALWAYSONBACKUPLOC\$DB_NAME.bak" -CompressionOption On 
                Backup-SqlDatabase  "$DB_NAME" "$ALWAYSONBACKUPLOC\$DB_NAME.trn" -BackupAction Log
                Pop-Location
                Write-Output "Backup of the database $DB_NAME successful"
            } else {
                Throw "Requested Database is in Simple Recovery model"
            }
        } else {
            Throw "Requested Database isn't present in the instance"
        }
    }

    $SecondaryReplicas = $secondaryReplica.Split(",")
    $agobj = $PrimarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}

    #Share the Directory
    $Replicas = $SecondaryReplicas
    if($PrimaryReplica -like "*\*"){
        $srvHostInst = $PrimaryReplica.Split("\")
        $srvHost = $srvHostInst[0]
        $srvInst = $srvHostInst[1]
        $Instance = "MSSQL$"+$srvInst
        $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
    } else {
        $srvHost = $PrimaryReplica
        $Instance = "MSSQLSERVER"
        $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
    }

    $directory = $ALWAYSONBACKUPLOC
    $ShareName = "AGBackupShare"
    $account = $ServiceAcct

    if(!(Get-SMBShare -Name $ShareName -ea 0)){
        New-SmbShare -Name $ShareName -Path $directory -FullAccess $account -ErrorAction silentlyContinue -ErrorVariable ShrErr | Out-Null
    } Else {
        Grant-SmbShareAccess -Name $ShareName -AccountName $account -AccessRight Full -Force | Out-Null
    }
    If($ShrErr.count -ne 0){
        $SHRError = $ShrErr[0].Exception.Message
        Throw "Error Creating Share due to an exception: $SHRError"
    }

    $BackupShare = "\\$srvHost\AGBackupShare"

    foreach($replica in $SecondaryReplicas){
        $secondarySQLConnObj = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $replica
        if($replica -like "*\*"){
            $SecondaryInsName = $replica.Split("\")
            $secondaryReplicaNode = $SecondaryInsName[0]
            $secondaryReplicaIns = $SecondaryInsName[1]
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        } else {
            $secondaryReplicaNode = $replica
            $secondaryReplicaIns = "DEFAULT"
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        }

        #Restore the Secondary Databases
        foreach($db in $DB_Names){
            $Instance = $Replica
            $DBName = $db
            $BackupLocation = $BackupShare

            IF($Instance -like "*\*"){
                $SQLINSTANCESEC = $Instance.Split("\")
                $SECNODE = $SQLINSTANCESEC[0]
                $SECINS = $SQLINSTANCESEC[1]
            } ELSE {
                $SECNODE = $Instance
                $SECINS = "DEFAULT"
            }

            Push-Location
            SET-LOCATION "SQLSERVER:\SQL\$SECNODE\$SECINS"
            Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.bak" -NoRecovery -ErrorVariable restorerr
            if($restorerr.count -gt 0){
                Throw "Restore failed due to error: $restorerr"
            }
            Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.trn" -RestoreAction "Log" -NoRecovery -ErrorVariable logrestorerr
            if($logrestorerr.count -gt 0){
                Throw "Log Restore failed due to error: $logrestorerr"
            }
            Pop-Location
            Write-Output "Database $dbname is restored successfully on secondary replica $Instance"
        }
    }

    #Refresh the SQL Primary Connection
    IF($PrimaryReplica -like "*\*"){
        $SQLINSTANCE = $PrimaryReplica.Split("\")
        $NODE = $SQLINSTANCE[0]
        $INS = $SQLINSTANCE[1]
    } ELSE {
        $NODE = $PrimaryReplica
        $INS = "DEFAULT"
    }
    
    foreach($replica in $SecondaryReplicas){
        $secondarySQLConnObj = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $replica
        if($replica -like "*\*"){
            $SecondaryInsName = $replica.Split("\")
            $secondaryReplicaNode = $SecondaryInsName[0]
            $secondaryReplicaIns = $SecondaryInsName[1]
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        } else {
            $secondaryReplicaNode = $replica
            $secondaryReplicaIns = "DEFAULT"
            $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
            $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
        }
        $SecFQDN = $SecondaryFQDN.Hostname
        $secEndpoint = "TCP://"+$SecFQDN+":5022"    
        New-SqlAvailabilityReplica -Name $replica -InputObject $agobj -EndpointUrl $secEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" 
        Join-SqlAvailabilityGroup -Name $AGName -InputObject $secondarySQLConnObj -ErrorAction Stop
        $SecondaryAGobject = $secondarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
        foreach($db in $DB_Names){
            $datab = $secondarySQLConnObj.Databases | Where-Object {$_.Name -eq $db}
            if($datab.Status -eq "Restoring"){
                $Databases += $db
                Add-SqlAvailabilityDatabase -InputObject $SecondaryAGobject -Database "$db"
            } else {
                Throw "Database $db isn't initilised. Please restore the database and join the database to Availability Group"
            }
        }
    }
}
