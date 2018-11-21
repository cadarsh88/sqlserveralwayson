#***************************************************************************************************************************************************#
#                                                                FUNCTIONS                                                                          #
#***************************************************************************************************************************************************#
#Function to Load SQLPS Module
function Set-SQLPS {
    try{
        $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
        $module = (Get-Module -FullyQualifiedName 'SQLPS' -ListAvailable).Name
        Import-Module -Name $module -DisableNameChecking -Verbose:$False -ErrorAction Stop
        Write-Host "SQLPS Import Successful"
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } catch {
        $ExceptionMessage = $_.Exception.Message
        Write-Host "Exception Importing SQLPS module due to exception: $ExceptionMessage"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}
#Function to Connect to SQL Instance
function Connect-SQLInstance
{
    [CmdletBinding()]
    param
    (
        [ValidateNotNull()]
        [System.String]
        $Computer = $env:COMPUTERNAME,

        [ValidateNotNull()]
        [System.String]
        $SQLInstanceName = 'MSSQLSERVER',

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $SetupCredential
    )
        try{
            if ($SQLInstanceName -eq 'MSSQLSERVER')
            {
                $databaseEngineInstance = $Computer
            }
            else
            {
                $databaseEngineInstance = "$Computer\$SQLInstanceName"
            }
            if ($SetupCredential)
            {
                $sql = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server
                $sql.ConnectionContext.ConnectAsUser = $true
                $sql.ConnectionContext.ConnectAsUserPassword = $SetupCredential.GetNetworkCredential().Password
                $sql.ConnectionContext.ConnectAsUserName = $SetupCredential.GetNetworkCredential().UserName
                $sql.ConnectionContext.ServerInstance = $databaseEngineInstance
                $sql.ConnectionContext.Connect()
            }
            else
            {
                $sql = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $databaseEngineInstance
                $sql.status
            }
            if ( $sql.Status -match '^Online$' )
            {
                return $sql
            }
            else
            {
            Throw "Failed to Connect to SQL Instance. Status of $SQLInstanceName is:"+$sql.Status
            }
        } Catch {
            $chkexception = $_.Exception.Message
            Write-Host "Error connecting to SQL Instance $SQLInstanceName on Computer $Computer due to exception: $chkexception"
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        }
}

#Function to Check Cluster Configuration
Function Check-ClusterStatus {
    Param(
        [String] $PrimaryReplica,
        [String] $SecondaryReplica #Comma seperated
    )
    try{
        $PrimaryNode = Invoke-Sqlcmd -ServerInstance "$primaryReplica" -Database "Master" -Query "SELECT @@SERVERNAME as HOSTNAME" -ErrorAction Stop -ErrorVariable sqlConnectError
        
        if($sqlConnectError.count -gt 0){
            Write-Host "Unable to connect to the Replica"
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        }

        $InstanceNode = @{}
        $ClusterNodes = Get-ClusterNode | Select-Object Name

        if($PrimaryNode.HOSTNAME -in $ClusterNodes.Name){
            $InstanceNode.Add($PrimaryReplica, $PrimaryNode)
        } else {
            Write-Host "Node $PrimaryNode not part of the cluster"
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        }

        foreach($Replica in $SecondaryReplicas){
            $Node = Invoke-Sqlcmd -ServerInstance "$Replica" -Database "Master" -Query "SELECT @@SERVERNAME as HOSTNAME" -ErrorAction Stop -ErrorVariable sqlConnectError
            
            if($sqlConnectError.count -gt 0){
                Write-Host "Unable to connect to the Replica"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            }

            if($Node.HOSTNAME -in $InstanceNode.Keys){
                Write-Host "Same Node cannot host more than one Replica for a given Availability Group"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            } else {
                if($node.HOSTNAME -in $ClusterNodes.Name){
                    $InstanceNode.Add($Replica, $Node)
                } else {
                    Write-Host "Node $node not part of the cluster"
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                }
            }
        }
        Write-Host "Cluster and Replica Configuration looks good."
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } Catch {
        $chkexception = $_.Exception.Message
        Write-Host "Error Checking Cluster-Node matching due to the exception: $chkexception"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}

#Function to Check Instance Preparedness for AlwaysON
Function Set-AlwaysON_Foundation {
    PARAM(
        [String]$ReplicaInstance
    )
    try{
        if($ReplicaInstance -like "*\*"){
            $NodeIns = $ReplicaInstance.Split("\")
            $Computer = $NodeIns[0]
            $Instance = $NodeIns[1]
            $servINS = "MSSQL$"+$Instance
        } else {
            $Computer = $ReplicaInstance
            $Instance = "MSSQLSERVER"
            $servINS = "MSSQLSERVER"
        }

        $SQLConnObj = Connect-SQLInstance -Computer $Computer -SQLInstanceName $Instance
        if($SQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $ReplicaInstance"
        }
        [String[]]$InstalledInstances = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
        If($SQLConnObj.IsHadrEnabled){
            Write-Host "AlwaysON feature already enabled."
        } else {
            Enable-SqlAlwaysOn -ServerInstance $instancename -Force -ErrorAction Stop
            Restart-Service -name $servINS -force -WarningAction SilentlyContinue
            Start-Sleep -seconds 30
            $svcStatus=Get-Service -name $svcname | Select-Object Status
        }
        Write-Host "SQL Instance $ReplicaInstance is all set to host Availability Group"
        return New-Object PSObject -Property @{
            Status="Success"
            ServiceStatus = $svcStatus
        }
    } Catch {
        $EXCEPTION = $_.EXCEPTION
        WRITE-HOST "Error enabling HADR on Replica $Computer due to the exception: $EXCEPTION"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
} 

#Function to Validate Service Accounts and respective permissions
Function Check-ReplicaServiceAccounts {
    Param(
        [String] $Replica,
        [String] $ServiceAcct
    )
    Try{
        If($Replica -like "*\*"){
            $ServerIns = $Replica.Split("\")
            $Node = $ServerIns[0]
            $Instance = $ServerIns[1]
            $InstanceSVC = "MSSQL$"+$Instance
            $SVCAccount = Get-WmiObject Win32_Service -ComputerName $Node | Where-Object {$_.Name -eq $InstanceSVC}
            if($ServiceAcct -ne $SVCAccount.StartName){
                Write-Host "SQL Service on Replica $Replica is not $ServiceAcct"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            }
            $SQLConnObj = Connect-SQLInstance -Computer $Node -SQLInstanceName $Instance
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $Replica"
            }
            $svcLogin = $SQLConnObj.Logins | Where-Object{ $_.Name -eq $ServiceAcct}
            if($svcLogin.ListMembers() -notcontains "sysadmin"){
                $svcLogin.AddToRole("sysadmin")
            }
        } Else {
            $ServerIns = $Replica
            $Node = $ServerIns
            $Instance = "MSSQLSERVER"
            $SVCAccount = Get-WmiObject Win32_Service -ComputerName $Node | Where-Object {$_.Name -eq $Instance} 
            if($ServiceAcct -ne $SVCAccount.StartName){
                Write-Host "SQL Service on Replica $Replica is not $ServiceAcct"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            }
            $SQLConnObj = Connect-SQLInstance -Computer $Node -SQLInstanceName $Instance
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $Replica"
            }
            $svcLogin = $SQLConnObj.Logins | Where-Object{ $_.Name -eq $ServiceAcct}
            if($svcLogin.ListMembers() -notcontains "sysadmin"){
                $svcLogin.AddToRole("sysadmin")
            }
        }
        Write-Host "Service Accounts on the replica $Replica is same as that of Primary Replica and has necessary permissions. "
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } Catch {
        $chkexception = $_.Exception.Message
        Write-Host "Error validating Service Accounts on Replica due to the exception: $chkexception"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}

#Function to Validate Replica Editions
Function Check-ReplicaEditions {
    Param(
        [String] $PrimaryReplica,
        [String] $SecondaryReplica  #Comma seperated
    )

    try{
        Write-Host $PrimaryReplica, $SecondaryReplica
        $PrimaryNode = Invoke-Sqlcmd -ServerInstance "$primaryReplica" -Database "Master" -Query "select @@SERVERNAME as HOSTNAME" -ErrorAction Stop
        $SecondaryReplicas = $SecondaryReplica.Split(",")
        if($PrimaryReplica -eq $PrimaryNode.HOSTNAME){
            $SQLConnObj = Connect-SQLInstance -Computer $PrimaryNode.Hostname -SQLInstanceName "MSSQLSERVER"
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $PrimaryReplica"
            }
        } ELSE {
            $PrimInsName = $PrimaryReplica.split("\")
            $SQLConnObj = Connect-SQLInstance -Computer $PrimaryNode.Hostname -SQLInstanceName $PrimInsName[1]
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $PrimaryReplica"
            }
        }
        $primMajorVersion = $SQLConnObj.Version.Major
        $primSQLVersionBuild = $SQLConnObj.Version.Build
        $primSQLEdition = $SQLConnObj.EngineEdition
        if((($primMajorVersion -eq 11) -or ($primMajorVersion -eq 12)) -and ($primSQLEdition -notlike "*Enterprise*")){
            Write-Host "This Edition of SQL Server doesn't support AlwaysON"
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        } elseif (($primMajorVersion -ge 13) -and (($primSQLEdition -like "*Enterprise*") -or (($primSQLEdition -like "*Standard*") -and ($primSQLVersionBuild -lt 4000)))){
            Write-Host "This Edition of SQL Server doesn't support AlwaysON"
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        } 
        foreach($Replica in $SecondaryReplicas){
            if($Replica -like "*\*"){
                $SecondaryInsName = $Replica.Split("\")
                $secondarySQLConnObj = Connect-SQLInstance -Computer $SecondaryInsName[0] -SQLInstanceName $SecondaryInsName[1]
                if($secondarySQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $Replica"
                }
                $secondaryMajorVersion = $secondarySQLConnObj.Version.Major
                $secondarySQLVersionBuild = $secondarySQLConnObj.Version.Build
                $secondarySQLEdition = $secondarySQLConnObj.EngineEdition
                if($secondarySQLConnObj.EngineEdition -ne $primSQLEdition){
                    Write-Host "Mismatch in Replica Editions Found. AlwaysON configuration isn't possible."
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } elseif((($secondaryMajorVersion -eq 11) -or ($secondaryMajorVersion -eq 12)) -and ($secondarySQLEdition -notlike "*Enterprise*")){
                    Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } elseif (($secondaryMajorVersion -ge 13) -and (($secondarySQLEdition -like "*Enterprise*") -or (($secondarySQLEdition -like "*Standard*") -and ($secondarySQLVersionBuild -lt 4000)))){
                    Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } 
            } else {
                $SecondaryInsName = "MSSQLSERVER"
                $secondarySQLConnObj = Connect-SQLInstance -Computer $Replica -SQLInstanceName $SecondaryInsName
                if($secondarySQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $Replica"
                }
                $secondaryMajorVersion = $secondarySQLConnObj.Version.Major
                $secondarySQLVersionBuild = $secondarySQLConnObj.Version.Build
                $secondarySQLEdition = $secondarySQLConnObj.EngineEdition
                if($secondarySQLConnObj.EngineEdition -ne $primSQLEdition){
                    Write-Host "Mismatch in Replica Editions Found. AlwaysON configuration isn't possible."
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } elseif((($secondaryMajorVersion -eq 11) -or ($secondaryMajorVersion -eq 12)) -and ($secondarySQLEdition -notlike "*Enterprise*")){
                    Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } elseif (($secondaryMajorVersion -ge 13) -and (($secondarySQLEdition -like "*Enterprise*") -or (($secondarySQLEdition -like "*Standard*") -and ($secondarySQLVersionBuild -lt 4000)))){
                    Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                    return New-Object PSObject -Property @{
                        Status="Failed"
                    }
                } 
            }
        }
        Write-Host "SQL Server editions of the replica are comaptible to host Availability Groups"
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } Catch {
        $chkexception = $_.Exception.Message
        Write-Host "Error Checking Replica Edition matching due to the exception: $chkexception"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}

#Function to validate and create Endpoints
Function Check-Endpoints{
    Param(
        [String] $PrimaryReplica,
        [String] $SecondaryReplica
    )

    try{
        $PrimaryNode = Invoke-Sqlcmd -ServerInstance "$primaryReplica" -Database "Master" -Query "select @@SERVERNAME as HOSTNAME" -ErrorAction Stop
    
        $SecondaryReplicas = $SecondaryReplica.Split(",")

        if($PrimaryReplica -eq $PrimaryNode.Hostname){
            $SQLConnObj = Connect-SQLInstance -Computer $PrimaryNode.Hostname -SQLInstanceName "MSSQLSERVER"
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $PrimaryReplica"
            }
        } ELSE {
            $PrimInsName = $PrimaryReplica.split("\")
            $SQLConnObj = Connect-SQLInstance -Computer $PrimaryNode.Hostname -SQLInstanceName $PrimInsName[1]
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $PrimaryReplica"
            }
        }

        if($SQLConnObj.Endpoints.Name -contains "hadr_endpoint"){
            $endpointobject = $SQLConnObj.Endpoints["hadr_endpoint"]
            if($endpointobject.endpointtype -eq "DatabaseMirroring"){
                if($endpointobject.Protocol.Tcp.ListenerPort -eq 5022){
                    if($endpointobject.Endpointstate -ne "Started"){
                        $endpointobject.Start()
                    } else {
                        Write-Host "Endpoint is already Started. No action needed."
                    }
                } else {
                    $endpointobject.Protocol.Tcp.ListenerPort = 5022
                }
            }
        } else {
            $EndpointName = "hadr_endpoint"
            $IpAddress = '0.0.0.0'
            $Port = 5022
            $endpointObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Endpoint -ArgumentList $SQLConnObj, $EndpointName
            $endpointObject.EndpointType = [Microsoft.SqlServer.Management.Smo.EndpointType]::DatabaseMirroring
            $endpointObject.ProtocolType = [Microsoft.SqlServer.Management.Smo.ProtocolType]::Tcp
            $endpointObject.Protocol.Tcp.ListenerPort = $Port
            $endpointObject.Protocol.Tcp.ListenerIPAddress = $IpAddress
            $endpointObject.Payload.DatabaseMirroring.ServerMirroringRole = [Microsoft.SqlServer.Management.Smo.ServerMirroringRole]::All
            $endpointObject.Payload.DatabaseMirroring.EndpointEncryption = [Microsoft.SqlServer.Management.Smo.EndpointEncryption]::Required
            $endpointObject.Payload.DatabaseMirroring.EndpointEncryptionAlgorithm = [Microsoft.SqlServer.Management.Smo.EndpointEncryptionAlgorithm]::Aes
            $endpointObject.Create()
            $endpointObject.Start()
        }


        foreach($Replica in $SecondaryReplica){
            if($Replica -like "*\*"){
                $SecondaryInsName = $Replica.Split("\")
                $secondarySQLConnObj = Connect-SQLInstance -Computer $SecondaryInsName[0] -SQLInstanceName $SecondaryInsName[1]
                if($secondarySQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $Replica"
                }
                
                if($secondarySQLConnObj.Endpoints.Name -contains "hadr_endpoint"){
                    $endpointobject = $secondarySQLConnObj.Endpoints["hadr_endpoint"]
                    if($endpointobject.endpointtype -eq "DatabaseMirroring"){
                        if($endpointobject.Protocol.Tcp.ListenerPort -eq 5022){
                            if($endpointobject.Endpointstate -ne "Started"){
                                $endpointobject.Start()
                            } else {
                                Write-Host "Endpoint is already Started on secondary replica $Replica. No action needed."
                            }
                        } else {
                            $endpointobject.Protocol.Tcp.ListenerPort = 5022
                        }
                    }
                } else {
                        $EndpointName = "hadr_endpoint"
                        $IpAddress = '0.0.0.0'
                        $Port = 5022
                        $endpointObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Endpoint -ArgumentList $secondarySQLConnObj, $EndpointName
                        $endpointObject.EndpointType = [Microsoft.SqlServer.Management.Smo.EndpointType]::DatabaseMirroring
                        $endpointObject.ProtocolType = [Microsoft.SqlServer.Management.Smo.ProtocolType]::Tcp
                        $endpointObject.Protocol.Tcp.ListenerPort = $Port
                        $endpointObject.Protocol.Tcp.ListenerIPAddress = $IpAddress
                        $endpointObject.Payload.DatabaseMirroring.ServerMirroringRole = [Microsoft.SqlServer.Management.Smo.ServerMirroringRole]::All
                        $endpointObject.Payload.DatabaseMirroring.EndpointEncryption = [Microsoft.SqlServer.Management.Smo.EndpointEncryption]::Required
                        $endpointObject.Payload.DatabaseMirroring.EndpointEncryptionAlgorithm = [Microsoft.SqlServer.Management.Smo.EndpointEncryptionAlgorithm]::Aes
                        $endpointObject.Create()
                        $endpointObject.Start()
                }
            } else {
                $SecondaryInsName = "MSSQLSERVER"
                $secondarySQLConnObj = Connect-SQLInstance -Computer $Replica -SQLInstanceName $SecondaryInsName
                if($secondarySQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $Replica"
                }
                if($secondarySQLConnObj.Endpoints.Name -contains "hadr_endpoint"){
                    $endpointobject = $secondarySQLConnObj.Endpoints["hadr_endpoint"]
                    if($endpointobject.endpointtype -eq "DatabaseMirroring"){
                        if($endpointobject.Protocol.Tcp.ListenerPort -eq 5022){
                            if($endpointobject.Endpointstate -ne "Started"){
                                $endpointobject.Start()
                            } else {
                                Write-Host "Endpoint is already Started on secondary replica $Replica. No action needed."
                            }
                        } else {
                            $endpointobject.Protocol.Tcp.ListenerPort = 5022
                        }
                    }
                } else {
                        $EndpointName = "hadr_endpoint"
                        $IpAddress = '0.0.0.0'
                        $Port = 5022
                        $endpointObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Endpoint -ArgumentList $secondarySQLConnObj, $EndpointName
                        $endpointObject.EndpointType = [Microsoft.SqlServer.Management.Smo.EndpointType]::DatabaseMirroring
                        $endpointObject.ProtocolType = [Microsoft.SqlServer.Management.Smo.ProtocolType]::Tcp
                        $endpointObject.Protocol.Tcp.ListenerPort = $Port
                        $endpointObject.Protocol.Tcp.ListenerIPAddress = $IpAddress
                        $endpointObject.Payload.DatabaseMirroring.ServerMirroringRole = [Microsoft.SqlServer.Management.Smo.ServerMirroringRole]::All
                        $endpointObject.Payload.DatabaseMirroring.EndpointEncryption = [Microsoft.SqlServer.Management.Smo.EndpointEncryption]::Required
                        $endpointObject.Payload.DatabaseMirroring.EndpointEncryptionAlgorithm = [Microsoft.SqlServer.Management.Smo.EndpointEncryptionAlgorithm]::Aes
                        $endpointObject.Create()
                        $endpointObject.Start()
                }
            }
        }
        Write-Host "Endpoints of the replicas are ready."
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } Catch {
        $chkexception = $_.Exception.Message
        Write-Host "Error Checking Endpoints due to the exception: $chkexception"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}

#Function to Share the Backup Directory
Function shareDIR{
    param(
        [String] $directory,
        [String] $ShareName,
        [String] $account
    )
    try{
        if(!(Get-SMBShare -Name $ShareName -ea 0))
        {
            New-SmbShare -Name $ShareName -Path $directory -FullAccess $account -ErrorAction silentlyContinue -ErrorVariable ShrErr | Out-Null
        }
        else
        {
            Grant-SmbShareAccess -Name $ShareName -AccountName $account -AccessRight Full -Force | Out-Null
        }

        If($ShrErr.count -ne 0)            
        {      
            $SHRError = $ShrErr[0].Exception.Message
            Write-Host "Error Creating Share due to an exception: $SHRError"
            return New-Object PSObject -Property @{
                Status="Failed"
            } 
        }
        return New-Object PSObject -Property @{
            Status="Success"
        }
    } Catch
	{
        $catcherror= $_.Exception.Message
        Write-Host "Error with Share due to an exception: $catcherror"				
		return New-Object PSObject -Property @{
			Status="Failed"
		}
	}
}

#Function to Backup the Databases
FUNCTION BACKUPDBS{
    Param(
        [STRING] $INSTANCE,
        [STRING] $DB_NAME
    )
    try {
        IF($INSTANCE -like "*\*"){
            $SQLINSTANCE = $INSTANCE.Split("\")
            $NODE = $SQLINSTANCE[0]
            $INS = $SQLINSTANCE[1]
            $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName $INS
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $INSTANCE"
            }
        } ELSE {
            $NODE = $INSTANCE
            $INS = "DEFAULT"
            $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName "MSSQLSERVER"
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $INSTANCE"
            }
        }

        $BKPDIR = $SQLConnObj.BackupDirectory
        $SQLConnobj.Databases.Name.Contains($DB_NAME)
        if($SQLConnobj.Databases.Name.Contains($DB_NAME)){
            $db = $SQLConnObj.Databases | Where-Object {$_.Name -eq $DB_Name}
            Write-Host $db.RecoveryModel
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
                Write-Host "Backup of the database $DB_NAME successful"
                return New-Object PSObject -Property @{
                    Status="Success"
                    BackupDirectory = $ALWAYSONBACKUPLOC
                }
            } else {
                Throw "Requested Database is in Simple Recovery model"
            }
        } else {
            Throw "Requested Database isn't present in the instance"
        }
    } catch {
        $EXCEPTION = $_.EXCEPTION.Message
        WRITE-HOST "Backup failed for the database $DB_NAME due to the exception: $EXCEPTION"
        return New-Object PSObject -Property @{
            Status="Failed"
        } 
    }
}

#Function to Restore the databases to Secondary Replicas
Function RestoreDB{
    Param(
        [string] $Instance,
        [string] $dbname,
        [String] $backuplocation
    )
    try{
        IF($Instance -like "*\*"){
            $SQLINSTANCE = $Instance.Split("\")
            $NODE = $SQLINSTANCE[0]
            $INS = $SQLINSTANCE[1]
            $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName $INS
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $Instance"
            }
        } ELSE {
            $NODE = $Instance
            $INS = "DEFAULT"
            $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName "MSSQLSERVER"
            if($SQLConnObj.Status -eq "Failed"){
                Throw "Cannot Connect to SQL Instace $Instance"
            }
        }
        Push-Location
        SET-LOCATION "SQLSERVER:\SQL\$NODE\$INS"
        Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.bak" -NoRecovery -ErrorVariable restorerr
        if($restorerr.count -gt 0){
            Write-Host "Restore failed due to error: $restorerr"
            return New-Object PSObject -Property @{
                Status="Failed"
            } 
        }
        Restore-SqlDatabase -Database "$dbname" -BackupFile "$backuplocation\$dbname.trn" -RestoreAction "Log" -NoRecovery -ErrorVariable logrestorerr
        if($logrestorerr.count -gt 0){
            Write-Host "Log Restore failed due to error: $logrestorerr"
            return New-Object PSObject -Property @{
                Status="Failed"
            } 
        }
        Pop-Location
        Write-Host "Database $dbname is restored successfully on secondary replica $Instance"
        return New-Object PSObject -Property @{
            Status="Success"
        } 
    } catch{
        $EXCEPTION = $_.EXCEPTION
        WRITE-HOST "Restore failed for the database $DB_NAME due to the exception: $EXCEPTION"
        return New-Object PSObject -Property @{
            Status="Failed"
        } 
    }    
}

#Function to Configure AlwaysON
function Start-AlwaysON {
    Param(
        [String] $PrimaryReplica,
        [String] $SecondaryReplica, 
        [String] $DB_Names, 
        [String] $AGName
    )
    try{
    #Connection to Primary
    IF($PrimaryReplica -like "*\*"){
        $SQLINSTANCE = $PrimaryReplica.Split("\")
        $NODE = $SQLINSTANCE[0]
        $INS = $SQLINSTANCE[1]
        $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName $INS
        if($SQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $PrimaryReplica"
        }
    } ELSE {
        $NODE = $PrimaryReplica
        $INS = "DEFAULT"
        $SQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName "MSSQLSERVER"
        if($SQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $PrimaryReplica"
        }
    }

    $PrimaryReplicaIndi = @()
    $PrimaryFQDN = [System.Net.Dns]::GetHostByName(($NODE)) | Select-Object Hostname
	$primfqdn = $PrimaryFQDN.Hostname
    $primEndpoint = "TCP://"+$primfqdn+":5022"
    
    $PrimaryReplicaIndi = New-SqlAvailabilityReplica -Name $PrimaryReplica -EndpointUrl $primEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" -AsTemplate -Version ($SQLConnObj.Version)
    #Join-SqlAvailabilityGroup -Name $AGName -InputObject $PrimaryReplica
    #Push-Location
    $Databases = @()
    $SecondaryReplicaIndi = @()
    
    #Connection to Secondary Replica
    if($SecondaryReplica -like "*\*"){
        $SecondaryInsName = $SecondaryReplica.Split("\")
        $secondaryReplicaNode = $SecondaryInsName[0]
        $secondaryReplicaIns = $SecondaryInsName[1]
        $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName $secondaryReplicaIns
        if($secondarySQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $SecondaryReplica"
        }
        $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
    } else {
        $secondaryReplicaNode = $SecondaryReplica
        $secondaryReplicaIns = "DEFAULT"
        $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName 'MSSQLSERVER'
        if($secondarySQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $SecondaryReplica"
        }
        $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
    }
    #SET-LOCATION "SQLSERVER:\SQL\$secondaryReplicaNode\$secondaryReplicaIns"
	$SecFQDN = $SecondaryFQDN.Hostname
	$secEndpoint = "TCP://"+$SecFQDN+":5022"
    $SecondaryReplicaIndi = New-SqlAvailabilityReplica -Name $SecondaryReplica -EndpointUrl $secEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" -AsTemplate -Version ($secondarySQLConnObj.Version)
    foreach($db in $DB_Names){
        $datab = $secondarySQLConnObj.Databases | Where-Object {$_.Name -eq $db}
        if($datab.Status -eq "Restoring"){
            $Databases += $db
        } else {
            Write-Host "Database isn't initilised. Please restore the database and join the database to Availability Group"
        }
    }
    New-SqlAvailabilityGroup -InputObject $PrimaryReplica -Name $AGName -AvailabilityReplica ($PrimaryReplicaIndi, $SecondaryReplicaIndi) -Database $Databases
    Join-SqlAvailabilityGroup -Name $AGName -InputObject $SecondaryReplica

    $SecondaryAGobject = $secondarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
    Write-Host $SecondaryAGobject
    foreach($db in $DB_Names){
        Add-SqlAvailabilityDatabase -InputObject $SecondaryAGobject -Database "$db"
    }

    #Pop-Location
    Write-Host "AlwaysON configuration Successful"
    return New-Object PSObject -Property @{
        Status="Success"
    } 
    } Catch {
        $EXCEPTION = $_.EXCEPTION
        WRITE-HOST "Starting AlwaysON failed for the database $DB_NAME due to the exception: $EXCEPTION"
        return New-Object PSObject -Property @{
            Status="Failed"
        }
    }
}

#Start-AlwaysON "ORF-SQL14-01" "ORF-SQL14-02" "AdventureWorks2016" "ADVWRKS"

#***************************************************************************************************************************************************#
#                                                                MAIN CODE                                                                          #
#***************************************************************************************************************************************************#
$PrimaryReplicaName = "ORF-SQL14-01"
$SecondaryReplicaNames = "ORF-SQL14-02"
$DB_NAMES = "NUM20"
$AvailabilityGroupName = "Infiniti"
#$MODE 

#Load SQLPS Module
$SQLPSSTATUS = Set-SQLPS
IF($SQLPSTATUS.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR importing SQLPS module" -ForegroundColor Red
    EXIT
}

#Check Replica in the Cluster
$clustercheckobj = @{
    PrimaryReplica = $PrimaryReplicaName
    SecondaryReplica = $SecondaryReplicaNames
}
$replicaclusterstatus = Check-ClusterStatus @clustercheckobj
if($replicaclusterstatus.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR checking Node Configuration" -ForegroundColor Red
    EXIT
}

#Check Instances are ready to host AlwaysON
$PrimAlwaysONFeatureStatus = Set-AlwaysON_Foundation $PrimaryReplicaName
if($PrimAlwaysONFeatureStatus.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR checking/enabling AlwaysON feature on Primary Replcia $PrimaryReplicaName" -ForegroundColor Red
    EXIT
}

foreach($Replica in $SecondaryReplicaNames){
    $SecondaryAlwaysONFeatureStatus = Set-AlwaysON_Foundation $Replica
    if($SecondaryAlwaysONFeatureStatus.STATUS -eq "FAILED"){
        WRITE-HOST "ERROR checking/enabling AlwaysON feature on Secondary Replica $Replica" -ForegroundColor Red
        EXIT
    }
}

#Validate Service Accounts 
$Replicas = $SecondaryReplicaNames.Split(",")
if($PrimaryReplicaName -like "*\*"){
    $srvHostInst = $PrimaryReplicaName.Split("\")
    $srvHost = $srvHostInst[0]
    $srvInst = $srvHostInst[1]
    $Instance = "MSSQL$"+$srvInst
    $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
} else {
    $srvHost = $PrimaryReplicaName
    $Instance = "MSSQLSERVER"
    $ServiceAcct = Get-WmiObject Win32_Service -ComputerName $srvHost | Where-Object {$_.Name -eq $Instance}
}
$ServiceAcct.StartName
foreach($Replica in $Replicas){
    $svcacctobj = @{
        Replica = $Replica
        ServiceAcct = $ServiceAcct.StartName
    }
    $svcacctstatus = Check-ReplicaServiceAccounts @svcacctobj

    if($svcacctstatus.STATUS -eq "FAILED"){
        WRITE-HOST "ERROR validating Service Account Configuration on the Replica $Replica" -ForegroundColor Red
        EXIT
    }
}

#SQL Instance Edition Validation
$replicaeditioncheckobj = @{
    PrimaryReplica = $PrimaryReplicaName
    SecondaryReplica = $SecondaryReplicaNames
}
$replicaeditioncheckstatus = Check-ReplicaEditions @replicaeditioncheckobj
if($replicaeditioncheckstatus.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR validating Editions on the Replica $Replica" -ForegroundColor Red
    EXIT
}

#Endpoint Validation
$EndpointCheckObj = @{
    PrimaryReplica = $PrimaryReplicaName
    SecondaryReplica = $SecondaryReplicaNames
}
$EndpointCheckStatus = Check-Endpoints @EndpointCheckObj
if($EndpointCheckStatus.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR validating Editions on the Replica $Replica" -ForegroundColor Red
    EXIT
}

#Initiate AlwaysON Configuration
#Backup the Databases
$BackupDBObj = @{
    Instance = $PrimaryReplicaName
    DB_Name = $DB_NAMES
}
$backupstatus = BACKUPDBS @BackupDBObj
if($backupstatus.STATUS -eq "FAILED"){
    WRITE-HOST "ERROR Backing up the databases on Primary Replica. Please check the error above." -ForegroundColor Red
    EXIT
} else {
    $BkpShareObj = @{
        Directory = $backupstatus.BackupDirectory
        ShareName = "AGBackupShare"
        Account = $ServiceAcct.StartName
    }
    $BkpShareStatus = shareDIR @BkpShareObj
    If($BkpShareStatus.Status -eq "FAILED"){
        WRITE-HOST "ERROR sharing Backup Directory on Primary Replica." -ForegroundColor Red
        EXIT
    }
}
$BackupShare = "\\$srvHost\AGBackupShare"

#Restore the databases to the Secondary Replica
foreach($Replica in $SecondaryReplicaNames){
    foreach($db in $DB_NAMES){
        $restoredbobj = @{
            Instance = $Replica
            DBName = $db
            BackupLocation = $BackupShare
        }
        $RestoreDBStatus = RestoreDB @restoredbobj
        if($RestoreDBStatus.Status -eq "Failed"){
            WRITE-HOST "ERROR Restorig the database $db on the Replica $Replca." -ForegroundColor Red
            EXIT
        }
    }
}

#Start AlwaysON
foreach($Replica in $SecondaryReplicaNames){
    $AlwaysONObj = @{
        PrimaryReplica = $PrimaryReplicaName
        SecondaryReplica = $Replica
        DB_Names = $DB_NAMES
        AGName = $AvailabilityGroupName
    }
    $AlwaysONStatus = Start-AlwaysON @AlwaysONObj
    if($AlwaysONStatus.Status -eq "Failed"){
        WRITE-HOST "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and Secondary Replica $Replca." -ForegroundColor Red
        EXIT
    }
}
