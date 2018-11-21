<#
    .SYNOPSIS
    Use this script to Configure AlwaysON availability group or add databases to already existing availability group. 

    .DESCRIPTION
    One can configure alwayson on a new built server. It has following features to help create availability group. 
    Features: 
    1. Verifies cluster is setup to configure alwaysON
    2. Enables AlwaysON feature if not already enabled
    3. Verifies all the nodes' SQL Server service accounts to be same as that of primary
    4. Validates appropriate edition requirement to configure AlwaysON
    5. Configures new AlwaysON availability groups for Enterprise Edition upto 100 databases in each group
    6. Cofigures new basic availability group on standard edition
    7. The replicas are configured as automatic failover modes
    8. One can add databases to already existing availability group
    9. Has auto rollover feature while adding databases to availability group by creating a new availability group with name AvailabilityGroup[number]
        if a default AG has utmost 100 databases
    
        Limitations:
            1. A feature should be added:Database that needs to be added should already have had a full backup
            2. A feature should be added:No check if database is already part of an AG.

        Assumptions:
            1. Drive structure are similar in all replica
            2. Instance Names are either default or named instances
            3. AG are configured with Auto Failover Capability
    .EXAMPLE
        -CREATE NEW AVAILABILITY GROUP -Full usage of parameters
        .\SetupAG.ps1 -PrimaryReplicaName "ORF-SQL14-20" -SecondaryReplicaNames "ORF-SQL14-21,ORF-SQL14-22" -DB_NAMES "NUM104,NUM105,NUM106" -AvailabilityGroupName "AvailabilityGroup"
    
        -CREATE NEW AVAILABILITY GROUP by Specifying only Primary Replica and DB Names. 
        Adds the requested databases to already existing availability group if it has lesser than 100 databases and can fit all requested databases.
        .\SetupAG.ps1 -PrimaryReplicaName "ORF-SQL14-20" -DB_NAMES "NUM104,NUM105,NUM106" 

        -One can specify AG name to add the databases into. 
        .\SetupAG.ps1 -PrimaryReplicaName "ORF-SQL14-20" -DB_NAMES "NUM104,NUM105,NUM106" -AvailabilityGroupName "AvailabilityGroup2" 
        
        -Create Availability Group with default name, AvailabilityGroup[number]. If there are no existing AGs, then this script creates AG with name AvailabilityGroup1
        .\SetupAG.ps1 -PrimaryReplicaName "ORF-SQL14-20" -SecondaryReplicaNames "ORF-SQL14-21,ORF-SQL14-22" -DB_NAMES "NUM104,NUM105,NUM106"

    .PARAMETER PrimaryReplicaName
    The Primary Replica hosting SQL Instance Name. This field is mandatory. 

    .PARAMETER SecondaryReplicaNames
    The Secondary Replica hosting SQL Instance Names in camma seperated string without space

    .PARAMETER DB_NAMES
    The comma seperated string of database names. This field is mandatory. Ensure all Databases have been backed up atleast once. 

    .PARAMETER AvailabilityGroupName
    The Availability Group Name of preference. If not specified, default name is given. 
#>

[cmdletbinding()]
Param(
    [Parameter(mandatory=$true)]
    [String]$PrimaryReplicaName = $env:COMPUTERNAME,
    [String]$SecondaryReplicaNames,
    [Parameter(mandatory=$true)]
    [String]$DB_NAMES,
    [String]$AvailabilityGroupName
    )
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

            if($PrimaryNode -like "*\*"){
                $NodeIns = $PrimaryNode.Split("\")
                $PrimaryNode = $NodeIns[0]
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

                if($Node -like "*\*"){
                    $NodeIns = $Node.Split("\")
                    $Node = $NodeIns[0]
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

            if($PrimaryNode -like "*\*"){
                $NodeIns = $PrimaryNode.Split("\")
                $PrimaryNode = $NodeIns[0]
            }

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
        write-host "$primMajorVersion, $primSQLVersionBuild, $primSQLEdition"
            if((($primMajorVersion -eq 11) -or ($primMajorVersion -eq 12)) -and ($primSQLEdition -notlike "*Enterprise*")){
                Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            } elseif (($primMajorVersion -ge 13) -and (($primSQLEdition -notlike "*Enterprise*") -or (($primSQLEdition -like "*Standard*") -and ($primSQLVersionBuild -lt 4000)))){
                Write-Host "This Edition of SQL Server doesn't support AlwaysON"
                return New-Object PSObject -Property @{
                    Status="Failed"
                }
            } 
            foreach($Replica in $SecondaryReplicas){
            Write-Host "$Replica"
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
                    } elseif (($secondaryMajorVersion -ge 13) -and (($secondarySQLEdition -notlike "*Enterprise*") -or (($secondarySQLEdition -like "*Standard*") -and ($secondarySQLVersionBuild -lt 4000)))){
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
            Write-Host "$secondaryMajorVersion, $secondarySQLVersionBuild, $secondarySQLEdition"
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
                    } elseif (($secondaryMajorVersion -ge 13) -and (($secondarySQLEdition -notlike "*Enterprise*") -or (($secondarySQLEdition -like "*Standard*") -and ($secondarySQLVersionBuild -lt 4000)))){
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

            if($PrimaryNode -like "*\*"){
                $NodeIns = $PrimaryNode.Split("\")
                $PrimaryNode = $NodeIns[0]
            }
        
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
    
    
            foreach($Replica in $SecondaryReplicas){
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
            [STRING] $DB_NAMES
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
            $DB_NAMESS = $DB_NAMES.Split(",")
            foreach($DB_NAME in $DB_NAMESS){
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
                    } else {
                        Throw "Requested Database is in Simple Recovery model"
                    }
                } else {
                    Throw "Requested Database isn't present in the instance"
                }
            }
            return New-Object PSObject -Property @{
                Status="Success"
                BackupDirectory = $ALWAYSONBACKUPLOC
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
        
        #Validate Service Accounts 
        $Replicas = $SecondaryReplica.Split(",")
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
        $ServiceAcct.StartName
        foreach($Replica in $Replicas){
            $svcacctobj = @{
                Replica = $Replica
                ServiceAcct = $ServiceAcct.StartName
                }
            $svcacctstatus = Check-ReplicaServiceAccounts @svcacctobj
            if($svcacctstatus.STATUS -eq "FAILED"){
                Throw "ERROR validating Service Account Configuration on the Replica $Replica"
            }
        }

        #Configure AlwaysON
        $PrimaryReplicaIndi = @()
        $PrimaryFQDN = [System.Net.Dns]::GetHostByName(($NODE)) | Select-Object Hostname
        $primfqdn = $PrimaryFQDN.Hostname
        $primEndpoint = "TCP://"+$primfqdn+":5022"
        $dbnames = $DB_Names.Split(",")
        if(($SQLConnObj.AvailabilityGroups.Name -contains $AGName)){
            Write-Host "AG discovered"
            $agobj = $SQLConnObj.AvailabilityGroups[$AGName]
            $Databases = @()
            $SecondaryReplicas = $secondaryReplica.Split(",")
            #Backup the Databases
            $BackupDBObj = @{
                Instance = $PrimaryReplicaName
                DB_Names = $DB_NAMES
                }
            $backupstatus = BACKUPDBS @BackupDBObj
            if($backupstatus.STATUS -eq "FAILED"){
                Throw "ERROR Backing up the databases on Primary Replica. Please check the error above." 
            } else {
                $BkpShareObj = @{
                    Directory = $backupstatus.BackupDirectory
                    ShareName = "AGBackupShare"
                    Account = $ServiceAcct.StartName
                    }
                $BkpShareStatus = shareDIR @BkpShareObj
                If($BkpShareStatus.Status -eq "FAILED"){
                    Throw "ERROR sharing Backup Directory on Primary Replica."
                }
            }
            $BackupShare = "\\$srvHost\AGBackupShare"

            
            foreach($db in $dbnames){
                Add-SqlAvailabilityDatabase -InputObject $agobj -Database "$db" -ErrorAction Stop
                }
    

            #Connection to Secondary Replica
            $agobj = $SQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
            foreach($replica in $SecondaryReplicas){
                if($replica -like "*\*"){
                    $SecondaryInsName = $replica.Split("\")
                    $secondaryReplicaNode = $SecondaryInsName[0]
                    $secondaryReplicaIns = $SecondaryInsName[1]
                    $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName $secondaryReplicaIns
                    if($secondarySQLConnObj.Status -eq "Failed"){
                        Throw "Cannot Connect to SQL Instace $replica"
                    }
                    $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
                    $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
                } else {
                    $secondaryReplicaNode = $replica
                    $secondaryReplicaIns = "DEFAULT"
                    $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName 'MSSQLSERVER'
                    if($secondarySQLConnObj.Status -eq "Failed"){
                        Throw "Cannot Connect to SQL Instace $replica"
                    }
                    $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
                    $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
                }
    
                #Restore the Secondary Databases
                $DB_NAMESSS = $DB_NAMES.Split(",")
                foreach($db in $DB_NAMESSS){
                    $restoredbobj = @{
                        Instance = $Replica
                        DBName = $db
                        BackupLocation = $BackupShare
                        }
                    $RestoreDBStatus = RestoreDB @restoredbobj
                    if($RestoreDBStatus.Status -eq "Failed"){
                        Throw "ERROR Restorig the database $db on the Replica $Replca."
                    }
                }
                $SecondaryAGobject = $secondarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
                foreach($db in $dbnames){
                    $datab = $secondarySQLConnObj.Databases | Where-Object {$_.Name -eq $db}
                    if($datab.Status -eq "Restoring"){
                        $Databases += $db
                        Add-SqlAvailabilityDatabase -InputObject $SecondaryAGobject -Database "$db"
                    } else {
                        Write-Host "Database $db isn't initilised. Please restore the database and join the database to Availability Group"
                        return New-Object PSObject -Property @{
                        Status="Failed"
                        }
                    }
                }
            }
        } else {
            $PrimaryReplicaIndi = New-SqlAvailabilityReplica -Name $PrimaryReplica -EndpointUrl $primEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" -AsTemplate -Version ($SQLConnObj.Version)
            New-SqlAvailabilityGroup -InputObject $PrimaryReplica -Name $AGName -AvailabilityReplica $PrimaryReplicaIndi -Database $dbnames -ErrorAction Stop
            #Refresh the SQL Primary Connection
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
            Write-Host $SQLConnObj.AvailabilityGroups        
            $Databases = @()
            $SecondaryReplicas = $secondaryReplica.Split(",")
            #Connection to Secondary Replica
            $agobj = $SQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
            foreach($replica in $SecondaryReplicas){
                if($replica -like "*\*"){
                    $SecondaryInsName = $replica.Split("\")
                    $secondaryReplicaNode = $SecondaryInsName[0]
                    $secondaryReplicaIns = $SecondaryInsName[1]
                    $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName $secondaryReplicaIns
                    if($secondarySQLConnObj.Status -eq "Failed"){
                        Throw "Cannot Connect to SQL Instace $replica"
                    }
                    $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
                    $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
                } else {
                    $secondaryReplicaNode = $replica
                    $secondaryReplicaIns = "DEFAULT"
                    $secondarySQLConnObj = Connect-SQLInstance -Computer $secondaryReplicaNode -SQLInstanceName 'MSSQLSERVER'
                    if($secondarySQLConnObj.Status -eq "Failed"){
                        Throw "Cannot Connect to SQL Instace $replica"
                    }
                    $secPath = "SQLSERVER:\SQL\$replica\$secondaryReplicaIns"
                    $SecondaryFQDN = [System.Net.Dns]::GetHostByName(($secondaryReplicaNode)) | Select-Object Hostname
                }
                $SecFQDN = $SecondaryFQDN.Hostname
                $secEndpoint = "TCP://"+$SecFQDN+":5022"
                
                New-SqlAvailabilityReplica -Name $replica -InputObject $agobj -EndpointUrl $secEndpoint -FailoverMode "Automatic" -AvailabilityMode "SynchronousCommit" 
                Join-SqlAvailabilityGroup -Name $AGName -InputObject $secondarySQLConnObj -ErrorAction Stop
                $SecondaryAGobject = $secondarySQLConnObj.AvailabilityGroups | Where-Object {$_.Name -eq $AGName}
                foreach($db in $dbnames){
                    $datab = $secondarySQLConnObj.Databases | Where-Object {$_.Name -eq $db}
                    if($datab.Status -eq "Restoring"){
                        $Databases += $db
                        Add-SqlAvailabilityDatabase -InputObject $SecondaryAGobject -Database "$db"
                    } else {
                        Write-Host "Database $db isn't initilised. Please restore the database and join the database to Availability Group"
                        return New-Object PSObject -Property @{
                        Status="Failed"
                        }
                    }
                }
            }
        }
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

    #Function to Setup Basic Availability Group
    function Start-BasicAlwaysON {
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
    
    #Function to Setup a New AG
    Function Setup-NewAG{
        Param(
            [String] $PrimaryReplicaName,
            [String] $SecondaryReplicaNames, 
            [String] $DB_Names, 
            [String] $AvailabilityGroupName
        )
        try{
            IF($PrimaryReplicaName -like "*\*"){
                $SQLINSTANCE = $PrimaryReplicaName.Split("\")
                $NODE = $SQLINSTANCE[0]
                $INS = $SQLINSTANCE[1]
                $PrimaryReplicaSQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName $INS
                if($PrimaryReplicaSQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $PrimaryReplicaName"
                }
            } ELSE {
                $NODE = $PrimaryReplicaName
                $INS = "DEFAULT"
                $PrimaryReplicaSQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName "MSSQLSERVER"
                if($PrimaryReplicaSQLConnObj.Status -eq "Failed"){
                    Throw "Cannot Connect to SQL Instace $PrimaryReplicaName"
                }   
            }
        $primEdition = $PrimaryReplicaSQLConnObj.EngineEdition
        #Check Replica in the Cluster
        $clustercheckobj = @{
            PrimaryReplica = $PrimaryReplicaName
            SecondaryReplica = $SecondaryReplicaNames
            }
        $replicaclusterstatus = Check-ClusterStatus @clustercheckobj
        if($replicaclusterstatus.STATUS -eq "FAILED"){
            Throw "ERROR checking Node Configuration"
        }
    
        #Check Instances are ready to host AlwaysON
        $PrimAlwaysONFeatureStatus = Set-AlwaysON_Foundation $PrimaryReplicaName
        if($PrimAlwaysONFeatureStatus.STATUS -eq "FAILED"){
            Throw "ERROR checking/enabling AlwaysON feature on Primary Replcia $PrimaryReplicaName"
        }
        $Replicas = $SecondaryReplicaNames.Split(",")
        foreach($Replica in $Replicas){
            $SecondaryAlwaysONFeatureStatus = Set-AlwaysON_Foundation $Replica
            if($SecondaryAlwaysONFeatureStatus.STATUS -eq "FAILED"){
                Throw "ERROR checking/enabling AlwaysON feature on Secondary Replica $Replica"
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
                Throw "ERROR validating Service Account Configuration on the Replica $Replica"
            }
        }
    
        #SQL Instance Edition Validation
        $replicaeditioncheckobj = @{
                PrimaryReplica = $PrimaryReplicaName
                SecondaryReplica = $SecondaryReplicaNames
            }
        $replicaeditioncheckstatus = Check-ReplicaEditions @replicaeditioncheckobj
        if($replicaeditioncheckstatus.STATUS -eq "FAILED"){
                Throw "ERROR validating Editions on the Replicas"
        }
    
        #Endpoint Validation
        $EndpointCheckObj = @{
            PrimaryReplica = $PrimaryReplicaName
            SecondaryReplica = $SecondaryReplicaNames
            }
        $EndpointCheckStatus = Check-Endpoints @EndpointCheckObj
        if($EndpointCheckStatus.STATUS -eq "FAILED"){
            Throw "ERROR validating Endpoints on the Replica"
        }
    
        #Initiate AlwaysON Configuration
        #Backup the Databases
        $BackupDBObj = @{
            Instance = $PrimaryReplicaName
            DB_Names = $DB_NAMES
            }
        $backupstatus = BACKUPDBS @BackupDBObj
        if($backupstatus.STATUS -eq "FAILED"){
            Throw "ERROR Backing up the databases on Primary Replica. Please check the error above."
        } else {
            $BkpShareObj = @{
                Directory = $backupstatus.BackupDirectory
                ShareName = "AGBackupShare"
                Account = $ServiceAcct.StartName
                }
            $BkpShareStatus = shareDIR @BkpShareObj
            If($BkpShareStatus.Status -eq "FAILED"){
                Throw "ERROR sharing Backup Directory on Primary Replica."
            }
        }
        $BackupShare = "\\$srvHost\AGBackupShare"
    
        #Restore the databases to the Secondary Replica
        foreach($Replica in $Replicas){
            $DB_NAMESSS = $DB_NAMES.Split(",")
            foreach($db in $DB_NAMESSS){
                $restoredbobj = @{
                    Instance = $Replica
                    DBName = $db
                    BackupLocation = $BackupShare
                }
                $RestoreDBStatus = RestoreDB @restoredbobj
                if($RestoreDBStatus.Status -eq "Failed"){
                    Throw "ERROR Restorig the database $db on the Replica $Replca."
                }
            }
        }
    
        #Start AlwaysON
        $AlwaysONObj = @{
            PrimaryReplica = $PrimaryReplicaName
            SecondaryReplica = $SecondaryReplicaNames
            DB_Names = $DB_NAMES
            AGName = $AvailabilityGroupName
            }
        if($primEdition -like "*enterprise*"){
            $AlwaysONStatus = Start-AlwaysON @AlwaysONObj
        } elseif($primEdition -like "*standard*"){
            $AlwaysONStatus = Start-BasicAlwaysON @AlwaysONObj
        } else {
            Throw "Edition doesn't support to host AlwaysON"
        }
        if($AlwaysONStatus.Status -eq "Failed"){
            Throw "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames."
        }
        return New-Object PSObject -Property @{
            Status="Success"
        }
        } Catch {
            $EXCEPTION = $_.EXCEPTION
            WRITE-HOST "AlwaysON Configuration failed due to the exception: $EXCEPTION" -BackgroundColor Red
            return New-Object PSObject -Property @{
                Status="Failed"
            }
        } 
    }
    
    #***************************************************************************************************************************************************#
    #                                                                MAIN CODE                                                                          #
    #***************************************************************************************************************************************************#
    
    #Load SQLPS Module
    $SQLPSTATUS = Set-SQLPS
    IF($SQLPSTATUS.STATUS -eq "FAILED"){
        WRITE-HOST "ERROR importing SQLPS module" -ForegroundColor Red
        EXIT
    }
    
    #Create Availability Groups
    IF($PrimaryReplicaName -like "*\*"){
        $SQLINSTANCE = $PrimaryReplicaName.Split("\")
        $NODE = $SQLINSTANCE[0]
        $INS = $SQLINSTANCE[1]
        $PrimarySQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName $INS
        if($PrimarySQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $PrimaryReplicaName"
        }
    } ELSE {
        $NODE = $PrimaryReplicaName
        $INS = "DEFAULT"
        $PrimarySQLConnObj = Connect-SQLInstance -Computer $NODE -SQLInstanceName "MSSQLSERVER"
        if($PrimarySQLConnObj.Status -eq "Failed"){
            Throw "Cannot Connect to SQL Instace $PrimaryReplicaName"
        }   
    }
    $DatabaseList = $DB_NAMES.Split(",")
    $dbreqcount = $DatabaseList.Count
    $success = 0
    $AGCount = $PrimarySQLConnObj.AvailabilityGroups.Name.Count
    if($AvailabilityGroupName -ne ""){
        if(($PrimarySQLConnObj.AvailabilityGroups.Name -contains $AvailabilityGroupName)){
            Write-Host 1
            $currDBcnt = $PrimarySQLConnObj.AvailabilityGroups[$AvailabilityGroupName].AvailabilityDatabases.Count
            if($currDBcnt -gt (100-$dbreqcount)){
                WRITE-HOST "Each Availability Group can host a maximum of 100 databases. Create a new AG." -ForegroundColor Red
                EXIT
            }
            $SecondaryReplicaNames = $PrimarySQLConnObj.AvailabilityGroups["$AvailabilityGroupName"].AvailabilityReplicas.Name | Where-Object {$_ -ne $PrimaryReplicaName}
	    $SecondaryReplicaNames = $SecondaryReplicaNames -replace '\s',','
            $AlwaysONObj = @{
                PrimaryReplica = $PrimaryReplicaName
                SecondaryReplica = $SecondaryReplicaNames
                DB_Names = $DB_NAMES
                AGName = $AvailabilityGroupName
                }
            $AlwaysONStatus = Start-AlwaysON @AlwaysONObj
            if($AlwaysONStatus.Status -eq "Failed"){
                WRITE-HOST "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames" -ForegroundColor Red
                EXIT
            }
            $success = 1
            Exit
        } Else {
            Write-Host 2
            IF($SecondaryReplicaNames -eq ""){
                Write-Host "Specify Secondary Replicas and reissue the command" -BackgroundColor Red
                Exit
            }
            $reqobj = @{
                PrimaryReplicaName = $PrimaryReplicaName
                SecondaryReplicaNames = $SecondaryReplicaNames
                DB_Names = $DB_NAMES
                AvailabilityGroupName = $AvailabilityGroupName
                }
            $newAGstatus = Setup-NewAG @reqobj
            if($newAGstatus.Status -eq "Failed"){
                WRITE-HOST "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames" -ForegroundColor Red
                EXIT
            } Else {
                $success = 1
                WRITE-HOST "Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames created successfully." -ForegroundColor Green
                EXIT
            }
        }
    } else {
        Wrie-te-Host 3
        foreach($AvailabilityGroupName in $PrimarySQLConnObj.AvailabilityGroups.Name){
            $currDBcnt = $PrimarySQLConnObj.AvailabilityGroups[$AvailabilityGroupName].AvailabilityDatabases.Count
            if($currDBcnt -lt (100-$dbreqcount)){
                if(($PrimarySQLConnObj.AvailabilityGroups.Name -contains $AvailabilityGroupName)){
                    $SecondaryReplicaNames = $PrimarySQLConnObj.AvailabilityGroups["$AvailabilityGroupName"].AvailabilityReplicas.Name | Where-Object {$_ -ne $PrimaryReplicaName}
                    $SecondaryReplicaNames = $SecondaryReplicaNames -join ","
                }
                $AlwaysONObj = @{
                    PrimaryReplica = $PrimaryReplicaName
                    SecondaryReplica = $SecondaryReplicaNames
                    DB_Names = $DB_NAMES
                    AGName = $AvailabilityGroupName
                    }
                $AlwaysONStatus = Start-AlwaysON @AlwaysONObj
                if($AlwaysONStatus.Status -eq "Failed"){
                    WRITE-HOST "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames" -ForegroundColor Red
                    EXIT
                }
                $success = 1
                WRITE-HOST "Database/s successfully added to the Availability Group $AvailabilityGroupName" -ForegroundColor Green
                Break
            } Else {
                $remDBcnt = 100-$currDBcnt
                WRITE-HOST "Too many databases requested for AG $AvailabilityGroupName. Can host another $remDBcnt Databases in this AG."
                Continue
            }
        }        
        if($success -eq 0){
            $AvailabilityGroupName = "AvailabilityGroup"+($AGCount+1)
            IF($SecondaryReplicaNames -eq ""){
                Write-Host "Specify Secondary Replicas and reissue the command" -BackgroundColor Red
                Exit
            }
            $reqobj = @{
                PrimaryReplicaName = $PrimaryReplicaName
                SecondaryReplicaNames = $SecondaryReplicaNames
                DB_Names = $DB_NAMES
                AvailabilityGroupName = $AvailabilityGroupName
                }
            $newAGstatus = Setup-NewAG @reqobj
            if($newAGstatus.Status -eq "Failed"){
                WRITE-HOST "ERROR Creating Availability Group between Primary Replica $PrimaryReplicaName and $SecondaryReplicaNames" -ForegroundColor Red
                EXIT
            }
        }
    }

