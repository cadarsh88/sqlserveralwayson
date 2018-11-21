function sync-agentjobs{
[cmdletbinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $true)]
    param (
        [parameter(Mandatory = $true)]
        [String]$SourceServer,
        [String]$SourceReplica,
        [parameter(Mandatory = $true)]
        [String]$DestinationServer,
        [String]$DestinationReplica,        
        [String]$Job,
        [String]$ExcludeJob,
        [switch]$DisableOnSource,
        [switch]$DisableOnDestination,
        [switch]$Force
    )

        begin{

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

#SQL Connection Object
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

    Set-SQLPS

    $srcServer = Connect-SqlInstance -Computer $SourceServer -SqlInstance $SourceReplica
    $destServer = Connect-SqlInstance -Computer $DestinationServer -SqlInstance $DestinationReplica

    Write-Host "Source Instance: "$srcServer.DomainInstanceName
    Write-Host "Destination Instance: "$destServer.DomainInstanceName
    }
    
    process{

    $serverJobs = $srcServer.JobServer.Jobs
    $destJobs = $destServer.JobServer.Jobs

    foreach ($serverJob in $serverJobs) {
        $jobName = $serverJob.name
        $jobId = $serverJob.JobId
        $copyJobStatus = [pscustomobject]@{
            SourceServer      = $srcServer.Name
            DestinationServer = $destServer.Name
            Name              = $jobName
            Type              = "Agent Job"
            Status            = $null
            Notes             = $null
            DateTime          = [DateTime](Get-Date)
        }

        if ($Job -and $jobName -notin $Job -or $jobName -in $ExcludeJob) {
            Write-Host "Job [$jobName] filtered. Skipping."
            continue
        }

        Write-Host "Working on job: $jobName"
        $sql = "SELECT sp.[name] AS MaintenancePlanName
                FROM msdb.dbo.sysmaintplan_plans AS sp
                INNER JOIN msdb.dbo.sysmaintplan_subplans AS sps
                    ON sps.plan_id = sp.id
                WHERE job_id = '$($jobId)'"
        
        $MaintenancePlanNameObj = $srcServer.ConnectionContext.ExecuteWithResults($sql)
        $MaintenancePlanName = $MaintenancePlanNameObj.Tables.MaintenancePlanName
        

        if ($MaintenancePlanName) {
            $copyJobStatus.Status = "Skipped"
            $copyJobStatus.Notes = "Job is associated with maintenance plan"
            Write-Host "Job [$jobName] is associated with Maintenance Plan: $MaintenancePlanName"
            continue
        }

        $dbNames = $serverJob.JobSteps.DatabaseName | Where-Object { $_.Length -gt 0 }
        $missingDb = $dbNames | Where-Object { $destServer.Databases.Name -notcontains $_ }

        if ($missingDb.Count -gt 0 -and $dbNames.Count -gt 0) {
            $missingDb = ($missingDb | Sort-Object | Get-Unique) -join ", "
            $copyJobStatus.Status = "Skipped"
            $copyJobStatus.Notes = "Job is dependent on database: $missingDb"
            Write-Host "Database(s) $missingDb doesn't exist on destination. Skipping job [$jobName]."
            continue
        }

        $missingLogin = $serverJob.OwnerLoginName | Where-Object { $destServer.Logins.Name -notcontains $_ }

        if ($missingLogin.Count -gt 0) {
            if ($force -eq $false) {
                $missingLogin = ($missingLogin | Sort-Object | Get-Unique) -join ", "
                $copyJobStatus.Status = "Skipped"
                $copyJobStatus.Notes = "Job is dependent on login $missingLogin"
                Write-Host "Login(s) $missingLogin doesn't exist on destination. Use -Force to set owner to [sa]. Skipping job [$jobName]."
                continue
            }
        }

        $proxyNames = $serverJob.JobSteps.ProxyName | Where-Object { $_.Length -gt 0 }
        $missingProxy = $proxyNames | Where-Object { $destServer.JobServer.ProxyAccounts.Name -notcontains $_ }

        if ($missingProxy.Count -gt 0 -and $proxyNames.Count -gt 0) {
            $missingProxy = ($missingProxy | Sort-Object | Get-Unique) -join ", "
            $copyJobStatus.Status = "Skipped"
            $copyJobStatus.Notes = "Job is dependent on proxy $($proxyNames[0])"
            Write-Host "Proxy Account(s) $($proxyNames[0]) doesn't exist on destination. Skipping job [$jobName]."
            continue
        }

        $operators = $serverJob.OperatorToEmail, $serverJob.OperatorToNetSend, $serverJob.OperatorToPage | Where-Object { $_.Length -gt 0 }
        $missingOperators = $operators | Where-Object {$destServer.JobServer.Operators.Name -notcontains $_}

        if ($missingOperators.Count -gt 0 -and $operators.Count -gt 0) {
            $missingOperator = ($operators | Sort-Object | Get-Unique) -join ", "
            $copyJobStatus.Status = "Skipped"
            $copyJobStatus.Notes = "Job is dependent on operator $missingOperator"
            Write-Host "Operator(s) $($missingOperator) doesn't exist on destination. Skipping job [$jobName]"
            continue
        }

        if ($destJobs.name -contains $serverJob.name) {
            if ($force -eq $false) {
                $copyJobStatus.Status = "Skipped"
                $copyJobStatus.Notes = "Job already exists on destination"
                Write-Host "Job $jobName exists at destination. Use -Force to drop and migrate."
                continue
            }
            else {
                if ($Pscmdlet.ShouldProcess($destination, "Dropping job $jobName and recreating")) {
                    try {
                        Write-Host "Dropping Job $jobName"
                        $destServer.JobServer.Jobs[$jobName].Drop()
                    }
                    catch {
                        $copyJobStatus.Status = "Failed"
                        $copyJobStatus.Notes = $_.Exception.Message
                        Write-Host "Issue dropping job on Target, JobName: $jobName"
                        Return
                    }
                }
            }
        }

        if ($Pscmdlet.ShouldProcess($destination, "Creating Job $jobName")) {
            try {
                Write-Host "Copying Job $jobName"
                $sql = $serverJob.Script() | Out-String

                if ($missingLogin.Count -gt 0 -and $force) {
                    $saLogin = Get-SqlSaLogin -SqlInstance $destServer
                    $sql = $sql -replace [Regex]::Escape("@owner_login_name=N'$missingLogin'"), [Regex]::Escape("@owner_login_name=N'$saLogin'")
                }

                $destServer.ConnectionContext.ExecuteWithResults($sql)

                $destServer.JobServer.Jobs.Refresh()
            }
            catch {
                $copyJobStatus.Status = "Failed"
                $copyJobStatus.Notes = (($_.Exception.InnerException.InnerException.Innerexception.InnerException).ToString().Split("`n"))[0]
                Write-Host "Issue copying job to Target, Job Name: $jobName"
                Return
            }
        }

        if ($DisableOnDestination) {
            if ($Pscmdlet.ShouldProcess($destination, "Disabling $jobName")) {
                Write-Host "Disabling $jobName on $destination" 
                $destServer.JobServer.Jobs[$serverJob.name].IsEnabled = $False
                $destServer.JobServer.Jobs[$serverJob.name].Alter()
            }
        }

        if ($DisableOnSource) {
            if ($Pscmdlet.ShouldProcess($source, "Disabling $jobName")) {
                Write-Host"Disabling $jobName on $source"
                $serverJob.IsEnabled = $false
                $serverJob.Alter()
            }
        }
        $copyJobStatus.Status = "Successful"
        Write-Host "Copy of the jobs: "$copyJobStatus.Status
    }
    }
    end {
        Write-Host "End of Job Sync"
    }
    }

    sync-agentjobs -SourceServer "ORF-SQL14-20" -DestinationServer "ORF-SQL14-22" 