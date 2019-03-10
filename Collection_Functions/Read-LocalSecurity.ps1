
Function Read-LocalSecurity {
param($SecurityPolicyFile,[switch]$ShowPasswordPolicy,[switch]$ShowLockoutPolicy,[switch]$ShowSecurityOptions,[switch]$ShowUserRightsAssignment)

	# Function taken with thanks from https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
	function Get-IniContent ($filePath)
	{
	    $ini = @{}
	    switch -regex -file $FilePath
	    {
	        "^\[(.+)\]" # Section
	        {
	            $section = $matches[1]
	            $ini[$section] = @{}
	            $CommentCount = 0
	        }
	        "^(;.*)$" # Comment
	        {
	            $value = $matches[1]
	            $CommentCount = $CommentCount + 1
	            $name = “Comment” + $CommentCount
	            $ini[$section][$name] = $value.trim()
	        } 
	        "(.+?)\s*=(.*)" # Key
	        {
	            $name,$value = $matches[1..2]
	            $ini[$section][$name] = $value.trim()
	        }
	    }
	    return $ini
	}

	# Function to resolve SID to username
	Function Get-UserFromSID {
	param($SID)

	    if([string]::IsNullOrEmpty($SID))
	    {
	        return $null
	    }

	    $CleanSID = $SID.Replace('*','').Trim()
	    
	    $Result = foreach($RawSID IN $CleanSID.Split(','))
	    {
	        try
	        {
	            $objSID  = New-Object System.Security.Principal.SecurityIdentifier ($RawSID)
	            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
	            $objUser.Value
	        }
	        catch
	        {
	            # Could not be translated so output SID
	            # This caused when accounts are deleted but policies not cleaned afterwards
	            # or possibly a foreign domain
	            $RawSID
	        }
	    }
	    
	    $Result -join ','

	}

	# Function to create a new security object
	Function New-SecObj {
	Param($SettingType,$Name,$DisplayName,$RawValue,$Value)

	    $Out = '' | Select-Object SettingType, Name, DisplayName, RawValue, Value
	    $Out.SettingType = $SettingType
	    $Out.Name = $Name
	    $Out.DisplayName = $DisplayName
	    $Out.RawValue = $RawValue
	    $Out.Value = $Value
	    $Out

	}

	# If using provided file then ignore export
	if($SecurityPolicyFile){
		# Export the security policy
		$ExportedPolicy = $SecurityPolicyFile
		
		# Temp file flag true
		$TempFileCreated = $false
	}else{
		# Export the security policy
		$ExportedPolicy = (Join-Path $env:TEMP SecurityPolicyExport.inf)

		# Run the export of the security policy
		$null = Invoke-Expression "secedit /export /cfg $ExportedPolicy"
		
		# Temp file flag true
		$TempFileCreated = $true
	}


	# Check if successful or not
	if($LASTEXITCODE -eq 0){
	    # Successful so grab info
	    $global:SecPol = Get-IniContent $ExportedPolicy

	    # Convert to security policy to objects as it makes life easier
	    $SystemAccess    = New-Object psobject -Property $SecPol.'System Access'
	    $AuditPolicy     = New-Object psobject -Property $SecPol.'Event Audit'
	    $PrivilegeRights = New-Object psobject -Property $SecPol.'Privilege Rights'

	    # Create empty array to store objects
	    $FinalOutput = @()

	    # Password Policy
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name EnforcePasswordHistory -DisplayName 'Enforce password history' -RawValue ([int]($SystemAccess.PasswordHistorySize)) -Value ([int]($SystemAccess.PasswordHistorySize))
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name MaximumPasswordAge -DisplayName 'Maximum password age' -RawValue ([int]($SystemAccess.MaximumPasswordAge)) -Value ([int]($SystemAccess.MaximumPasswordAge))
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name MinimumPasswordAge -DisplayName 'Minimum password age' -RawValue ([int]($SystemAccess.MinimumPasswordAge)) -Value ([int]($SystemAccess.MinimumPasswordAge))
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name MinimumPasswordLength -DisplayName 'Minimum password length' -RawValue ([int]($SystemAccess.MinimumPasswordLength)) -Value ([int]($SystemAccess.MinimumPasswordLength))
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name PasswordComplexity -DisplayName 'Password must meet complexity requirements' -RawValue ([int]($SystemAccess.PasswordComplexity)) -Value ([bool]([int]($SystemAccess.PasswordComplexity)))
	    $FinalOutput += New-SecObj -SettingType PasswordPolicy -Name ReversibleEncryption -DisplayName 'Store passwords using reversible encryption' -RawValue ([int]($SystemAccess.ClearTextPassword)) -Value ([bool]([int]($SystemAccess.ClearTextPassword)))
	    
	    # Lockout Policy
	    $FinalOutput += New-SecObj -SettingType LockoutPolicy -Name LockoutDuration -DisplayName 'Account lockout duration' -RawValue ([int]($SystemAccess.LockoutDuration)) -Value ([int]($SystemAccess.LockoutDuration))
	    $FinalOutput += New-SecObj -SettingType LockoutPolicy -Name LockoutThreshold -DisplayName 'Account lockout threshold'-RawValue ([int]($SystemAccess.LockoutBadCount)) -Value ([int]($SystemAccess.LockoutBadCount))
	    $FinalOutput += New-SecObj -SettingType LockoutPolicy -Name ResetLockoutCount -DisplayName 'Reset account lockout counter after' -RawValue ([int]($SystemAccess.ResetLockoutCount)) -Value ([int]($SystemAccess.ResetLockoutCount))

	    # Audit Policy (legacy)
	    function AuditType {
	    param($RawValue)
	        switch($RawValue)
	        { 
	            0 {"No Auditing"} 
	            1 {"Success"} 
	            2 {"Failure"} 
	            3 {"Success, Failure"}
	        }
	    }
	    
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditAccountLogon -RawValue ([int]($AuditPolicy.AuditAccountLogon)) -Value (AuditType ([int]($AuditPolicy.AuditAccountLogon)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditAccountManage -RawValue ([int]($AuditPolicy.AuditAccountManage)) -Value (AuditType ([int]($AuditPolicy.AuditAccountManage)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditDSAccess -RawValue ([int]($AuditPolicy.AuditDSAccess)) -Value (AuditType ([int]($AuditPolicy.AuditDSAccess)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditLogonEvents -RawValue ([int]($AuditPolicy.AuditLogonEvents)) -Value (AuditType ([int]($AuditPolicy.AuditLogonEvents)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditObjectAccess -RawValue ([int]($AuditPolicy.AuditObjectAccess)) -Value (AuditType ([int]($AuditPolicy.AuditObjectAccess)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditPolicyChange -RawValue ([int]($AuditPolicy.AuditPolicyChange)) -Value (AuditType ([int]($AuditPolicy.AuditPolicyChange)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditPrivilegeUse -RawValue ([int]($AuditPolicy.AuditPrivilegeUse)) -Value (AuditType ([int]($AuditPolicy.AuditPrivilegeUse)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditProcessTracking -RawValue ([int]($AuditPolicy.AuditProcessTracking)) -Value (AuditType ([int]($AuditPolicy.AuditProcessTracking)))
	    $FinalOutput += New-SecObj -SettingType AuditPolicy -Name AuditSystemEvents -RawValue ([int]($AuditPolicy.AuditSystemEvents)) -Value (AuditType ([int]($AuditPolicy.AuditSystemEvents)))

	    # Security Options (work in progress)
	    function EorD {
	    param($RawValue)

	        switch($RawValue)
	        {
	            0 {"Disabled"}
	            1 {"Enabled"}
	        }

	    }

	    # Process MS account block status
		if($SecPol.'Registry Values'.'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser'){
			$BlockMSAccountsRaw = $SecPol.'Registry Values'.'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser'.Split(',')[1]
			$BlockMSAccountsValue = switch($BlockMSAccountsRaw)
		    {
				0 {"This policy is disabled"}
				1 {"Users can't add Microsoft accounts"}
				3 {"Users can't add or log on with Microsoft accounts"}
			}
		}else{
			$BlockMSAccountsRaw = -1
			$BlockMSAccountsValue = "Not Defined"
		}
		
	    # console password use
	    $LimitBlankPasswordUse = $SecPol.'Registry Values'.'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'.Split(',')[1]
	  
	    # Security Options
	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name AdminAccountStatus -DisplayName 'Administrator account status' -RawValue ([int]($SystemAccess.EnableAdminAccount)) -Value (EorD ([int]($SystemAccess.EnableAdminAccount)))
	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name BlockMSAccounts -DisplayName 'Block Microsoft accounts' -RawValue ([int]($BlockMSAccountsRaw)) -Value $BlockMSAccountsValue
	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name GuestAccountStatus -DisplayName 'Guest account status' -RawValue ([int]($SystemAccess.EnableGuestAccount)) -Value (EorD ([int]($SystemAccess.EnableGuestAccount)))
	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name LimitBlankPasswordUse -DisplayName 'Limit local account use of blank passwords to console logon only' -RawValue ([int]($LimitBlankPasswordUse)) -Value (EorD ([int]($LimitBlankPasswordUse)))
		$FinalOutput += New-SecObj -SettingType SecurityOptions:NetworkAccess -Name LSAAnonymousNameLookup -DisplayName 'Network access: Allow anonymous SID/Name translation' -RawValue ([int]($SystemAccess.LSAAnonymousNameLookup )) -Value (EorD ([int]($SystemAccess.LSAAnonymousNameLookup )))
		$FinalOutput += New-SecObj -SettingType SecurityOptions:NetworkSecurity -Name ForceLogoffWhenHourExpire -DisplayName 'Network security: Force logoff when logon hours expire' -RawValue ([int]($SystemAccess.ForceLogoffWhenHourExpire )) -Value (EorD ([int]($SystemAccess.ForceLogoffWhenHourExpire )))
	     

	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name RenameAdministrator -DisplayName 'Rename administrator account' -RawValue ([string]($SystemAccess.NewAdministratorName).Replace('"','').trim()) -Value ([string]($SystemAccess.NewAdministratorName).Replace('"','').trim())
	    $FinalOutput += New-SecObj -SettingType SecurityOptions:Accounts -Name RenameGuest -DisplayName 'Rename guest account' -RawValue ([string]($SystemAccess.NewGuestName).Replace('"','').trim()) -Value ([string]($SystemAccess.NewGuestName).Replace('"','').trim())

	    # User rights assignment
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeNetworkLogonRight                -DisplayName 'Access this computer from the network'                          -RawValue $PrivilegeRights.SeNetworkLogonRight             -Value (Get-UserFromSID $PrivilegeRights.SeNetworkLogonRight            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeBackupPrivilege                  -DisplayName 'Back up files and directories'                                  -RawValue $PrivilegeRights.SeBackupPrivilege               -Value (Get-UserFromSID $PrivilegeRights.SeBackupPrivilege              )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeChangeNotifyPrivilege            -DisplayName 'Bypass traverse checking'                                       -RawValue $PrivilegeRights.SeChangeNotifyPrivilege         -Value (Get-UserFromSID $PrivilegeRights.SeChangeNotifyPrivilege        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeSystemtimePrivilege              -DisplayName 'Change the system time'                                         -RawValue $PrivilegeRights.SeSystemtimePrivilege           -Value (Get-UserFromSID $PrivilegeRights.SeSystemtimePrivilege          )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeCreatePagefilePrivilege          -DisplayName 'Create a pagefile'                                              -RawValue $PrivilegeRights.SeCreatePagefilePrivilege       -Value (Get-UserFromSID $PrivilegeRights.SeCreatePagefilePrivilege      )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDebugPrivilege                   -DisplayName 'Debug programs'                                                 -RawValue $PrivilegeRights.SeDebugPrivilege                -Value (Get-UserFromSID $PrivilegeRights.SeDebugPrivilege               )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeRemoteShutdownPrivilege          -DisplayName 'Force shutdown from a remote system'                            -RawValue $PrivilegeRights.SeRemoteShutdownPrivilege       -Value (Get-UserFromSID $PrivilegeRights.SeRemoteShutdownPrivilege      )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeAuditPrivilege                   -DisplayName 'Manage auditing and security log'                               -RawValue $PrivilegeRights.SeAuditPrivilege                -Value (Get-UserFromSID $PrivilegeRights.SeAuditPrivilege               )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeIncreaseQuotaPrivilege           -DisplayName 'Adjust memory quotas for a process'                             -RawValue $PrivilegeRights.SeIncreaseQuotaPrivilege        -Value (Get-UserFromSID $PrivilegeRights.SeIncreaseQuotaPrivilege       )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeIncreaseBasePriorityPrivilege    -DisplayName 'Increase scheduling priority'                                   -RawValue $PrivilegeRights.SeIncreaseBasePriorityPrivilege -Value (Get-UserFromSID $PrivilegeRights.SeIncreaseBasePriorityPrivilege)
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeLoadDriverPrivilege              -DisplayName 'Load and unload device drivers'                                 -RawValue $PrivilegeRights.SeLoadDriverPrivilege           -Value (Get-UserFromSID $PrivilegeRights.SeLoadDriverPrivilege          )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeBatchLogonRight                  -DisplayName 'Log on as a batch job'                                          -RawValue $PrivilegeRights.SeBatchLogonRight               -Value (Get-UserFromSID $PrivilegeRights.SeBatchLogonRight              )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeServiceLogonRight                -DisplayName 'Log on as a service'                                            -RawValue $PrivilegeRights.SeServiceLogonRight             -Value (Get-UserFromSID $PrivilegeRights.SeServiceLogonRight            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeInteractiveLogonRight            -DisplayName 'Log on locally'                                                 -RawValue $PrivilegeRights.SeInteractiveLogonRight         -Value (Get-UserFromSID $PrivilegeRights.SeInteractiveLogonRight        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeSecurityPrivilege                -DisplayName 'Generate security audits'                                       -RawValue $PrivilegeRights.SeSecurityPrivilege             -Value (Get-UserFromSID $PrivilegeRights.SeSecurityPrivilege            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeSystemEnvironmentPrivilege       -DisplayName 'Modify firmware environment values'                             -RawValue $PrivilegeRights.SeSystemEnvironmentPrivilege    -Value (Get-UserFromSID $PrivilegeRights.SeSystemEnvironmentPrivilege   )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeProfileSingleProcessPrivilege    -DisplayName 'Profile single process'                                         -RawValue $PrivilegeRights.SeProfileSingleProcessPrivilege -Value (Get-UserFromSID $PrivilegeRights.SeProfileSingleProcessPrivilege)
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeSystemProfilePrivilege           -DisplayName 'Profile system performance'                                     -RawValue $PrivilegeRights.SeSystemProfilePrivilege        -Value (Get-UserFromSID $PrivilegeRights.SeSystemProfilePrivilege       )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeAssignPrimaryTokenPrivilege      -DisplayName 'Replace a process level token'                                  -RawValue $PrivilegeRights.SeAssignPrimaryTokenPrivilege   -Value (Get-UserFromSID $PrivilegeRights.SeAssignPrimaryTokenPrivilege  )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeRestorePrivilege                 -DisplayName 'Restore files and directories'                                  -RawValue $PrivilegeRights.SeRestorePrivilege              -Value (Get-UserFromSID $PrivilegeRights.SeRestorePrivilege             )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeShutdownPrivilege                -DisplayName 'Shut down the system'                                           -RawValue $PrivilegeRights.SeShutdownPrivilege             -Value (Get-UserFromSID $PrivilegeRights.SeShutdownPrivilege            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeTakeOwnershipPrivilege           -DisplayName 'Take ownership of files or other objects'                       -RawValue $PrivilegeRights.SeTakeOwnershipPrivilege        -Value (Get-UserFromSID $PrivilegeRights.SeTakeOwnershipPrivilege       )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyNetworkLogonRight            -DisplayName 'Deny access to this computer from the network'                  -RawValue $PrivilegeRights.SeDenyNetworkLogonRight         -Value (Get-UserFromSID $PrivilegeRights.SeDenyNetworkLogonRight        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyInteractiveLogonRight        -DisplayName 'Deny log on locally'                                            -RawValue $PrivilegeRights.SeDenyInteractiveLogonRight     -Value (Get-UserFromSID $PrivilegeRights.SeDenyInteractiveLogonRight    )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeUndockPrivilege                  -DisplayName 'Remove computer from docking station'                           -RawValue $PrivilegeRights.SeUndockPrivilege               -Value (Get-UserFromSID $PrivilegeRights.SeUndockPrivilege              )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeManageVolumePrivilege            -DisplayName 'Perform volume maintenance tasks'                               -RawValue $PrivilegeRights.SeManageVolumePrivilege         -Value (Get-UserFromSID $PrivilegeRights.SeManageVolumePrivilege        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeRemoteInteractiveLogonRight      -DisplayName 'Allow log on through Remote Desktop Services'                   -RawValue $PrivilegeRights.SeRemoteInteractiveLogonRight   -Value (Get-UserFromSID $PrivilegeRights.SeRemoteInteractiveLogonRight  )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeImpersonatePrivilege             -DisplayName 'Impersonate a client after authentication'                      -RawValue $PrivilegeRights.SeImpersonatePrivilege          -Value (Get-UserFromSID $PrivilegeRights.SeImpersonatePrivilege         )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeCreateGlobalPrivilege            -DisplayName 'Create global objects'                                          -RawValue $PrivilegeRights.SeCreateGlobalPrivilege         -Value (Get-UserFromSID $PrivilegeRights.SeCreateGlobalPrivilege        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeIncreaseWorkingSetPrivilege      -DisplayName 'Increase a process working set'                                 -RawValue $PrivilegeRights.SeIncreaseWorkingSetPrivilege   -Value (Get-UserFromSID $PrivilegeRights.SeIncreaseWorkingSetPrivilege  )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeTimeZonePrivilege                -DisplayName 'Change the Time Zone'                                           -RawValue $PrivilegeRights.SeTimeZonePrivilege             -Value (Get-UserFromSID $PrivilegeRights.SeTimeZonePrivilege            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeCreateSymbolicLinkPrivilege      -DisplayName 'Create symbolic links'                                          -RawValue $PrivilegeRights.SeCreateSymbolicLinkPrivilege   -Value (Get-UserFromSID $PrivilegeRights.SeCreateSymbolicLinkPrivilege  )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeLockMemoryPrivilege              -DisplayName 'Lock pages in memory'                                           -RawValue $PrivilegeRights.SeLockMemoryPrivilege              -Value (Get-UserFromSID $PrivilegeRights.SeLockMemoryPrivilege              )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeCreatePermanentPrivilege         -DisplayName 'Create permanent shared objects'                                -RawValue $PrivilegeRights.SeCreatePermanentPrivilege         -Value (Get-UserFromSID $PrivilegeRights.SeCreatePermanentPrivilege         )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeMachineAccountPrivilege          -DisplayName 'Add workstations to domain'                                     -RawValue $PrivilegeRights.SeMachineAccountPrivilege          -Value (Get-UserFromSID $PrivilegeRights.SeMachineAccountPrivilege          )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeTcbPrivilege                     -DisplayName 'Act as part of the operating system'                            -RawValue $PrivilegeRights.SeTcbPrivilege                     -Value (Get-UserFromSID $PrivilegeRights.SeTcbPrivilege                     )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyBatchLogonRight              -DisplayName 'Deny logon as a batch job'                                      -RawValue $PrivilegeRights.SeDenyBatchLogonRight              -Value (Get-UserFromSID $PrivilegeRights.SeDenyBatchLogonRight              )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyServiceLogonRight            -DisplayName 'Deny logon as a service'                                        -RawValue $PrivilegeRights.SeDenyServiceLogonRight            -Value (Get-UserFromSID $PrivilegeRights.SeDenyServiceLogonRight            )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyInteractiveLogonRight        -DisplayName 'Deny local logon'                                               -RawValue $PrivilegeRights.SeDenyInteractiveLogonRight        -Value (Get-UserFromSID $PrivilegeRights.SeDenyInteractiveLogonRight        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeDenyRemoteInteractiveLogonRight  -DisplayName 'Deny logon through Terminal Services'                           -RawValue $PrivilegeRights.SeDenyRemoteInteractiveLogonRight  -Value (Get-UserFromSID $PrivilegeRights.SeDenyRemoteInteractiveLogonRight  )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeCreateTokenPrivilege             -DisplayName 'Create a token object'                                          -RawValue $PrivilegeRights.SeCreateTokenPrivilege             -Value (Get-UserFromSID $PrivilegeRights.SeCreateTokenPrivilege             )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeTrustedCredManAccessPrivilege    -DisplayName 'Access Credential Manager as a trusted caller'                  -RawValue $PrivilegeRights.SeTrustedCredManAccessPrivilege    -Value (Get-UserFromSID $PrivilegeRights.SeTrustedCredManAccessPrivilege    )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeRelabelPrivilege                 -DisplayName 'Modify an object label'                                         -RawValue $PrivilegeRights.SeRelabelPrivilege                 -Value (Get-UserFromSID $PrivilegeRights.SeRelabelPrivilege                 )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeEnableDelegationPrivilege        -DisplayName 'Enable computer and user accounts to be trusted for delegation' -RawValue $PrivilegeRights.SeEnableDelegationPrivilege        -Value (Get-UserFromSID $PrivilegeRights.SeEnableDelegationPrivilege        )
	    $FinalOutput += New-SecObj -SettingType UserRightsAssignment -Name SeSyncAgentPrivilege               -DisplayName 'Synchronize directory service data'                             -RawValue $PrivilegeRights.SeSyncAgentPrivilege               -Value (Get-UserFromSID $PrivilegeRights.SeSyncAgentPrivilege               )
	  
	  
	    # Output cleaned password policy
	    if(-not $ShowLockoutPolicy -and -not $ShowPasswordPolicy -and -not $ShowSecurityOptions -and -not $ShowUserRightsAssignment)
	    {
		    $FinalOutput
	    }
	    if($ShowPasswordPolicy){
	    	$FinalOutput | Where-Object { $_.SettingType -eq 'PasswordPolicy' }
	    }
	    if($ShowLockoutPolicy){
	    	$FinalOutput | Where-Object { $_.SettingType -eq 'LockoutPolicy' }
	    }
	    if($ShowSecurityOptions){
	    	$FinalOutput | Where-Object { $_.SettingType -like 'SecurityOptions*' }
	    }
	    if($ShowUserRightsAssignment){
	    	$FinalOutput | Where-Object { $_.SettingType -eq 'UserRightsAssignment' }
	    }

	    # Clean up remove exported policy
		if($TempFileCreated){
			Remove-Item $ExportedPolicy
		}
	}else{

	    # Handle secedit error
	    Write-Error "secedit failed to run - $(([ComponentModel.Win32Exception]$LASTEXITCODE).Message)" -TargetObject secedit -ErrorId $LASTEXITCODE

	}
}