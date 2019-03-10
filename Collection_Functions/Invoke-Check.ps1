Function Invoke-Check {
param([PSObject]$CheckData,$Config,$Caption,$DomainRole)

	#Check if requirements are met for check
	$CheckRequirements = $CheckData.Requirements -split ','
	$MeetsRequirements = $false
	foreach($Requirement in $CheckRequirements)
	{
		if(-not $MeetsRequirements)
		{
			$Tmp = $Config.SelectNodes("//Requirements/Requirement[@ID=`"$Requirement`"]")
			if($Caption -like "*$($($Tmp).Caption)*" -and ($($Tmp).DomainRole -split ',') -contains $DomainRole)
			{
				$MeetsRequirements = $true
			}

		}
	}
	if(-not $MeetsRequirements)
	{
		return $false
	}

	#Preload any required data
	if(-not $Global:SecurityOptionsCache)
	{
		$Global:SecurityOptionsCache = Read-LocalSecurity
	}
	if(-not $Global:AuditPolCache)
	{
		$Global:AuditPolCache = Get-AuditPolicy
	}
	if(-not $Global:SoftwareCache)
	{
		$Global:SoftwareCache = Get-InstalledSoftware
	}

	# Function to resolve SID to username
	Function Get-UserFromSID {
	param($RawSID)

        try
        {
            $objSID  = New-Object System.Security.Principal.SecurityIdentifier ($RawSID)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
            "SID resolves to $($objUser.Value)"
        }
        catch
        {
            # Could not be translated so output SID
            # This caused when accounts are deleted but policies not cleaned afterwards
            # or possibly a foreign domain
            "SID could not be resolved, user might be deleted or on a foreign domain"
        }

	}

	Switch($CheckData.Type)
	{ 
	
		'registry'
		{

			switch($CheckData.Hive)
			{
				'HKLM'
				{
					$OutObj = '' | Select-Object  KeyUsed, PropertyUsed, ObtainedValue, CheckResult, Note
					$OutObj.KeyUsed = "$($CheckData.Hive):\$($CheckData.Path)"
					$OutObj.PropertyUsed = $CheckData.Name
					try
					{
						$OutObj.ObtainedValue = (Get-ItemProperty $OutObj.KeyUsed -ErrorAction stop).$($CheckData.Name)
						$OutObj.Note = $null
						if((Test-IsNull $OutObj.ObtainedValue))
						{
							$Value = $OutObj.ObtainedValue
						}
					}
					catch
					{
						$OutObj.ObtainedValue = $null
						$OutObj.Note = "Check Failed due to Error: $_"
					}
					$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value -Value2 $CheckData.Value2 -Comparison $CheckData.Comparison

					@{
						Object = $OutObj
						XML = "<Result CID=`"$($CheckData.CID)`" KeyUsed=`"$($OutObj.KeyUsed)`" PropertyUsed=`"$($OutObj.PropertyUsed)`" ObtainedValue=`"$($OutObj.ObtainedValue)`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
					}
				}

				'HKU'
				{
					# Only include SIDs that begin with a S-1-5-21 but do not end with a _Classes this stops the default and network service profiles being checked
					$SIDs = Get-ChildItem HKU: | Select-Object -ExpandProperty PSChildName | Where-Object { $_ -like 'S-1-5-21*' -and $_ -notlike '*_Classes' }
					foreach($SID in $SIDs)
					{
						$OutObj = '' | Select-Object  KeyUsed, PropertyUsed, ObtainedValue, CheckResult, Note
						$OutObj.KeyUsed = "HKU:\$SID\$($CheckData.Path)"
						$OutObj.PropertyUsed = $CheckData.Name
						try
						{
							$OutObj.ObtainedValue = (Get-ItemProperty $OutObj.KeyUsed -ErrorAction stop).$($CheckData.Name)
							$OutObj.Note = Get-UserFromSID -RawSID $SID
							if((Test-IsNull $OutObj.ObtainedValue))
							{
								$OutObj.ObtainedValue = $null
							}
						}
						catch
						{
							$OutObj.ObtainedValue = $null
							$OutObj.Note = "Check Failed due to Error: $_"
						}
						$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value -Value2 $CheckData.Value2 -Comparison $CheckData.Comparison
						
						@{
							Object = $OutObj
							XML = "<Result CID=`"$($CheckData.CID)`" KeyUsed=`"$($OutObj.KeyUsed)`" PropertyUsed=`"$($OutObj.PropertyUsed)`" ObtainedValue=`"$($OutObj.ObtainedValue)`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
						}
					}
				}

				default
				{
					throw 'Registry check requires a valid hive!'
				}
			}
			
		}

		'securityoption'
		{
			$OutObj = '' | Select-Object  ObtainedValue, CheckResult, Note
			$SecPath = $CheckData.Name.Split('/')
			if($SecPath[0] -eq 'UserRightsAssignment')
			{
				$OutObj.ObtainedValue = ($Global:SecurityOptionsCache | Where-Object { $_.SettingType -eq $SecPath[0] -and $_.Name -eq $SecPath[1] }).Value
			}else
			{
				$OutObj.ObtainedValue = ($Global:SecurityOptionsCache | Where-Object { $_.SettingType -eq $SecPath[0] -and $_.Name -eq $SecPath[1] }).RawValue
			}
			
			$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value -Value2 $CheckData.Value2 -Comparison $CheckData.Comparison
			$OutObj.Note = $null

			@{
				Object = $OutObj
				XML = "<Result CID=`"$($CheckData.CID)`" ObtainedValue=`"$($OutObj.ObtainedValue)`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
			}
		}

		'audit'
		{
			$OutObj = '' | Select-Object  ObtainedValue, CheckResult, Note
			$OutObj.ObtainedValue = ($Global:AuditPolCache | Where-Object { $_.SubCategory -eq $CheckData.Name }).RawValue
			$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value -Comparison $CheckData.Comparison
			$OutObj.Note = $null

			@{
				Object = $OutObj
				XML = "<Result CID=`"$($CheckData.CID)`" ObtainedValue=`"$($OutObj.ObtainedValue)`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
			}

		}

		'software'
		{
			$OutObj = '' | Select-Object  ObtainedValue, CheckResult, Note
			$SoftwareInfo = $Global:SoftwareCache | Where-Object { $_.DisplayName -eq $CheckData.Name }
			$OutObj.ObtainedValue = $SoftwareInfo.$($CheckData.Value)
			if($CheckData.Value -eq 'DisplayVersion')
			{
				$OutObj.ObtainedValue = [version]$OutObj.ObtainedValue
				$ValueToCompare = [version]$CheckData.Value2
			}else
			{
				$ValueToCompare = $CheckData.Value2
			}
			$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value2 -Comparison $CheckData.Comparison
			if($SoftwareInfo)
			{
				$OutObj.Note = $null
			}else{
				$OutObj.Note = "$($CheckData.Name) is not installed on this computer."
			}
			

			@{
				Object = $OutObj
				XML = "<Result CID=`"$($CheckData.CID)`" ObtainedValue=`"$($OutObj.ObtainedValue)`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
			}
		}

		'wmi'
		{
			$OutObj = '' | Select-Object  ObtainedValue, CheckResult, Note

			try
			{
				$QueryResult = Get-WmiObject -Query $CheckData.Query
			}
			catch
			{
				$OutObj.Note = "WMI query failed to run: $_"
			}
			
			$OutObj.ObtainedValue = $QueryResult | Select-Object -ExpandProperty $($CheckData.Name)
			$OutObj.CheckResult = Compare-Values -ObtainedValue $OutObj.ObtainedValue -Value $CheckData.Value -Value2 $CheckData.Value2 -Comparison $CheckData.Comparison	

			@{
				Object = $OutObj
				XML = "<Result CID=`"$($CheckData.CID)`" ObtainedValue=`"$($OutObj.ObtainedValue -join ',')`" CheckResult=`"$($OutObj.CheckResult)`" Note=`"$($OutObj.Note)`" />"
			}
		}
        
        default { Write-Warning "Type '$($CheckData.Type)' is not defined!" } 
	
	}


}