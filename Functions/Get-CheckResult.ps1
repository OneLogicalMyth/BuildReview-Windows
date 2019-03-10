Function Get-CheckResult {
param($ResultXML,$CheckResult,$Definition)

	if($CheckResult.ParentNode.ParentNode.Name -eq 'MissingUpdates')
	{

		$Out = '' | Select-Object Host, Title, Severity, KB, SecurityBulletin, CVE, DateReleased, OptionalUpdate, UpdateService
		$Out.Host = $ResultXML.Policy.ComputerInfo.HostName
		$Out.Title = $CheckResult.Title
		$Out.Severity = $CheckResult.Severity
		$Out.KB = $CheckResult.KB
		$Out.SecurityBulletin = $CheckResult.SecurityBulletin
		$Out.CVE = $CheckResult.CVE
		$Out.DateReleased = $CheckResult.DateReleased
		$Out.OptionalUpdate = $CheckResult.OptionalUpdate
		$Out.UpdateService = $CheckResult.UpdateService
		$Out

	}elseif($CheckResult.ParentNode.ParentNode.Name -eq 'JavaVersions')
	{

		$Out = '' | Select-Object Host, FileName, FileVersion, ProductVersion, ProductName
		$Out.Host = $ResultXML.Policy.ComputerInfo.HostName
		$Out.FileName = $CheckResult.FileName
		$Out.FileVersion = $CheckResult.FileVersion
		$Out.ProductVersion = $CheckResult.ProductVersion
		$Out.ProductName = $CheckResult.ProductName
		$Out		

	}else{

		# get check
		$CheckData = $ResultXML.SelectSingleNode("//Check[@CID=`"$($CheckResult.CID)`"]")

		# get values
		$ValueItem = $Definition.SelectSingleNode("//Check/CIDs/CID[text()=`"$($CheckResult.CID)`"]")
		$ValueItemDescription = $ValueItem.Description
		$Note = $CheckResult.Note

		if($Note -like 'Check Failed due to Error: Cannot find path*')
		{
			$Note = 'No registry key or property was found, "Not Defined" has been assumed.'
		}

		Switch($CheckData.Type)
		{
			'software'
			{
				$CheckDataValue = "version $($CheckData.Value2)"
			}

			default
			{
				$CheckDataValue = $CheckData.Value
			}
		}

		Switch($CheckData.Comparison)
		{
			'ge'
			{
				$ValueItemObtained = $CheckResult.ObtainedValue
				$ValueItemRequired = "Greater or equal to $CheckDataValue"
			}

			'le'
			{
				$ValueItemObtained = $CheckResult.ObtainedValue
				$ValueItemRequired = "Less or equal to $CheckDataValue"
			}

			'gt'
			{
				$ValueItemObtained = $CheckResult.ObtainedValue
				$ValueItemRequired = "Greater than $CheckDataValue"
			}

			'lt'
			{
				$ValueItemObtained = $CheckResult.ObtainedValue
				$ValueItemRequired = "Less than $CheckDataValue"
			}

			'between'
			{
				$ValueItemObtained = $CheckResult.ObtainedValue
				$ValueItemRequired = "Between $CheckDataValue and $($CheckData.Value2) inclusive"
			}

			default
			{
				if($ValueItem)
				{
					$ValueItemObtained = $ValueItem.ParentNode.ParentNode.Value | Where-Object { $_.raw -eq $CheckResult.ObtainedValue } | Select-Object -ExpandProperty translated
					$ValueItemRequired = $ValueItem.ParentNode.ParentNode.Value | Where-Object { $_.raw -eq $CheckDataValue } | Select-Object -ExpandProperty translated
				}else{
					$ValueItemDescription = 'No definition for check item, update the definition file!'
					$ValueItemObtained = $CheckResult.ObtainedValue
					$ValueItemRequired = $CheckDataValue
				}

			}

		}

		if((Test-IsNull $ValueItemObtained) -and (Test-IsNull $CheckResult.ObtainedValue))
		{
			$ValueItemObtained = 'Not Defined'
		}elseif((Test-IsNull $ValueItemObtained)){
			$ValueItemObtained = $CheckResult.ObtainedValue
		}
		if((Test-IsNull $ValueItemRequired))
		{
			$ValueItemRequired = $CheckDataValue
		}

		$Out = '' | Select-Object Host, Description, 'Value Obtained', 'Value Required', Notes
		$Out.Host = $ResultXML.Policy.ComputerInfo.HostName
		$Out.Description = $ValueItemDescription
		$Out.'Value Obtained' = $ValueItemObtained
		$Out.'Value Required' = $ValueItemRequired
		$Out.Notes = $Note
		$Out

	}

}