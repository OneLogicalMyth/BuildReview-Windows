#region Start Build Review
	#load windows forms for output
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

	# Check for admin rights
	$IsAdmin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	if(-not $IsAdmin)
	{
		[system.windows.forms.messagebox]::Show('This needs to be run as administrator, please right click and select "run as administrator".','Build Review',0,16)
		exit
	}

	#Basic WMI calls
	$OSInfo  = Get-Wmiobject Win32_operatingsystem
	$SYSInfo = Get-Wmiobject Win32_computersystem
	$IPs	 = (Get-Wmiobject win32_networkadapterconfiguration -Filter 'IPEnabled = "True"' | Select-Object -ExpandProperty IPAddress) -Join ','	

	[xml]$Policy = [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($PolicyXML))
	$Config = $Policy.Policy

	# Check for internet access, for Windows Update
    if(-not $DisableWindowsUpdate)
    {
	    $CabFile = Join-Path $env:SystemDrive 'wsusscn2.cab'
	    if(-not (Test-Path $CabFile))
	    {
	        # try to download the cab file
	        # more info at https://msdn.microsoft.com/en-us/library/windows/desktop/aa387290%28v=vs.85%29.aspx
	        $url = 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
	        try
	        {
	        	(New-Object System.Net.webclient).DownloadFile($url,$CabFile)
	        }
	        catch
	        {
	        		[system.windows.forms.messagebox]::Show("Unable to download the required files for missing Windows Update checks. Please download from 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab' and save to '$CabFile'.",'Build Review',0,16)
	        		exit
	        }
	    }
    }

	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null

	# Add basic info to the XML for future reference
	$DomainRole = @{
		0='Standalone Workstation'
		1='Member Workstation'
		2='Standalone Server'
		3='Member Server'
		4='Backup Domain Controller'
		5='Primary Domain Controller'
	}
	$XMLResults = $Policy.CreateElement('ComputerInfo')
	$XMLResults.InnerXml = "<HostName>$($SYSInfo.DNSHostName)</HostName><Domain>$($SYSInfo.Domain)</Domain><Manufacturer>$($SYSInfo.Manufacturer)</Manufacturer><OSArchitecture>$($OSInfo.OSArchitecture)</OSArchitecture><UserName>$($SYSInfo.UserName)</UserName><OS>$($OSInfo.Caption)</OS><ServicePack>$($OSInfo.CSDVersion)</ServicePack><DomainRole>$($DomainRole[([int]$SYSInfo.DomainRole)])</DomainRole><IPs>$IPs</IPs>"
	$Config.AppendChild($XMLResults) | Out-Null
	Remove-Variable XMLResults

	$DesktopPath = [Environment]::GetFolderPath("Desktop")
	$SaveResultTo = Join-Path $DesktopPath "$($SYSInfo.DNSHostName)_$((Get-Date).ToString('dd-MM-yyyy_HH-mm')).xml"

	$StartCollection = [system.windows.forms.messagebox]::Show('The Build Review tool will now start. Do you want to continue?','Build Review',4,32)
	if($StartCollection -ne 6)
	{
		exit
	}

#Checks

	$CollectionsCount = @($Config.Collection).Count
	$i = 1

	Write-Host "$((get-Date).ToString('dd-MM-yyyy HH:mm:ss')) - Starting checks"
	foreach($Collection in $Config.Collection)
	{
		Write-Host "$((get-Date).ToString('dd-MM-yyyy HH:mm:ss')) - Processing check collection $i out of $CollectionsCount, please wait..."
		$i++

		foreach($Group in $Collection.Group)
		{
			$XMLResults = $Policy.CreateElement('Results')
			$InnerXML = ''

			$CheckResults = Foreach($Check in $Group.Check)
			{
				
				$Result = Invoke-Check $Check $Config $OSInfo.Caption $SYSInfo.DomainRole
				$Result
				if($Result)
				{
					# `0 replaces a 0x00 byte string, that sometimes the registry uses instead of null
					$InnerXml += ($Result.XML -replace "`0")
					$Result.Object
					Remove-Variable Check,Result
				}
			}

			$XMLResults.InnerXml = $InnerXml
			$Group.AppendChild($XMLResults) | Out-Null
				

			$ChecksPassed = [int]($CheckResults | Group-Object CheckResult | Where-Object { $_.name -eq 'Pass' }).count
			$ChecksFailed = [int]($CheckResults | Group-Object CheckResult | Where-Object { $_.name -eq 'Fail' }).count

			if($Group.Comparison -eq 'and' -and $ChecksFailed -eq 0)
			{
				$Group.SetAttribute('GroupResult','Pass')

			}elseif($Group.Comparison -eq 'or' -and $ChecksPassed -gt 0)
			{
					$Group.SetAttribute('GroupResult','Pass')
			}else{
					$Group.SetAttribute('GroupResult','Fail')
			}
			
			Remove-Variable Group,ChecksFailed,ChecksPassed,CheckResults

		}
		
	}


#Missing Updates
$XMLResults = $Policy.CreateElement('Collection')
$XMLResults.SetAttribute('Name','MissingUpdates')
if(-not $DisableWindowsUpdate)
{
	$MissingUpdates = Get-MissingUpdates
	if($MissingUpdates)
	{
			$XMLResults.InnerXml = "<Group Name=`"MissingUpdates`" GroupResult=`"Fail`" Comparison=`"and`"><Results>$($MissingUpdates -Join '')</Results></Group>"
	}else{
			$XMLResults.InnerXml = "<Group Name=`"MissingUpdates`" GroupResult=`"Pass`" Comparison=`"and`"><Results /></Group>"
	}
}else{
	$XMLResults.InnerXml = "<Group Name=`"MissingUpdates`" GroupResult=`"CheckDisabled`" Comparison=`"and`"><Results /></Group>"
}
$Config.AppendChild($XMLResults) | Out-Null
Remove-Variable XMLResults

# grab a list of all Java binaries on the system
$XMLResults = $Policy.CreateElement('Collection')
$XMLResults.SetAttribute('Name','JavaBinaries')
Write-Host "$((get-Date).ToString('dd-MM-yyyy HH:mm:ss')) - Looking for Java binaries, please wait..."
$JavaBinaries = Get-JavaVersions | foreach{ "<Result FileName=`"$($_.FileName)`" FileVersion=`"$($_.FileVersion)`" ProductVersion=`"$($_.ProductVersion)`" ProductName=`"$($_.ProductName)`" />" }
if($JavaBinaries)
{
		$XMLResults.InnerXml = "<Group Name=`"JavaVersions`" GroupResult=`"Fail`" Comparison=`"and`"><Results>$($JavaBinaries -join '')</Results></Group>"
}else{
		$XMLResults.InnerXml = "<Group Name=`"JavaVersions`" GroupResult=`"Pass`" Comparison=`"and`"><Results /></Group>"
}
$Config.AppendChild($XMLResults) | Out-Null
Remove-Variable XMLResults

#Remove all comments before saving
$Policy.SelectNodes('.//comment()') | foreach{ $N = [System.Xml.XmlNode]$_; $N.ParentNode.RemoveChild($N) } | Out-Null

# collect raw configuration files
$ExportedPolicy = (Join-Path $env:TEMP SecurityPolicy.inf)
$null = Invoke-Expression "secedit /export /cfg $ExportedPolicy"
$SecPol = Read-FileToBase64 $ExportedPolicy
Remove-Item $ExportedPolicy -Force

Remove-Variable ExportedPolicy
$ExportedPolicy = (Join-Path $env:TEMP GPResult.html)
$null = Invoke-Expression "gpresult /H $ExportedPolicy /F"
$gpresult = Read-FileToBase64 $ExportedPolicy
Remove-Item $ExportedPolicy -Force

Remove-Variable ExportedPolicy
$ExportedPolicy = (Join-Path $env:TEMP auditpol.txt)
$null = Invoke-Expression "auditpol /get /category:* > $ExportedPolicy"
$auditpol = Read-FileToBase64 $ExportedPolicy
Remove-Item $ExportedPolicy -Force

$XMLResults = $Policy.CreateElement('FileDump')
$XMLResults.InnerXml = "<File Name=`"SecurityPolicy.inf`">$SecPol</File><File Name=`"GPResult.html`">$gpresult</File><File Name=`"auditpol.txt`">$auditpol</File>"
$Config.AppendChild($XMLResults) | Out-Null

# Save output
$SaveResultTo = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SaveResultTo)
$Policy.Save($SaveResultTo)

[system.windows.forms.messagebox]::Show("Completed!`nResults have been saved to '$SaveResultTo'",'Build Review',0,64)