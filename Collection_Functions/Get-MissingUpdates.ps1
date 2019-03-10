Function Get-MissingUpdates {
param($Timeout=10)

	$StartTime = Get-Date
	$EndTime = (Get-Date).AddMinutes($Timeout)

	$Job = Start-Job -ScriptBlock {
	    $CabFile = Join-Path $env:SystemDrive 'wsusscn2.cab'

	    if(-not (Test-Path $CabFile))
	    {
	        # try to download the cab file
	        # more info at https://msdn.microsoft.com/en-us/library/windows/desktop/aa387290%28v=vs.85%29.aspx
	        $url = 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
	        (New-Object System.Net.webclient).DownloadFile($url,$CabFile)
	    }

	    $Session = New-Object -ComObject Microsoft.Update.Session
	    $UServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager

	    # Remove old offline sync services
	    $UServiceManager.Services | Where-Object { $_.Name -eq 'Offline Sync Service' } | Foreach{ $UServiceManager.RemoveService($_.ServiceID) }

	    $UService =  $UServiceManager.AddScanPackageService("Offline Sync Service", $CabFile)
	    $Searcher = $Session.CreateUpdateSearcher()
	    $Searcher.ServerSelection = 3

	    $Services = $UServiceManager.Services | Where-Object { $_.OffersWindowsUpdates -eq $true }
	    $Criteria = "IsInstalled=0" # Important updates that are not installed

	    foreach($Service in $Services)
	    {
	    	try
	    	{
			    $Searcher.ServiceID = $Service.ServiceID
			    $SearchResult = $Searcher.Search($Criteria)
			    $SearchResult.Updates | Sort-Object MsrcSeverity | foreach{
			        $Out = '' | Select-Object Title, Severity, KB, SecurityBulletin, CVE, DateReleased
			        $Out.Title = $_.Title
			        $Out.Severity = $_.MsrcSeverity
			        $Out.KB = "KB$($_.KBArticleIDs -join ',KB')"
			        $Out.SecurityBulletin = $_.SecurityBulletinIDs -join ','
			        $Out.CVE = $_.CveIDs -join ','
			        $Out.DateReleased = $_.LastDeploymentChangeTime
			        $OptionalUpdate = if($_.BrowseOnly){'Yes'}else{'No'}

					"<Result Title=`"$($Out.Title)`" Severity=`"$($Out.Severity)`" KB=`"$($Out.KB)`" SecurityBulletin=`"$($Out.SecurityBulletin)`" CVE=`"$($Out.CVE)`" DateReleased=`"$($Out.DateReleased)`" UpdateService=`"$($Service.Name)`" OptionalUpdate=`"$($OptionalUpdate)`" />"

			    }
		    }
		    catch
		    {
		    	Write-Warning "Unable to communicate with '$($Service.Name)' skipping this update service. This is perfectly fine."
		    }
	    }
    }

    while('Completed','Stopped' -notcontains $Job.State)
    {
        $Job = Get-Job $Job.Id
		        
		Write-Host "$((get-Date).ToString('dd-MM-yyyy HH:mm:ss')) - Windows Update is processing please wait, run time is $([math]::Round(((Get-Date) - $StartTime).totalminutes)) minutes"

        if((Get-Date) -gt $EndTime)
		{
			Write-Host "$((get-Date).ToString('dd-MM-yyyy HH:mm:ss')) - Windows Update stopping due to timeout, run time was $([math]::Round(((Get-Date) - $StartTime).totalminutes)) minutes" -Foregroundcolor yellow
            $Job | Stop-Job
		}
        elseif($Job.State -eq 'Running')
        {
            Start-Sleep -Seconds 60
        }
    }
    
    $Job | Receive-Job
    $Job | Remove-Job

}#end