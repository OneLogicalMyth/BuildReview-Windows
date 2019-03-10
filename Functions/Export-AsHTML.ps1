Function Export-AsHTML {
param($InputFolder='.\')

    # Used for building a host list at the end
	$global:Hosts = @()

	Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status 'Building File List' -PercentComplete 25

	# import required AssemblyName
	Add-Type -AssemblyName System.Web

	$Files = Get-ChildItem -Path $InputFolder -Filter *.xml
	if(-not $Files)
	{
		throw 'No files found to merge into a report!'
		return
	}

	[xml]$Def = Get-Content (Join-Path $global:BuildReviewRoot 'Policy\definitions.xml')

	$VulnID = 1
	$TableID = 1

	# create object to store results
	$FinalResult = '' | Select-Object Result
	$FinalResult.Result = @()

	Foreach($File in $Files)
	{
		[xml]$Result = Get-Content $File.FullName

        # output raw files
        $TooloutputFolder = Join-Path -Path (Resolve-Path $InputFolder) -ChildPath 'tool-output'
        if(-not (Test-Path $TooloutputFolder))
        {
            New-Item $TooloutputFolder -ItemType Directory | Out-Null
        }
        $Result.Policy.FileDump.File | foreach {
            $FileOut = (Join-Path $TooloutputFolder "$($Result.Policy.ComputerInfo.HostName)-$($_.Name)")
            Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status "Exporting Raw Files from '$($File.Name)'" -CurrentOperation "Exporting raw file $($_.Name)" -PercentComplete 50
            Out-FileFromBase64 -Base64 $_.'#text' -FileName $FileOut
            Remove-Variable FileOut
        }

		# add to host list
		$FileDevices = (New-Object -TypeName PSObject -Property @{
																	'HostName'=$Result.Policy.ComputerInfo.HostName
																	'OS'=$Result.Policy.ComputerInfo.OS
																})
		$Hosts += @($FileDevices)

		# Checks to exclude from collections or groups
		$CheckIDsToExclude = $Def.Definitions.Checks.Check | Select-Object -ExpandProperty CID

		# process collections
		foreach($Collection in ($Def.Definitions.Collections.Collection))
		{
			Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status "Exporting Collection Results from '$($File.Name)'" -CurrentOperation "Processing results for '$($Collection.name)'" -PercentComplete 75

			# check to see if any groups are excluded from this result
			$ResultCollection = $Result.SelectNodes("//Collection[@Name=`"$($Collection.name)`"]").Group
			$GroupsForCollection = $Def.Definitions.Groups.Group | Where-Object { $_.collection -eq $Collection.name }
			$ResultGroups = foreach($ResultCollectionGroup in $ResultCollection)
			{
				# excludes any defined groups
				if(-not ($GroupsForCollection | Where-Object { $_.name -eq $ResultCollectionGroup.Name }) -and $ResultCollectionGroup.GroupResult -ne 'Pass')
				{
					foreach($CheckResult in $ResultCollectionGroup.Results.Result)
					{
						if($CheckIDsToExclude -notcontains $CheckResult.CID -and $CheckResult.CheckResult -ne 'Pass')
						{
							# process group and add results to table array for collection
							Get-CheckResult $Result $CheckResult $Def
                            $CollectionHasResults = $true
						}						
					}
				}
			}

            if($CollectionHasResults)
            {
            	$FinalResult.Result += (New-Object -TypeName PSObject -Property @{
																'Title'=$Collection.Title
																'Description'=$Collection.Description
																'LongRecommendation'=$Collection.LongRecommendation
																'ShortRecommendation'=$Collection.ShortRecommendation
																'Devices'=$FileDevices
																'TableTitle'=$Collection.TableTitle
																'TableResults'=$ResultGroups
																'Details'=$Collection.Details
																'ExternalReference'=$Collection.ExternalReference
																})
                
                $CollectionHasResults = $false
            }
		}

		#process groups
		foreach($Group in ($Def.Definitions.Groups.Group))
		{
			Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status "Exporting Group Results from '$($File.Name)'" -CurrentOperation "Processing results for '$($Group.name)'" -PercentComplete 85

			# check to see if any groups are excluded from this result
			$ResultGroup = $Result.SelectNodes("//Group[@Name=`"$($Group.name)`"]")
			if($ResultGroup.GroupResult -eq 'Fail')
			{
				$GroupChecks = foreach($CheckResult in $ResultGroup.Results.Result)
				{
					if($CheckIDsToExclude -notcontains $CheckResult.CID -and $CheckResult.CheckResult -ne 'Pass')
					{
						# process group and add results to table array for collection
						Get-CheckResult $Result $CheckResult $Def
                        $GroupHasResults = $true
					}
				}
                
                if($GroupHasResults)
                {

            	$FinalResult.Result += (New-Object -TypeName PSObject -Property @{
																'Title'=$Group.Title
																'Description'=$Group.Description
                                                                'LongRecommendation'=$Group.LongRecommendation
                                                                'ShortRecommendation'=$Group.ShortRecommendation
																'Devices'=$FileDevices
																'TableTitle'=$Group.TableTitle
																'TableResults'=$GroupChecks
																'Details'=$Group.Details
																'ExternalReference'=$Group.ExternalReference
																})

                    $GroupHasResults = $false
                }
			}
		}

		#process checks
		foreach($Check in ($Def.Definitions.Checks.Check))
		{
			Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status "Exporting Indivdual Check Results from '$($File.Name)'" -CurrentOperation "Processing results for '$($Check.CID)'" -PercentComplete 90

			# check to see if any groups are excluded from this result
			$CheckResult = $Result.SelectNodes("//Result[@CID=`"$($Check.CID)`"]")
			$CheckData = Get-CheckResult $Result $CheckResult $Def
			$Details = $Check.Details -replace '{{VALUE}}',$CheckData.'Value Obtained'

			 if($CheckResult.CheckResult -eq 'Fail')
			 {
			 
            	$FinalResult.Result += (New-Object -TypeName PSObject -Property @{
																'Title'=$Check.Title
																'Description'=$Check.Description
                                                                'LongRecommendation'=$Check.LongRecommendation
                                                                'ShortRecommendation'=$Check.ShortRecommendation
																'Devices'=$FileDevices
																'TableTitle'=$null
																'TableResults'=$null
																'Details'=$Details
																'ExternalReference'=$Check.ExternalReference
																})

			}
		}

	}

    # start to build the HTML output
	$FinalResult = $FinalResult.Result | Group-Object Title
	$HTML = ''

    # build the devices in scope of review
    $HTML += "<h1>Hosts for Review</h1><div id=`"row`"><div class=`"col`"><table class=`"table table-striped table-bordered`"><tr><th>Hostname</th><th>OS</th></tr>$($Hosts | Foreach { 
        '<tr><td>'
        $($Hosts.HostName)
        '</td><td>'
        $($Hosts.OS)
        '</td></tr>'
         })</table></div></div>"

    # build summary of findings
    $HTML += '<div id="summary-table"><h1>Summary of Findings</h1><div id="row"><div class="col"><p>The below summary lists the findings identified during the review. Click the left hand number for further details.</p>'
    $HTML += '<table class="table table-striped table-bordered"><tr><th>#</th><th>Title</th><th>Recommendation</th><th>Affected Hosts</th></tr>'
    $HTML += $FinalResult | %{

        $ResultTmp = $_
        $FirstRow = $ResultTmp.Group | Select-Object -First 1
        $VulnDevices = @($ResultTmp.Group | Select-Object -ExpandProperty Devices)
        "<tr><td><a href=`"#finding$($VulnID)`">$($VulnID)</a></td><td>$($FirstRow.Title)</td><td>$($FirstRow.ShortRecommendation)</td><td>$($VulnDevices.Count)</td></tr>"

        $VulnID++

    }
    $HTML += '</table></div></div>'

    # build the main body of the report
    $VulnID = 1
    $HTML += '<h1 id="findings-heading">Finding Details</h1>'
	$HTML += $FinalResult | %{

		$ResultTmp = $_
		$FirstRow = $ResultTmp.Group | Select-Object -First 1
		Write-Progress -Activity 'Exporting Build Review Results to HTML' -Status "Merging all Results" -CurrentOperation "Processing Vulnerability '$($FirstRow.Title)'" -PercentComplete 100

        '<div id="row"><div class="col"><div class="shadow p-3 mb-5 bg-light rounded">'
        "<h2 id=`"finding$($VulnID)`">$($FirstRow.Title)</h2><ul>"
        $ResultTmp.Group | Select-Object -ExpandProperty Devices | %{ "<li>$($_.HostName)</li>" }
        '</ul>'
        '<h3>Description</h3>'
        "<p class=`"finding-description`">$($FirstRow.Description)</p>"
        if($FirstRow.ExternalReference){ "<p><a class=`"badge badge-info`" href=`"$($FirstRow.ExternalReference)`" target=`"_blank`">External Reference</a></p>"}
        '<h3>Recommendation</h3>'
        "<p class=`"finding-recommendation`">$($FirstRow.LongRecommendation)</p>"    
        '<h3>Detail</h3>'

		if($FirstRow.TableTitle)
		{
			$TableResults = ($ResultTmp.Group | Select-Object -ExpandProperty TableResults | Sort-Object Description,Host | ConvertTo-Html -Fragment) -replace '<table>','<table class="table table-striped table-bordered">'
		}else{
            $TableResults = $null
        }

		$AllDetails = $ResultTmp.Group | Select-Object -ExpandProperty Details
		if(@($AllDetails).Count -gt 0 -and $TableResults -eq $null)
		{
			$Details = $AllDetails -Join "`r`n"
		}else{
			$Details = '<p>' + $FirstRow.Details + '</p>' + $TableResults
		}

        $Details
		$VulnID++
        '</div></div></div>'
	}


	# complete the HTML file and save to disk
	$HTML = New-HTML $HTML
    $HTMLPath = Join-Path (Resolve-Path $InputFolder) "BuildReview-Results-$(get-date -Format D).html"
    $HTML | Out-File -FilePath $HTMLPath -Encoding ascii -Force

	# move file to tool-output folder to mark it as complete
	$Files | Move-Item -Destination $TooloutputFolder
	
}