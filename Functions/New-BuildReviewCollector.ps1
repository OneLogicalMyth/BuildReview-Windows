Function New-BuildReviewCollector {

	begin
	{

		# Check for internet access, for Windows Update
	    $CabFile = (Join-Path ($env:USERPROFILE) 'wsusscn2.cab')
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

	    # Store WSUS cab file as base64
	    #$WSUSFile = Read-FileToBase64 -FileName $CabFile

		$Functions = Get-ChildItem -Path $BuildReviewRoot\Collection_Functions -Filter *.ps1 | Get-Content | Out-String

		# load policy file
		[xml]$Policy = Get-Content (Join-Path $BuildReviewRoot 'Policy\policy.xml')
		# strip comments
		$Policy.SelectNodes('.//comment()') | foreach{ $N = [System.Xml.XmlNode]$_; $N.ParentNode.RemoveChild($N) } | Out-Null
		# convert contents to base64
		$Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($Policy.InnerXml))
	}

	process
	{
		
$Collector = @"
param([switch]`$DisableWindowsUpdate)
$Functions
`$PolicyXML = '$Base64'
$(Get-Content $BuildReviewRoot\Collection_Functions\Invoke-BuildReview.tpl | Out-String)
"@

	}

	end
	{
		$File = (Join-Path ($env:USERPROFILE) 'BuildReview.ps1')
		$Collector | Out-File $File
		Write-Host "File saved to $File"
		Write-Host "Finished!" -ForegroundColor Green
	}

}