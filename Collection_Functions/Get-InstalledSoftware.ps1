Function Get-InstalledSoftware {

	function Sort-InstallDate {
	param([string]$StringDate)

	    $Y = $StringDate.Substring(0,4)
	    $M = $StringDate.Substring(4,2)
	    $D = $StringDate.Substring(6,2)
	    [datetime]"$Y-$M-$D"

	}

	if((Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
	    [string[]]$RootKeys      = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
	}else{
	    [string[]]$RootKeys      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
	}

	Get-ItemProperty -Path $RootKeys | Where-Object {
		($_.DisplayName -notlike 'Security Update for Windows*' -AND
		$_.DisplayName -notlike 'Hotfix for Windows*' -AND
		$_.DisplayName -notlike 'Update for Windows*' -AND
		$_.DisplayName -notlike 'Update for Microsoft*' -AND
		$_.DisplayName -notlike 'Security Update for Microsoft*' -AND
		$_.DisplayName -notlike 'Hotfix for Microsoft*' -AND
	    $_.PSChildName -notlike '*}.KB') } | Where-Object { $_.DisplayName -ne $null -AND $_.DisplayName -ne '' } |
	Select-Object Publisher, DisplayName, DisplayVersion, @{n='InstallDate';e={Sort-InstallDate $_.InstallDate}}, InstallLocation, @{n='EstimatedSizeMB';e={[math]::Round($_.EstimatedSize / 1024,2)}}


}