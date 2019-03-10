Function Get-JavaVersions {
	begin
	{
		$LocalDisks = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
	}
	process
	{
		$JavaFiles = foreach($DriveRoot in $LocalDisks){ Get-ChildItem -Path $DriveRoot -Recurse -Name java.exe | foreach{ Join-Path $DriveRoot $_ } }
		foreach($JavaFile in $JavaFiles)
		{
			(Get-Item $JavaFile).VersionInfo | Select-Object FileName, FileVersion, ProductVersion, ProductName
		}
	}
}