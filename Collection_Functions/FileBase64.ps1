Function Read-FileToBase64 {
param($FileName)
	[System.Convert]::ToBase64String(([System.IO.File]::ReadAllBytes($FileName)))
}