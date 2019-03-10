Function Out-FileFromBase64 {
param($Base64,$FileName)
	$Content = [System.Convert]::FromBase64String($Base64)
	Set-Content -Path $FileName -Value $Content -Encoding Byte -Force
}