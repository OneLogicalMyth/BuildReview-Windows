function Get-ServiceUnquoted {

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service |
    Where-Object {$_} |
    Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} |
    Where-Object {-not $_.pathname.StartsWith("`"")} |
    Where-Object {-not $_.pathname.StartsWith("'")} |
    Where-Object {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -match ".* .*"}
    
    if ($VulnServices) {
        ForEach ($Service in $VulnServices){
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'ServiceName' $Service.name
            $Out | Add-Member Noteproperty 'Path' $Service.pathname
            $Out | Add-Member Noteproperty 'StartName' $Service.startname
            $Out
        }
    }

}