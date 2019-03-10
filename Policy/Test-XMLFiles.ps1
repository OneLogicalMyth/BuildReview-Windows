$PolicyFile = Join-Path $PSScriptRoot policy.xml
$DefinitionsFile = Join-Path $PSScriptRoot definitions.xml

$global:Policy = New-Object XML
$Policy.Load($PolicyFile)

$global:Definitions = New-Object XML
$Definitions.Load($DefinitionsFile)


# Checks both policy and definitions are valid XML