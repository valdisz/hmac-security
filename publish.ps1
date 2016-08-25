param(
    [Parameter(Mandatory)]$Source,
    [Parameter(Mandatory)]$ApiKey
)

$env:Path += ';'
$env:Path += (Resolve-Path .\packages\NuGet.CommandLine.3.4.3\tools)

ls *.nupkg `
    | foreach { &nuget (@('push', $_.FullName, '-Source', $Source, '-ApiKey', $ApiKey )) }
