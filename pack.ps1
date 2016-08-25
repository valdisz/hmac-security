param([Parameter(Mandatory)]$Version)

$env:Path += ';'
$env:Path += (Resolve-Path .\packages\NuGet.CommandLine.3.4.3\tools)

@(
    '.\src\Core\Core.nuspec';
    '.\src\Owin\Owin.nuspec';
    '.\src\WebAPI\WebAPI.nuspec';
) | foreach {
    $opts = @(
        'pack';
        $_;
        '-Version';
        $Version;
    )

    &nuget.exe $opts
}

