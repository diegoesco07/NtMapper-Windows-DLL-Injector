param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$build = Join-Path $root 'build'

if (-not $SkipBuild) {
    cmake -S $root -B $build -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    cmake --build $build --config $Configuration --parallel
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    ctest --test-dir $build -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'PE inspector tests failed.' }
}

$bin = Join-Path $build "bin\$Configuration"
$targetExe = Join-Path $bin 'NtMapperDemoTarget.exe'
$payload = Join-Path $bin 'NtMapperDemoPayload.dll'
$injector = Join-Path $build "$Configuration\NtMapper.exe"
foreach ($path in @($targetExe, $payload, $injector)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing demo binary: $path" }
}
if (Get-Process -Name 'NtMapperDemoTarget' -ErrorAction SilentlyContinue) {
    throw 'Another NtMapperDemoTarget process is running; close it before starting this demo.'
}

$stdout = Join-Path $build 'demo-target.stdout.txt'
$stderr = Join-Path $build 'demo-target.stderr.txt'
$target = Start-Process -FilePath $targetExe -WorkingDirectory $bin `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
    -WindowStyle Hidden -PassThru
try {
    $ready = $false
    for ($i = 0; $i -lt 50; ++$i) {
        if (Test-Path -LiteralPath $stdout) {
            $ready = [bool](Select-String -Path $stdout -Pattern '^DEMO_READY' -Quiet)
            if ($ready) { break }
        }
        if ($target.HasExited) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Demo target did not become ready.' }

    & $injector inspect $payload
    if ($LASTEXITCODE -ne 0) { throw 'PE inspection failed.' }
    & $injector inject 'NtMapperDemoTarget.exe' $payload --profile QueryPerformanceCounter
    $injectorExit = $LASTEXITCODE
    $exited = $target.WaitForExit(5000)
    $target.Refresh()
    $targetOutput = Get-Content -LiteralPath $stdout -Raw
    Write-Output $targetOutput
    if ($injectorExit -ne 0) { throw "Injector exited with code $injectorExit." }
    if (-not $exited -or $targetOutput -notmatch '(?m)^DEMO_LOADED\r?$') {
        throw 'Demo DLL load was not confirmed by the target.'
    }
    Write-Output 'DEMO_PASS: injector completed and target confirmed DLL load.'
} finally {
    if (-not $target.HasExited) { Stop-Process -Id $target.Id -Force }
}
