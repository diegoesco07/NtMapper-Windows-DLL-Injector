$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root 'docs\demo-transcript.txt'
$destination = Join-Path $root 'docs\demo-output.png'

$sourceLines = Get-Content -LiteralPath $source
$patterns = @(
    '^PE32\+ DLL', '^Sections \(', '^  \.text', '^  \.reloc',
    '^Imported DLLs', '^Relocations:', '^Target PID:',
    '^\[NtMapper\] Hooking', '^\[NtMapper\] Hook executed',
    '^Injection completed\.', '^DEMO_READY', '^DEMO_LOADED', '^DEMO_PASS'
)
$lines = foreach ($pattern in $patterns) {
    $sourceLines | Where-Object { $_ -match $pattern } | Select-Object -Last 1
}
$bitmap = [System.Drawing.Bitmap]::new(1320, 660)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$background = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(18, 22, 30))
$foreground = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(225, 233, 241))
$accent = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(93, 220, 178))
$muted = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(146, 160, 175))
$font = [System.Drawing.Font]::new('Consolas', 18)
$small = [System.Drawing.Font]::new('Consolas', 12)
try {
    $graphics.FillRectangle($background, 0, 0, 1320, 660)
    $graphics.DrawString('NtMapper / local Release demo', $font, $accent, 44, 34)
    $graphics.DrawString('Selected lines from docs/demo-transcript.txt', $small, $muted, 46, 74)
    $y = 120
    foreach ($line in $lines) {
        if ($y -gt 610) { break }
        $brush = if ($line -match 'DEMO_LOADED|DEMO_PASS|Hook executed') { $accent } else { $foreground }
        $graphics.DrawString($line, $font, $brush, 44, $y)
        $y += 37
    }
    $bitmap.Save($destination, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $font.Dispose(); $small.Dispose(); $background.Dispose(); $foreground.Dispose()
    $accent.Dispose(); $muted.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
Write-Output $destination
