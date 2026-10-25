[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null

$p = (Resolve-Path 'dataset/evidence/images/security_audit_explorer_20260905.png').Path
$op1 = [Windows.Storage.StorageFile]::GetFileFromPathAsync($p)
while ($op1.Status -eq 0) { Start-Sleep -Milliseconds 10 }
$file = $op1.GetResults()

$op2 = $file.OpenAsync(0)
while ($op2.Status -eq 0) { Start-Sleep -Milliseconds 10 }
$stream = $op2.GetResults()

$op3 = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)
while ($op3.Status -eq 0) { Start-Sleep -Milliseconds 10 }
$decoder = $op3.GetResults()

$op4 = $decoder.GetSoftwareBitmapAsync()
while ($op4.Status -eq 0) { Start-Sleep -Milliseconds 10 }
$bitmap = $op4.GetResults()

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$op5 = $engine.RecognizeAsync($bitmap)
while ($op5.Status -eq 0) { Start-Sleep -Milliseconds 10 }
$result = $op5.GetResults()

Write-Output "OCR SUCCESS:"
Write-Output $result.Text
