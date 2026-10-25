Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null

function Await-Async($asyncOp) {
    $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.IsGenericMethod
    } | Select-Object -First 1
    # Determine the return type of the async operation
    $interface = $asyncOp.GetType().GetInterfaces() | Where-Object { $_.IsGenericType -and $_.GetGenericTypeDefinition().Name -eq 'IAsyncOperation`1' }
    $returnType = $interface.GetGenericArguments()[0]
    $asTask = $asTaskGeneric.MakeGenericMethod($returnType)
    $task = $asTask.Invoke($null, @($asyncOp))
    $task.Wait()
    return $task.Result
}

function Get-OcrText($filePath) {
    $absPath = (Resolve-Path $filePath).Path
    $asyncOp = [Windows.Storage.StorageFile]::GetFileFromPathAsync($absPath)
    $file = Await-Async $asyncOp
    $stream = Await-Async ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read))
    $decoder = Await-Async ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream))
    $bitmap = Await-Async ($decoder.GetSoftwareBitmapAsync())
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    $result = Await-Async ($engine.RecognizeAsync($bitmap))
    return $result.Text
}

$images = Get-ChildItem "dataset/evidence/images/*.png"
foreach ($img in $images) {
    Write-Output "=== FILE: $($img.Name) ==="
    $text = Get-OcrText $img.FullName
    Write-Output $text
}
