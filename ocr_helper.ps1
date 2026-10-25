$code = @'
using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;

public class OcrHelper {
    public static string Recognize(string filePath) {
        return Task.Run(async () => {
            var file = await StorageFile.GetFileFromPathAsync(filePath);
            using (var stream = await file.OpenAsync(FileAccessMode.Read)) {
                var decoder = await BitmapDecoder.CreateAsync(stream);
                var bitmap = await decoder.GetSoftwareBitmapAsync();
                var engine = OcrEngine.TryCreateFromUserProfileLanguages();
                var result = await engine.RecognizeAsync(bitmap);
                return result.Text;
            }
        }).GetAwaiter().GetResult();
    }
}
'@

$refs = [string[]]@(
    "System.Runtime.WindowsRuntime.dll",
    "C:\Windows\System32\WinMetadata\Windows.Media.Ocr.winmd",
    "C:\Windows\System32\WinMetadata\Windows.Graphics.winmd",
    "C:\Windows\System32\WinMetadata\Windows.Storage.winmd",
    "C:\Windows\System32\WinMetadata\Windows.Foundation.winmd"
)

Add-Type -TypeDefinition $code -ReferencedAssemblies $refs

$p = (Resolve-Path "dataset/evidence/images/security_audit_explorer_20260905.png").Path
$res = [OcrHelper]::Recognize($p)
Write-Output "OCR RESULT:"
Write-Output $res
