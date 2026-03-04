# 1. Start server in background
Start-Process -NoNewWindow -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py" -PassThru -RedirectStandardOutput server_out.txt -RedirectStandardError server_err.txt | Set-Variable -Name server
Start-Sleep -Seconds 3

# 2. Login
$loginArgs = @{
    Uri = "http://localhost:5000/api/auth/login"
    Method = "POST"
    Body = @{ email = "nedpearson@gmail.com"; password = "1Pearson2" } | ConvertTo-Json
    ContentType = "application/json"
    SessionVariable = "Session"
}
Invoke-RestMethod @loginArgs

# 3. Upload preview
$fileBytes = [System.IO.File]::ReadAllBytes("test.zip")
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "
"
$bodyLines = (
    "--$boundary",
    "Content-Disposition: form-data; name="doc_type"",
    "",
    "auto",
    "--$boundary",
    "Content-Disposition: form-data; name="doc_category"",
    "",
    "bank_statement",
    "--$boundary",
    "Content-Disposition: form-data; name="file"; filename="test.zip"",
    "Content-Type: application/zip",
    ""
)
$bodyString = $bodyLines -join $LF
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyString) + $LF + $fileBytes + $LF + [System.Text.Encoding]::UTF8.GetBytes("--$boundary--
")
$previewUrl = "http://localhost:5000/api/upload/preview"
$request = [System.Net.WebRequest]::Create($previewUrl)
$request.Method = "POST"
$request.ContentType = "multipart/form-data; boundary=$boundary"
$request.CookieContainer = $Session
$stream = $request.GetRequestStream()
$stream.Write($bodyBytes, 0, $bodyBytes.Length)
$stream.Close()
$response = $request.GetResponse()
$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
$jsonPreview = $reader.ReadToEnd()
Write-Output $jsonPreview

# 4. Cleanup
Stop-Process -Id $server.Id -Force
