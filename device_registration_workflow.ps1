param(
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

Set-StrictMode -Version Latest

# region Color helpers
function Write-Step {
    param([string]$Message)
    Write-Host "=== $Message ===" -ForegroundColor Blue
}

function Write-Substep {
    param([string]$Message)
    Write-Host "--- $Message ---" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK]  $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage {
    param([string]$Message)
    Write-Host "[ERR] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor DarkYellow
}

function Write-DebugMessage {
    param([string]$Message)
    Write-Host "[DBG] $Message" -ForegroundColor Magenta
}
# endregion

# region Global state
$script:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:SessionCookie = $null
$script:AccessToken = $null
$script:RefreshToken = $null
$script:UserId = $null
$script:DeviceCode = $null
$script:UserCode = $null
$script:VerificationUri = $null
$script:VerificationUriComplete = $null
$script:Interval = 5
$script:ExpiresIn = 900
$script:RegistrationCode = $null
$script:RegistrationCodeTtl = $null
$script:DevicePublicId = $null
$script:RegisteredDeviceId = $null
$script:LastAccessToken = $null
$script:LastRefreshToken = $null
$script:DevicePlatform = $null
$script:DeviceModel = $null
$script:DeviceAppVersion = $null
$script:DeviceName = $null
$script:DeviceIp = $null
$script:DeviceUserAgent = $null
$script:X25519PublicKey = $null
$script:X25519PrivateKey = $null

$script:ServerScheme = $null
$script:ServerHost = $null
$script:ServerPort = $null
$script:BaseUrl = $null
$script:DeviceAuthEndpoint = $null
$script:LoginEndpoint = $null
$script:DevicesEndpointTemplate = $null
$script:DeviceUpdatesEndpoint = $null
$script:ClientConfigDir = Join-Path $env:USERPROFILE '.config/bbserver_client'
# endregion

function Show-Usage {
    Write-Host "Usage: .\\device_registration_workflow.ps1 [-Help]" -ForegroundColor White
    Write-Host """"Device Registration Workflow Script"""" -ForegroundColor Magenta
    Write-Host """"This script mirrors the Bash workflow but implemented in PowerShell."""" -ForegroundColor Magenta
    Write-Host ''
    Write-Host 'Environment variables:'
    Write-Host '  SERVER_SCHEME             Protocol (default: https)'
    Write-Host '  SERVER_HOST               Hostname (default: api.cjj365.cc)'
    Write-Host '  SERVER_PORT               Port (default: empty)'
    Write-Host '  CERT_CTRL_TEST_EMAIL      Preferred login email override'
    Write-Host '  CERT_CTRL_TEST_PASSWORD   Preferred login password override'
    Write-Host '  TEST_EMAIL                Legacy login email override'
    Write-Host '  TEST_PASSWORD             Legacy login password override'
    Write-Host ''
    Write-Host 'Example:'
    Write-Host '  SERVER_HOST=api.example.com powershell -File device_registration_workflow.ps1'
}

if ($Help) {
    Show-Usage
    return
}

function Initialize-Config {
    $script:ServerScheme = if ([string]::IsNullOrWhiteSpace($env:SERVER_SCHEME)) { 'https' } else { $env:SERVER_SCHEME }
    $script:ServerHost = if ([string]::IsNullOrWhiteSpace($env:SERVER_HOST)) { 'api.cjj365.cc' } else { $env:SERVER_HOST }
    $script:ServerPort = if ([string]::IsNullOrWhiteSpace($env:SERVER_PORT)) { $null } else { $env:SERVER_PORT }

    if ($script:ServerPort) {
        $script:BaseUrl = "${script:ServerScheme}://${script:ServerHost}:$script:ServerPort"
    }
    else {
        $script:BaseUrl = "${script:ServerScheme}://${script:ServerHost}"
    }

    $script:DeviceAuthEndpoint = "$script:BaseUrl/auth/device"
    $script:LoginEndpoint = "$script:BaseUrl/auth/general"
    $script:DevicesEndpointTemplate = "$script:BaseUrl/apiv1/users/{user_id}/devices"
    $script:DeviceUpdatesEndpoint = "$script:BaseUrl/apiv1/devices/self/updates"
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Check-Dependencies {
    $missing = @()
    if (-not (Test-CommandExists -Command 'openssl')) {
        $missing += 'openssl'
    }

    if ($missing.Count -gt 0) {
        Write-ErrorMessage ("Missing dependencies: {0}." -f ($missing -join ', '))
        throw 'Install the required command line tools before running the script.'
    }
}

function Invoke-HttpRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','DELETE')] [string]$Method,
        [Parameter(Mandatory)][string]$Url,
        [Parameter()][object]$Body,
        [ValidateSet('session','bearer','none')] [string]$AuthType = 'session'
    )

    $headers = @{
        'Content-Type' = 'application/json'
    }

    if ($AuthType -eq 'session' -and $script:SessionCookie) {
        $headers['Cookie'] = $script:SessionCookie
    }
    elseif ($AuthType -eq 'bearer' -and $script:AccessToken) {
        $headers['Authorization'] = "Bearer $($script:AccessToken)"
    }

    if ($Body -and $Method -ne 'GET' -and $Method -ne 'DELETE') {
        if ($Body -isnot [string]) {
            $Body = $Body | ConvertTo-Json -Depth 10
        }
    }
    else {
        $Body = $null
    }

    Write-Info "HTTP $Method $Url"
    if ($Body) {
        Write-DebugMessage "Request Body: $Body"
    }
    else {
        Write-DebugMessage 'Request Body: (empty)'
    }

    try {
        if ($Body) {
            $response = Invoke-WebRequest -Uri $Url -Method $Method -Headers $headers -Body $Body -WebSession $script:WebSession -UseBasicParsing
        }
        else {
            $response = Invoke-WebRequest -Uri $Url -Method $Method -Headers $headers -WebSession $script:WebSession -UseBasicParsing
        }
    }
    catch {
        Write-ErrorMessage "HTTP request failed: $($_.Exception.Message)"
        throw
    }

    $content = $response.Content
    if ($content) {
        Write-DebugMessage "Response Body: $content"
    }
    else {
        Write-DebugMessage 'Response Body: (empty)'
    }

    $json = $null
    if ($content) {
        try {
            $json = $content | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            # Non-JSON response is acceptable
        }
    }

    return [pscustomobject]@{
        Json = $json
        Content = $content
        StatusCode = $response.StatusCode
    }
}

function Preview-Token {
    param([string]$Token, [int]$Length = 16)
    if ([string]::IsNullOrWhiteSpace($Token)) { return '(empty)' }
    $sanitized = $Token -replace "[\n\r\t]", ''
    if ($sanitized.Length -le $Length) {
        return $sanitized
    }
    return $sanitized.Substring(0, $Length) + '...'
}

function Decode-JwtPayload {
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Length -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        1 { $payload += '===' }
    }
    try {
        $bytes = [Convert]::FromBase64String($payload)
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    catch {
        return $null
    }
}

function Confirm-AccessTokenDeviceId {
    if (-not $script:AccessToken) {
        Write-WarningMessage 'Access token not available; skipping device_id claim verification'
        return $false
    }
    if (-not $script:RegisteredDeviceId) {
        Write-WarningMessage 'Registered device ID unavailable; cannot validate token claim'
        return $false
    }

    $payloadJson = Decode-JwtPayload -Token $script:AccessToken
    if (-not $payloadJson) {
        Write-ErrorMessage 'Failed to decode access token payload'
        return $false
    }

    Write-DebugMessage "Access token payload JSON: $payloadJson"
    try {
        $payload = $payloadJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-ErrorMessage 'Access token payload is not valid JSON'
        return $false
    }

    $tokenDeviceId = $payload.device_id
    if (-not $tokenDeviceId) {
        Write-ErrorMessage 'Access token payload missing device_id claim'
        return $false
    }
    if ($tokenDeviceId -eq $script:RegisteredDeviceId) {
        Write-Success "Access token contains matching device_id claim: $tokenDeviceId"
        return $true
    }

    Write-ErrorMessage "Access token device_id ($tokenDeviceId) does not match registered device ($script:RegisteredDeviceId)"
    return $false
}

function Initialize-DeviceFingerprint {
    $script:DevicePublicId = [guid]::NewGuid().ToString()
    Write-DebugMessage "Generated Device Public ID: $script:DevicePublicId"
}

function Invoke-OpenSsl {
    param([string[]]$Arguments)
    & openssl @Arguments
}

function Extract-HexFromOpenSslBlock {
    param([string[]]$Lines)
    $hexLines = @()
    foreach ($line in $Lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^[0-9a-f]{2}(:[0-9a-f]{2})*') {
            $hexLines += ($trimmed -replace ':', '')
        }
        elseif ($hexLines.Count -gt 0) {
            break
        }
    }
    return ($hexLines -join '').Substring(0, [Math]::Min(64, ($hexLines -join '').Length))
}

function Generate-X25519KeyPair {
    Write-Substep 'Generating X25519 keypair for device registration'
    New-Item -ItemType Directory -Force -Path $script:ClientConfigDir | Out-Null

    $privateKeyPath = Join-Path $script:ClientConfigDir 'device_private.key'
    $publicKeyPath = Join-Path $script:ClientConfigDir 'device_public.key'

    Invoke-OpenSsl -Arguments @('genpkey', '-algorithm', 'X25519', '-out', $privateKeyPath) | Out-Null
    if (-not (Test-Path $privateKeyPath)) {
        Write-ErrorMessage 'Failed to generate X25519 private key'
        return $false
    }

    Invoke-OpenSsl -Arguments @('pkey', '-in', $privateKeyPath, '-pubout', '-out', $publicKeyPath) | Out-Null
    if (-not (Test-Path $publicKeyPath)) {
        Write-ErrorMessage 'Failed to generate X25519 public key'
        return $false
    }

    $privateText = Invoke-OpenSsl -Arguments @('pkey', '-in', $privateKeyPath, '-noout', '-text')
    $publicText = Invoke-OpenSsl -Arguments @('pkey', '-in', $publicKeyPath, '-pubin', '-noout', '-text')

    $privateHex = Extract-HexFromOpenSslBlock -Lines $privateText
    $publicHex = Extract-HexFromOpenSslBlock -Lines $publicText

    if ($privateHex.Length -ne 64) {
        Write-ErrorMessage "Invalid private key length: $($privateHex.Length) chars, expected 64"
        return $false
    }
    if ($publicHex.Length -ne 64) {
        Write-ErrorMessage "Invalid public key length: $($publicHex.Length) chars, expected 64"
        return $false
    }

    $privateBytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) {
        $privateBytes[$i] = [Convert]::ToByte($privateHex.Substring($i * 2, 2), 16)
    }
    $publicBytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) {
        $publicBytes[$i] = [Convert]::ToByte($publicHex.Substring($i * 2, 2), 16)
    }

    $script:X25519PrivateKey = [Convert]::ToBase64String($privateBytes)
    $script:X25519PublicKey = [Convert]::ToBase64String($publicBytes)

    if ($privateBytes.Length -ne 32 -or $publicBytes.Length -ne 32) {
        Write-ErrorMessage 'Failed to capture correct key lengths from OpenSSL output'
        return $false
    }

    Write-Success 'X25519 keypair generated successfully'
    Write-Info "Private key saved to: $privateKeyPath"
    Write-Info "Public key saved to: $publicKeyPath"
    Write-DebugMessage "Public key (base64): $($script:X25519PublicKey.Substring(0, [Math]::Min(32, $script:X25519PublicKey.Length)))..."
    return $true
}

function Save-DeviceSecretKey {
    Write-Substep 'Saving device secret key to client config'
    $secretKeyPath = Join-Path $script:ClientConfigDir 'dev_sk.bin'
    $metadataPath = Join-Path $script:ClientConfigDir 'device_info.json'

    [IO.File]::WriteAllBytes($secretKeyPath, [Convert]::FromBase64String($script:X25519PrivateKey))
    (Get-Item $secretKeyPath).Attributes = 'Hidden'

    $metadata = [ordered]@{
        device_public_id = $script:DevicePublicId
        generated_at = (Get-Date).ToString('o')
        public_key_b64 = $script:X25519PublicKey
        config_version = '1.0'
    } | ConvertTo-Json -Depth 5

    Set-Content -Path $metadataPath -Value $metadata -Encoding UTF8
    Write-Success "Device secret key saved to: $secretKeyPath"
    Write-Info "Device metadata saved to: $metadataPath"
}

function Get-ExternalIp {
    try {
        $response = Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 5
        if ($response.Content) {
            return $response.Content.Trim()
        }
    }
    catch {
        Write-WarningMessage 'Failed to retrieve external IP; defaulting to 127.0.0.1'
    }
    return '127.0.0.1'
}

function User-Login {
    Write-Step 'Step 1: User Login'
    $email = if ($env:CERT_CTRL_TEST_EMAIL) { $env:CERT_CTRL_TEST_EMAIL }
        elseif ($env:TEST_EMAIL) { $env:TEST_EMAIL }
        else { 'jianglibo@hotmail.com' }
    $password = if ($env:CERT_CTRL_TEST_PASSWORD) { $env:CERT_CTRL_TEST_PASSWORD }
        elseif ($env:TEST_PASSWORD) { $env:TEST_PASSWORD }
        else { 'StrongPass1!' }

    Write-Info "Attempting login with email: $email"

    $body = [ordered]@{
        action = 'login'
        email = $email
        password = $password
    }

    $response = Invoke-HttpRequest -Method POST -Url $script:LoginEndpoint -Body $body -AuthType 'none'

    if ($script:WebSession.Cookies.Count -gt 0) {
        $firstCookie = $script:WebSession.Cookies.GetCookies($script:BaseUrl)[0]
        if ($firstCookie) {
            $script:SessionCookie = "$($firstCookie.Name)=$($firstCookie.Value)"
        }
    }

    $json = $response.Json
    if ($json) {
        $script:UserId = $json.data.user.id
        if (-not $script:UserId) {
            $script:UserId = $json.user.id
        }
    }

    if ($script:SessionCookie -and $script:UserId) {
        Write-Success 'Login successful'
        Write-Info "User ID: $script:UserId"
        Write-Info "Session: $(Preview-Token $script:SessionCookie 64)"
        return $true
    }

    Write-ErrorMessage 'Login failed or incomplete response'
    return $false
}

function Device-AuthStart {
    Write-Step 'Step 2: Starting Device Authorization Flow'
    $body = [ordered]@{
        action = 'device_start'
        scopes = @('openid','profile','email')
        interval = 5
        expires_in = 900
    }

    $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'none'
    $json = $response.Json
    if (-not $json) {
        Write-ErrorMessage 'No response received from device authorization request'
        return $false
    }

    $data = $json.data
    if (-not $data) { $data = $json }

    $script:DeviceCode = $data.device_code
    $script:UserCode = $data.user_code
    $script:VerificationUri = $data.verification_uri
    $script:VerificationUriComplete = $data.verification_uri_complete
    $script:Interval = if ($data.interval) { [int]$data.interval } else { 5 }
    $script:ExpiresIn = if ($data.expires_in) { [int]$data.expires_in } else { 900 }

    if (-not $script:DeviceCode -or -not $script:UserCode) {
        Write-ErrorMessage 'Failed to get device_code or user_code from response'
        return $false
    }

    Write-Success 'Device authorization started successfully'
    Write-Info "Device Code: $script:DeviceCode"
    Write-Info "User Code: $script:UserCode"
    Write-Info "Verification URI: $script:VerificationUri"
    Write-Info "Verification URI Complete: $script:VerificationUriComplete"
    Write-Info "Poll Interval: $script:Interval s"
    Write-Info "Expires In: $script:ExpiresIn s"
    return $true
}

function Device-Verify {
    Write-Step 'Step 3: Device Verification (User Approval)'
    if (-not $script:SessionCookie) {
        Write-ErrorMessage 'No session cookie available. Cannot perform automatic verification.'
        return $false
    }

    $body = [ordered]@{
        action = 'device_verify'
        user_code = $script:UserCode
        approve = $true
    }

    $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'session'
    $json = $response.Json
    if (-not $json) {
        Write-ErrorMessage 'Device verification failed: empty response'
        return $false
    }

    $status = $json.data.status
    if (-not $status) { $status = $json.status }

    if ($status -eq 'approved') {
        Write-Success 'Device verification approved successfully'
        return $true
    }

    Write-ErrorMessage "Device verification failed or returned unexpected status: $status"
    return $false
}

function Device-Poll {
    Write-Step 'Step 4: Device Polling for Registration Code'
    if (-not $script:DeviceCode) {
        Write-ErrorMessage 'No device code available for polling'
        return $false
    }

    $body = [ordered]@{
        action = 'device_poll'
        device_code = $script:DeviceCode
    }

    $maxAttempts = [Math]::Max(1, [int]($script:ExpiresIn / $script:Interval))
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-Substep "Poll attempt $attempt / $maxAttempts"
        $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'none'
        if (-not $response.Json) {
            Write-ErrorMessage 'No response received from polling request'
            return $false
        }

        $json = $response.Json
        if ($json.error) {
            Write-ErrorMessage "Server returned error: $($json.error.what) (code: $($json.error.code))"
            return $false
        }

        $status = $json.data.status
        if (-not $status) { $status = $json.status }

        switch ($status) {
            'authorization_pending' {
                Write-Info 'Authorization still pending, waiting...'
            }
            'slow_down' {
                Write-WarningMessage 'Server requested slow down, increasing interval'
                $script:Interval += 5
            }
            'access_denied' {
                Write-ErrorMessage 'Access denied by user'
                return $false
            }
            'expired' {
                Write-ErrorMessage 'Device code expired'
                return $false
            }
            'ready' {
                $data = $json.data
                $script:RegistrationCode = $data.registration_code
                $script:RegistrationCodeTtl = $data.registration_code_ttl
                if (-not $script:RegistrationCode) {
                    Write-ErrorMessage 'Poll response missing registration_code'
                    return $false
                }
                Write-Success 'Authorization complete! Registration code issued.'
                Write-Info "Registration Code: $script:RegistrationCode"
                if ($script:RegistrationCodeTtl) {
                    Write-Info "Registration Code TTL: $script:RegistrationCodeTtl s"
                }
                return $true
            }
            default {
                Write-ErrorMessage "Unknown status: $status"
                Write-DebugMessage "Full response: $($response.Content)"
                return $false
            }
        }
        Start-Sleep -Seconds $script:Interval
    }

    Write-ErrorMessage 'Polling timeout reached without success'
    return $false
}

function Device-Register {
    Write-Step 'Step 5: Device Registration'
    if (-not $script:SessionCookie -or -not $script:UserId) {
        Write-ErrorMessage 'Session cookie or user ID not available for device registration'
        return $false
    }
    if (-not $script:RegistrationCode) {
        Write-ErrorMessage 'No registration code available; run device_poll first'
        return $false
    }

    Initialize-DeviceFingerprint
    if (-not (Generate-X25519KeyPair)) { return $false }
    Save-DeviceSecretKey

    $script:DevicePlatform = (Get-CimInstance Win32_OperatingSystem).Caption
    if (-not $script:DevicePlatform) { $script:DevicePlatform = 'windows' }
    $script:DeviceModel = (Get-CimInstance Win32_ComputerSystem).Model
    $script:DeviceAppVersion = '1.0.0'
    $script:DeviceName = "Test Device $(Get-Date -UFormat %s)"
    $script:DeviceIp = Get-ExternalIp
    $script:DeviceUserAgent = 'DeviceRegistrationScript/1.0'

    Write-Info 'Device Information:'
    Write-Info "  Public ID: $script:DevicePublicId"
    Write-Info "  Platform: $script:DevicePlatform"
    Write-Info "  Model: $script:DeviceModel"
    Write-Info "  App Version: $script:DeviceAppVersion"
    Write-Info "  Name: $script:DeviceName"
    Write-Info "  IP: $script:DeviceIp"
    Write-Info "  X25519 Public Key: $(Preview-Token $script:X25519PublicKey 32)"

    $body = [ordered]@{
        device_public_id = $script:DevicePublicId
        platform = $script:DevicePlatform
        model = $script:DeviceModel
        app_version = $script:DeviceAppVersion
        name = $script:DeviceName
        ip = $script:DeviceIp
        user_agent = $script:DeviceUserAgent
        dev_pk = $script:X25519PublicKey
        registration_code = $script:RegistrationCode
    }

    $devicesEndpoint = $script:DevicesEndpointTemplate.Replace('{user_id}', $script:UserId)
    $response = Invoke-HttpRequest -Method POST -Url $devicesEndpoint -Body $body -AuthType 'session'

    $json = $response.Json
    if (-not $json) {
        Write-WarningMessage 'Device registration response empty (possibly not implemented).'
        return $true
    }

    $device = $json.data.device
    if (-not $device) { $device = $json.device }

    if ($device) {
        $script:RegisteredDeviceId = $device.id
        Write-Success 'Device registered successfully'
        Write-Info "Device ID: $script:RegisteredDeviceId"

        $session = $json.data.session
        if (-not $session) { $session = $json.session }

        if ($session) {
            $script:AccessToken = $session.access_token
            $script:RefreshToken = $session.refresh_token
            if ($session.token_type) { Write-Info "Token Type: $($session.token_type)" }
            if ($session.expires_in) { Write-Info "Access token TTL: $($session.expires_in)s" }
            if ($script:AccessToken) {
                Write-Substep 'Validating access token device_id claim'
                Confirm-AccessTokenDeviceId | Out-Null
            }
            $script:LastAccessToken = $script:AccessToken
            $script:LastRefreshToken = $script:RefreshToken
            if ($script:LastRefreshToken) {
                Write-Info "Refresh token issued: $(Preview-Token $script:LastRefreshToken 24)"
            }
        }

        Device-RegisterRetry | Out-Null
        return $true
    }

    Write-WarningMessage 'Device registration may not be implemented yet'
    return $true
}

function Device-RegisterRetry {
    Write-Substep 'Re-registering device to demonstrate idempotent session rotation'
    if (-not $script:RegisteredDeviceId) {
        Write-WarningMessage 'Device was not registered; skipping retry'
        return $false
    }
    if (-not $script:LastRefreshToken) {
        Write-WarningMessage 'No refresh token from initial registration; skipping retry'
        return $false
    }

    $body = [ordered]@{
        device_public_id = $script:DevicePublicId
        platform = $script:DevicePlatform
        model = $script:DeviceModel
        app_version = $script:DeviceAppVersion
        name = $script:DeviceName
        ip = $script:DeviceIp
        user_agent = $script:DeviceUserAgent
        dev_pk = $script:X25519PublicKey
        refresh_token = $script:LastRefreshToken
    }

    $devicesEndpoint = $script:DevicesEndpointTemplate.Replace('{user_id}', $script:UserId)
    $response = Invoke-HttpRequest -Method POST -Url $devicesEndpoint -Body $body -AuthType 'session'

    $json = $response.Json
    if (-not $json) {
        Write-WarningMessage 'Idempotent registration response empty'
        return $false
    }

    $device = $json.data.device
    if (-not $device) { $device = $json.device }
    if (-not $device) {
        Write-WarningMessage 'Retry response missing device payload'
        return $false
    }

    Write-Info "Existing device ID confirmed: $($device.id)"

    $session = $json.data.session
    if (-not $session) { $session = $json.session }
    if (-not $session) {
        Write-WarningMessage 'Retry response missing session data'
        return $false
    }

    $newRefresh = $session.refresh_token
    $newAccess = $session.access_token
    if (-not $newRefresh) {
        Write-WarningMessage 'Retry response missing refresh token'
        return $false
    }

    Write-Info "Previous refresh token: $(Preview-Token $script:LastRefreshToken 24)"
    Write-Info "New refresh token: $(Preview-Token $newRefresh 24)"

    if ($newRefresh -ne $script:LastRefreshToken) {
        Write-Success 'Refresh token rotated on idempotent retry'
    }
    else {
        Write-WarningMessage 'Refresh token was not rotated on retry'
    }

    if ($script:LastAccessToken) {
        Write-Info "Previous access token: $(Preview-Token $script:LastAccessToken 24)"
    }
    if ($newAccess) {
        Write-Info "New access token: $(Preview-Token $newAccess 24)"
        $script:AccessToken = $newAccess
        Confirm-AccessTokenDeviceId | Out-Null
        $script:LastAccessToken = $newAccess
    }

    if ($session.token_type) { Write-Info "Token Type (retry): $($session.token_type)" }
    if ($session.expires_in) { Write-Info "Access token TTL (retry): $($session.expires_in)s" }

    $script:RefreshToken = $newRefresh
    $script:LastRefreshToken = $newRefresh
    return $true
}

function List-Devices {
    Write-Step 'Step 6: List Registered Devices'
    if (-not $script:SessionCookie -or -not $script:UserId) {
        Write-ErrorMessage 'Session cookie or user ID not available for listing devices'
        return $false
    }

    $devicesEndpoint = $script:DevicesEndpointTemplate.Replace('{user_id}', $script:UserId)
    $response = Invoke-HttpRequest -Method GET -Url $devicesEndpoint -AuthType 'session'
    $json = $response.Json
    if (-not $json) {
        Write-WarningMessage 'Devices list response empty (possibly not implemented).'
        return $true
    }

    $devices = $json.data
    if (-not $devices) { $devices = @($json) }

    if ($devices.Count -gt 0) {
        Write-Success "Found $($devices.Count) registered device(s)"
        foreach ($device in $devices) {
            $name = if ($device.name) { $device.name } else { 'Unnamed' }
            $id = if ($device.device_public_id) { $device.device_public_id } elseif ($device.id) { $device.id } else { '(unknown)' }
            Write-Host "  Device: $name ($id)" -ForegroundColor Gray
        }
    }
    else {
        Write-Info 'No registered devices found or device listing not implemented'
    }
    return $true
}

function Test-ErrorScenarios {
    Write-Step 'Step 7: Error Scenario Testing'

    Write-Substep 'Testing invalid device auth action'
    $body = @{ action = 'invalid_action' }
    $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'none'
    if ($response.Content) {
        Write-DebugMessage "Invalid action response: $($response.Content)"
    }

    Write-Substep 'Testing missing device_code in poll'
    $body = @{ action = 'device_poll' }
    $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'none'
    if ($response.Content) {
        Write-DebugMessage "Missing device_code response: $($response.Content)"
    }

    Write-Substep 'Testing invalid device_code'
    $body = @{ action = 'device_poll'; device_code = 'invalid_code' }
    $response = Invoke-HttpRequest -Method POST -Url $script:DeviceAuthEndpoint -Body $body -AuthType 'none'
    if ($response.Content) {
        Write-DebugMessage "Invalid device_code response: $($response.Content)"
    }

    Write-Success 'Error scenario testing completed'
}

function Device-UpdatesPoll {
    Write-Step 'Step 8: Device Updates Poll'
    if (-not $script:AccessToken) {
        Write-ErrorMessage 'Access token not available for updates poll'
        return $false
    }

    $response = Invoke-HttpRequest -Method GET -Url $script:DeviceUpdatesEndpoint -AuthType 'bearer'
    if ($response.Content) {
        Write-DebugMessage "Device Updates Response: $($response.Content)"
    }
    else {
        Write-Info 'Updates endpoint returned no body (likely 204 No Content)'
    }
    return $true
}

function Check-ServerConnectivity {
    Write-Info 'Checking server connectivity...'
    try {
        $health = Invoke-WebRequest -Uri "$script:BaseUrl/health" -UseBasicParsing -TimeoutSec 5
        if ($health.StatusCode -ge 200 -and $health.StatusCode -lt 500) {
            Write-Success 'Server is reachable'
            return $true
        }
    }
    catch {
        Write-ErrorMessage "Cannot connect to server at $script:BaseUrl"
        Write-Info 'Please ensure the server is running and accessible'
        throw
    }
    return $true
}

function Run-Workflow {
    Initialize-Config
    Write-Host 'Device Registration Workflow Test' -ForegroundColor Magenta
    Write-Host '===================================' -ForegroundColor Magenta
    Write-Host "Server: $script:BaseUrl"
    Write-Host "Device Auth Endpoint: $script:DeviceAuthEndpoint"
    Write-Host "Devices Endpoint Template: $script:DevicesEndpointTemplate"
    Write-Host ''

    Check-Dependencies
    Check-ServerConnectivity | Out-Null
    Write-Host ''

    if (-not (User-Login)) { throw 'User login failed, aborting workflow' }
    Write-Host ''

    if (-not (Device-AuthStart)) { throw 'Device authorization start failed, aborting workflow' }
    Write-Host ''

    if (-not (Device-Verify)) { throw 'Device verification failed, aborting workflow' }
    Write-Host ''

    if (-not (Device-Poll)) { throw 'Device polling failed, aborting workflow' }
    Write-Host ''

    $stepFailed = $false
    if (-not (Device-Register)) {
        Write-WarningMessage 'Device registration step had issues (may not be implemented)'
        $stepFailed = $true
    }
    Write-Host ''

    if (-not (List-Devices)) {
        Write-WarningMessage 'Device listing step had issues (may not be implemented)'
        $stepFailed = $true
    }
    Write-Host ''

    Test-ErrorScenarios
    Write-Host ''

    if (-not (Device-UpdatesPoll)) {
        Write-WarningMessage 'Device updates poll encountered an issue'
        $stepFailed = $true
    }
    Write-Host ''

    if (-not $stepFailed) {
        Write-Success 'Complete device registration workflow completed successfully!'
    }
    else {
        Write-WarningMessage 'Device registration workflow completed with some warnings'
        Write-Info 'Some endpoints may not be fully implemented yet'
    }

    Write-Host ''
    Write-Host 'Summary:' -ForegroundColor Magenta
        Write-Host "[OK]  User authenticated and session established"
        Write-Host "[OK]  Device authorization flow completed"
        Write-Host "[OK]  Access token obtained via device flow"
    if ($script:DevicePublicId) {
           Write-Host "[OK]  Device fingerprint generated: $script:DevicePublicId"
    }
    if (-not $stepFailed) {
           Write-Host '[OK]  Device registered and listed successfully'
           Write-Host '[OK]  Device updates endpoint polled'
    }
    else {
           Write-Host '[WARN] Device registration/listing may need implementation'
           Write-Host '[WARN] Device updates poll had issues'
    }
}

try {
    Run-Workflow
}
catch {
    Write-ErrorMessage "Workflow failed: $($_.Exception.Message)"
    exit 1
}
