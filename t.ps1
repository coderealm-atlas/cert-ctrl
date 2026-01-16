$ErrorActionPreference = 'Stop'

function Write-HaproxyPem {
	param(
		[Parameter(Mandatory = $true)][string]$FullchainPath,
		[Parameter(Mandatory = $true)][string]$PrivateKeyPath,
		[Parameter(Mandatory = $true)][string]$OutPath
	)

	if (!(Test-Path -LiteralPath $PrivateKeyPath)) {
		throw "private key not found: $PrivateKeyPath"
	}
	if (!(Test-Path -LiteralPath $FullchainPath)) {
		throw "fullchain not found: $FullchainPath"
	}

	$keyText = Get-Content -LiteralPath $PrivateKeyPath -Raw
	$certText = Get-Content -LiteralPath $FullchainPath -Raw

	# HAProxy expects private key + certificate chain in one PEM file.
	$combined = ($keyText.TrimEnd() + "`n" + $certText.TrimEnd() + "`n")

	$outDir = Split-Path -Parent -Path $OutPath
	if ($outDir -and !(Test-Path -LiteralPath $outDir)) {
		New-Item -ItemType Directory -Path $outDir -Force | Out-Null
	}

	$tmpPath = "$OutPath.tmp"
	Set-Content -LiteralPath $tmpPath -Value $combined -NoNewline -Encoding ascii
	Move-Item -LiteralPath $tmpPath -Destination $OutPath -Force
    Write-Host "Wrote combined PEM to $OutPath"
}

$EventName = if ($args.Count -ge 1) { $args[0] } else { 'unknown' }
Write-Host "got message: $EventName"

# Cert directory can be overridden for testing or different layouts.
# Priority: $env:CERT_DIR > args[1] > default.
$CertDir = if ($env:CERT_DIR) {
	$env:CERT_DIR
} elseif ($args.Count -ge 2 -and $args[1]) {
	$args[1]
} else {
	'C:\Users\jiang\certs'
}

$FullchainPem = Join-Path $CertDir 'fullchain.pem'
$PrivateKeyPem = Join-Path $CertDir 'private.key'
$HaproxyPem = if ($env:HAPROXY_PEM) {
	$env:HAPROXY_PEM
} elseif ($args.Count -ge 3 -and $args[2]) {
	$args[2]
} else {
	(Join-Path $CertDir 'haproxy.pem')
}

switch ($EventName) {
	{ $_ -in @('install.updated', 'cert.updated', 'cert.wrap_ready') } {
		Write-HaproxyPem -FullchainPath $FullchainPem -PrivateKeyPath $PrivateKeyPem -OutPath $HaproxyPem
		Write-Host "wrote: $HaproxyPem"
		break
	}
	'cert.unassigned' { }
	'config.updated' { }
	'ca.assigned' { }
	'ca.unassigned' { }
	default { }
}
