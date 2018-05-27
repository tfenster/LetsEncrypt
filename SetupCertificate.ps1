$ContactEMailForLetsEncrypt = $env:ContactEMailForLetsEncrypt

try {
    Write-Host "Creating temp website for letsEncrypt"
    mkdir c:\inetpub\wwwroot\http -ErrorAction Ignore | Out-Null
    new-website -name http -port 80 -physicalpath c:\inetpub\wwwroot\http -ErrorAction Ignore | Out-Null

    Write-Host "Installing NuGet PackageProvider"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Ignore | Out-Null
    
    Write-Host "Installing ACMESharp PowerShell modules"
    Install-Module -Name ACMESharp -AllowClobber -force -ErrorAction Ignore | Out-Null
    Install-Module -Name ACMESharp.Providers.IIS -force -ErrorAction Ignore | Out-Null
    Import-Module ACMESharp
    Enable-ACMEExtensionModule -ModuleName ACMESharp.Providers.IIS | Out-Null
    Write-Host "Initializing ACMEVault"
    Initialize-ACMEVault
                
    Write-Host "Register Contact EMail address and accept Terms Of Service"
    New-ACMERegistration -Contacts "mailto:$ContactEMailForLetsEncrypt" -AcceptTos | Out-Null
                
    Write-Host "Creating new dns Identifier"
    $dnsAlias = "dnsAlias"
    New-ACMEIdentifier -Dns $publicDnsName -Alias $dnsAlias | Out-Null
    
    Write-Host "Performing Lets Encrypt challenge to default web site"
    Complete-ACMEChallenge -IdentifierRef $dnsAlias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = 'http' } | Out-Null
    Submit-ACMEChallenge -IdentifierRef $dnsAlias -ChallengeType http-01 | Out-Null
    sleep -s 60
    Update-ACMEIdentifier -IdentifierRef $dnsAlias | Out-Null
    
    Write-Host "Requesting certificate"
    $certAlias = "certAlias"
    $certificatePfxPassword = [GUID]::NewGuid().ToString()
    $certificatePfxFile = Join-Path $runPath "certificate.pfx"
    New-ACMECertificate -Generate -IdentifierRef $dnsAlias -Alias $certAlias | Out-Null
    Submit-ACMECertificate -CertificateRef $certAlias | Out-Null
    Update-ACMECertificate -CertificateRef $certAlias | Out-Null
    Get-ACMECertificate -CertificateRef $certAlias -ExportPkcs12 $certificatePfxFile -CertificatePassword $certificatePfxPassword | Out-Null
    
    $certificatePemFile = Join-Path $runPath "certificate.pem"
    Remove-Item -Path $certificatePemFile -Force -ErrorAction Ignore | Out-Null
    Get-ACMECertificate -CertificateRef $certAlias -ExportKeyPEM $certificatePemFile | Out-Null
    
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePfxFile, $certificatePfxPassword)
    $certificateThumbprint = $cert.Thumbprint
    
    $dnsidentity = $cert.GetNameInfo("SimpleName",$false)
    if ($dnsidentity.StartsWith("*")) {
        $dnsidentity = $dnsidentity.Substring($dnsidentity.IndexOf(".")+1)
    }
}
catch {
    # If Any error occurs (f.ex. rate-limits), setup self signed certificate
    Write-Host "Error creating letsEncrypt certificate, reverting to self-signed"
    . (Join-Path $runPath $MyInvocation.MyCommand.Name)

}
finally {
    Write-Host "Removing temp website"
    Remove-WebSite -name http -ErrorAction Ignore
    Remove-Item -path c:\inetpub\wwwroot\http -Recurse -Force -ErrorAction Ignore
}
