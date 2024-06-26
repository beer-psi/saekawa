cargo build --target i686-pc-windows-msvc --release

if (!(Test-Path ./saekawa.pfx)) {
    $cert = New-SelfSignedCertificate -Type Custom `
        -Subject "CN=saekawa self-signed certificate" `
        -CertStoreLocation cert:\CurrentUser\My `
        -KeyUsage DigitalSignature

    Export-PfxCertificate -Cert $cert `
        -FilePath saekawa.pfx `
        -Password (ConvertTo-SecureString -String "saekawa" -Force -AsPlainText)
}

signtool sign -f saekawa.pfx -p "saekawa" -fd SHA256 -t http://timestamp.comodoca.com/authenticode -v target/i686-pc-windows-msvc/release/saekawa.dll
sha256sum target/i686-pc-windows-msvc/release/saekawa.dll
