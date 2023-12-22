[ default ]
ca                      = {{CA_NAME}}
domain                  = {{CA_DOMAIN}}
base_url                = http://$domain/ca        # CA base URL
aia_url                 = $base_url/$ca.crt        # CA certificate URL
crl_url                 = $base_url/$ca.crl        # CRL distribution point
name_opt                = multiline,-esc_msb,utf8  # Display UTF-8 characters

# CA certificate request
# Configuration for `openssl req ...`

[ req ]
default_bits            = 4096                  # RSA key size
default_days            = 3652                  # How long to certify for
encrypt_key             = yes                   # Protect private key
default_md              = sha256                # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions

[ ca_dn ]
countryName             = "{{CA_CERT_C}}"
stateOrProvinceName     = "{{CA_CERT_ST}}"
localityName            = "{{CA_CERT_L}}"
organizationName        = "{{CA_CERT_O}}"
organizationalUnitName  = "{{CA_CERT_OU}}"
commonName              = "{{CA_CERT_CN}}"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash

# CA operational settings
# Configuration for `openssl ca ...`

[ ca ]
default_ca              = root_ca               # The default CA section

[ root_ca ]
certificate             = ca/ca.crt             # The CA cert
private_key             = ca/private/ca.key     # CA private key
serial                  = ca/db/crt.srl         # Serial number file
crlnumber               = ca/db/crl.srl         # CRL number file
database                = ca/db/certificate.db  # Index file
new_certs_dir           = archive                # Certificate archive
unique_subject          = no                    # Require unique subject
default_md              = sha256                # MD to use
policy                  = match_pol             # Default naming policy
email_in_dn             = no                    # Add email to cert DN
preserve                = no                    # Keep passed DN ordering
name_opt                = $name_opt             # Subject DN display options
cert_opt                = ca_default            # Certificate display options
copy_extensions         = copy                  # Copy extensions from CSR
x509_extensions         = signing_ca_ext        # Default cert extensions
default_crl_days        = 1                     # How long before next CRL
crl_extensions          = crl_ext               # CRL extensions

[ match_pol ]
countryName             = match                 # Must match
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

# Extensions for this root CA
[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

# Extensions for signing CAs issued by this root CA
[ signing_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

# Extensions for signing certs issued by this signing CA
[ server_ext ]
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
extendedKeyUsage        = serverAuth,clientAuth
subjectKeyIdentifier    = hash
#subjectAltName          = $ENV::SAN
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ client_ext ]
keyUsage                = critical,digitalSignature
basicConstraints        = CA:false
extendedKeyUsage        = clientAuth
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info

[ issuer_info ]
caIssuers;URI.0         = $aia_url

[ crl_info ]
URI.0                   = $crl_url
